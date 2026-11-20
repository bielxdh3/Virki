package c1c4bridge

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func syntheticMeta() C1BuildMetadata {
	return C1BuildMetadata{
		Epoch:                  1,
		SessionID:              "session-c1c4-bridge-01",
		JobID:                  "job-c1c4-bridge-01",
		Role:                   "runtime",
		Nonce:                  "0123456789abcdef0123456789abcdef",
		SourceCommit:           strings.Repeat("a", 40),
		BuildPlanSHA256:        strings.Repeat("b", 64),
		ExecutablePolicySHA256: strings.Repeat("c", 64),
		OutputImageID:          "sha256:" + strings.Repeat("d", 64),
		ArchiveSHA256:          strings.Repeat("e", 64),
		ArchiveBytes:           42,
		TranscriptSHA256:       strings.Repeat("f", 64),
		Contexts: [ContextCount]C1ContextInput{
			{Name: "source", TreeDigest: "sha256:" + strings.Repeat("1", 64), Data: []byte("SYNTHETIC_SOURCE")},
			{Name: "dockerfile", TreeDigest: "sha256:" + strings.Repeat("2", 64), Data: []byte("FROM scratch\n")},
			{Name: "offline-npm-cacache", TreeDigest: "sha256:" + strings.Repeat("3", 64), Data: []byte("SYNTHETIC_NPM")},
			{Name: "offline-prisma-engines", TreeDigest: "sha256:" + strings.Repeat("4", 64), Data: []byte("SYNTHETIC_PRISMA")},
		},
	}
}

func TestVROAV2ABISizes(t *testing.T) {
	if got := binary.Size(RequestFrame{}); got != 1526 {
		t.Fatalf("RequestFrame size = %d, want 1526 (must match native-owner-authority-protocol.h)", got)
	}
	if got := binary.Size(ResponseFrame{}); got != 4455 {
		t.Fatalf("ResponseFrame size = %d, want 4455 (must match native-owner-authority-protocol.h)", got)
	}
}

func TestBuildC4RequestPositiveAndRejections(t *testing.T) {
	for _, role := range []string{"runtime", "migrator"} {
		meta := syntheticMeta()
		meta.Role = role
		req, err := BuildC4Request(meta, CmdStatus, "")
		if err != nil {
			t.Fatalf("valid BuildC4Request(%s) failed: %v", role, err)
		}
		encoded, err := EncodeRequestFrame(req)
		if err != nil || len(encoded) != 1526 {
			t.Fatalf("EncodeRequestFrame len=%d err=%v", len(encoded), err)
		}
	}

	// Reject authorizing flags
	badAuth := syntheticMeta()
	badAuth.DeployAuthorized = true
	if _, err := BuildC4Request(badAuth, CmdSignAck, strings.Repeat("a", 64)); err == nil {
		t.Fatal("expected error when DeployAuthorized=true")
	}

	badReceipt := syntheticMeta()
	badReceipt.WorkerReceiptPairAdmitted = true
	if _, err := BuildC4Request(badReceipt, CmdSignAck, strings.Repeat("a", 64)); err == nil {
		t.Fatal("expected error when WorkerReceiptPairAdmitted=true")
	}

	// Reject unsupported cmd & invalid scopeToken
	if _, err := BuildC4Request(syntheticMeta(), 99, ""); err == nil {
		t.Fatal("expected error for unsupported cmd")
	}
	if _, err := BuildC4Request(syntheticMeta(), CmdStatus, strings.Repeat("a", 64)); err == nil {
		t.Fatal("expected error when STATUS carries scopeToken")
	}
	if _, err := BuildC4Request(syntheticMeta(), CmdSignAck, "bad"); err == nil {
		t.Fatal("expected error when SIGN_ACK has invalid scopeToken")
	}

	// Reject invalid epoch, role, nonce, sourceCommit, JSON injection, NUL
	badEpoch := syntheticMeta()
	badEpoch.Epoch = 0
	if _, err := BuildC4Request(badEpoch, CmdStatus, ""); err == nil {
		t.Fatal("expected error for Epoch=0")
	}
	badRole := syntheticMeta()
	badRole.Role = "admin"
	if _, err := BuildC4Request(badRole, CmdStatus, ""); err == nil {
		t.Fatal("expected error for invalid Role")
	}
	badJSON := syntheticMeta()
	badJSON.JobID = `job"injected`
	if _, err := BuildC4Request(badJSON, CmdStatus, ""); err == nil {
		t.Fatal("expected error for JSON-injectable JobID")
	}
	badNul := syntheticMeta()
	badNul.SessionID = "bad\x00id"
	if _, err := BuildC4Request(badNul, CmdStatus, ""); err == nil {
		t.Fatal("expected error for embedded NUL")
	}

	// Reject wrong context order, empty context, and >64 MiB ceiling
	badOrder := syntheticMeta()
	badOrder.Contexts[0], badOrder.Contexts[1] = badOrder.Contexts[1], badOrder.Contexts[0]
	if _, err := BuildC4Request(badOrder, CmdScopeBegin, ""); err == nil {
		t.Fatal("expected error on reordered canonical contexts")
	}
	badEmpty := syntheticMeta()
	badEmpty.Contexts[0].Data = nil
	if _, err := BuildC4Request(badEmpty, CmdScopeBegin, ""); err == nil {
		t.Fatal("expected error on empty context")
	}
	badSize := syntheticMeta()
	badSize.Contexts[0].Data = bytes.Repeat([]byte("x"), MaxContextBytes+1)
	if _, err := BuildC4Request(badSize, CmdSignAck, strings.Repeat("a", 64)); err == nil {
		t.Fatal("expected error on >64 MiB context")
	}

	// Reject invalid response magic, version, and AckJSONLen > 4096
	badResp := make([]byte, 4455)
	if _, err := DecodeResponseFrame(badResp); err == nil {
		t.Fatal("expected error on invalid VROA_V2 response magic")
	}
	var validResp ResponseFrame
	copy(validResp.Magic[:], ProtocolMagic)
	validResp.Version = ProtocolVersion
	validResp.AckJSONLen = 5000
	var respBuf bytes.Buffer
	_ = binary.Write(&respBuf, binary.LittleEndian, &validResp)
	if _, err := DecodeResponseFrame(respBuf.Bytes()); err == nil {
		t.Fatal("expected error on AckJSONLen > 4096")
	}
}
