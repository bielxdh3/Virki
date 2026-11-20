package c1c4bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testSPKIPin(publicKey ed25519.PublicKey) string {
	prefix := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	sum := sha256.Sum256(append(prefix, publicKey...))
	return hex.EncodeToString(sum[:])
}

func testV3ApprovalInput(t *testing.T, publicKey ed25519.PublicKey) (V3ApprovalInput, [][]byte) {
	t.Helper()
	var input V3ApprovalInput
	input.Epoch = 1
	input.ExpiresUnix = uint64(time.Now().Add(5 * time.Minute).Unix())
	input.KeyID = "owner-test-key"
	input.PublicKeyPinSHA256 = testSPKIPin(publicKey)
	input.ApprovalID = "approval-test-01"
	input.ApprovalSerial = "1"
	input.JobID = "job-test-01"
	input.Role = "runtime"
	input.Nonce = strings.Repeat("1", 32)
	input.SourceCommit = strings.Repeat("2", 40)
	input.BuildPlanSHA256 = strings.Repeat("3", 64)
	input.ExecutablePolicySHA256 = strings.Repeat("4", 64)
	input.ExporterIntentSHA256 = strings.Repeat("5", 64)
	input.OutputImageID = "sha256:" + strings.Repeat("6", 64)
	input.FileSyncManifestSHA256 = strings.Repeat("7", 64)
	input.IgnorePolicySHA256 = strings.Repeat("8", 64)
	input.WorkerID = "worker-test-01"
	input.WorkerUID = 60001
	input.WorkerGID = 60001
	input.DockerfileSHA256 = strings.Repeat("9", 64)
	input.IgnoreSource = "none"
	streams := make([][]byte, ContextCount)
	for i, name := range CanonicalContextNames {
		data, treeDigest := testV3CanonicalStream(name)
		streams[i] = data
		sum := sha256.Sum256(data)
		ctx := &input.Contexts[i]
		if err := fixedString(ctx.Name[:], name); err != nil {
			t.Fatal(err)
		}
		if err := fixedString(ctx.SessionID[:], fmt.Sprintf("session-%d", i)); err != nil {
			t.Fatal(err)
		}
		if err := fixedString(ctx.Identity[:], fmt.Sprintf("uid:%d:gid:%d", input.WorkerUID, input.WorkerGID)); err != nil {
			t.Fatal(err)
		}
		if err := fixedString(ctx.TreeDigest[:], treeDigest); err != nil {
			t.Fatal(err)
		}
		if err := fixedString(ctx.StreamDigest[:], "sha256:"+hex.EncodeToString(sum[:])); err != nil {
			t.Fatal(err)
		}
		ctx.StreamLength = uint64(len(data))
	}
	return input, streams
}

// Deterministic directory, file and symlink observations in the BuildKit stream ABI.
func testV3CanonicalStream(name string) ([]byte, string) {
	var stream, tree bytes.Buffer
	stream.WriteString("virki-context-stream-v1\x00")
	tree.WriteString("buildkit-worker-local-context-v2\x00")
	writeUint := func(b *bytes.Buffer, value uint64) {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		b.Write(encoded[:])
	}
	writeSized := func(b *bytes.Buffer, value string) {
		writeUint(b, uint64(len(value)))
		b.WriteString(value)
	}
	writeSized(&stream, name)
	content := []byte("DEV fixture for " + name + "\n")
	for _, b := range []*bytes.Buffer{&stream, &tree} {
		b.WriteByte('D')
		writeSized(b, "sub")
		writeUint(b, 0755)
		b.WriteByte('F')
		writeSized(b, "sub/evidence.txt")
		writeUint(b, 0644)
		writeUint(b, uint64(len(content)))
	}
	stream.Write(content)
	sum := sha256.Sum256(content)
	tree.Write(sum[:])
	for _, b := range []*bytes.Buffer{&stream, &tree} {
		b.WriteByte('L')
		writeSized(b, "zz-link")
		writeUint(b, 0777)
		writeSized(b, "sub/evidence.txt")
	}
	treeSum := sha256.Sum256(tree.Bytes())
	return stream.Bytes(), "sha256:" + hex.EncodeToString(treeSum[:])
}

func TestV3BinaryLayoutsAndOwnerApprovalSignature(t *testing.T) {
	if got := binary.Size(V3ContextClaim{}); got != 316 {
		t.Fatalf("V3 context claim size=%d, want 316", got)
	}
	if got := binary.Size(V3ApprovalEnvelope{}); got != 2669 {
		t.Fatalf("V3 approval envelope size=%d, want 2669", got)
	}
	if got := binary.Size(V3CandidateEvidenceHeader{}); got != 1347 {
		t.Fatalf("V3 evidence header size=%d, want 1347", got)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := testV3ApprovalInput(t, publicKey)
	raw, err := BuildV3ApprovalEnvelope(input, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := VerifyV3ApprovalEnvelope(raw, publicKey, input.KeyID, input.PublicKeyPinSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if fixedValue(decoded.WorkerID[:]) != input.WorkerID || decoded.Epoch != input.Epoch {
		t.Fatal("decoded V3 owner claims differ from signed input")
	}
	tampered := append([]byte(nil), raw...)
	tampered[32] ^= 1
	if _, err := VerifyV3ApprovalEnvelope(tampered, publicKey, input.KeyID, input.PublicKeyPinSHA256); err == nil {
		t.Fatal("tampered V3 approval envelope unexpectedly verified")
	}
}

func TestV3EvidenceAndRequestBinding(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := testV3ApprovalInput(t, publicKey)
	envelopeRaw, err := BuildV3ApprovalEnvelope(input, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DecodeV3ApprovalEnvelope(envelopeRaw)
	if err != nil {
		t.Fatal(err)
	}
	approvalSum := sha256.Sum256(envelopeRaw)
	proofPayload := []byte(`{"causalityProofSha256":"` + strings.Repeat("a", 64) + `","ociDagSha256":"` + strings.Repeat("b", 64) + `"}`)
	evidence, evidenceSHA, err := EncodeV3Evidence(V3EvidenceInput{
		ApprovalEnvelopeSHA256: hex.EncodeToString(approvalSum[:]),
		JobID:                  input.JobID, Role: input.Role, Nonce: input.Nonce, WorkerID: input.WorkerID,
		OutputImageID: input.OutputImageID, ExporterIntentSHA256: input.ExporterIntentSHA256,
		FileSyncManifestSHA256: input.FileSyncManifestSHA256,
		CausalityProofSHA256:   strings.Repeat("a", 64), OCIDAGSHA256: strings.Repeat("b", 64),
		FrontendProofSHA256: strings.Repeat("c", 64), Contexts: input.Contexts, Payload: proofPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(evidence); hex.EncodeToString(got[:]) != evidenceSHA {
		t.Fatal("evidence digest mismatch")
	}
	begin, err := BuildV3Request(envelope, envelopeRaw, CmdV3Begin, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if begin.Version != ProtocolVersionV3 || string(begin.Magic[:]) != ProtocolMagicV3 || begin.Cmd != CmdV3Begin {
		t.Fatal("V3_BEGIN frame has incorrect protocol identity")
	}
	verify, err := BuildV3Request(envelope, envelopeRaw, CmdV3VerifyCandidate, strings.Repeat("d", 64), evidence)
	if err != nil {
		t.Fatal(err)
	}
	if fixedValue(verify.TranscriptSHA256[:]) != evidenceSHA || fixedValue(verify.ApprovalEnvelopeSHA256[:]) != hex.EncodeToString(approvalSum[:]) {
		t.Fatal("V3_VERIFY frame does not bind evidence and approval bytes")
	}
}
