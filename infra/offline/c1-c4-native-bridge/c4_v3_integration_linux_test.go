//go:build linux && amd64

package c1c4bridge

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type v3Daemon struct {
	cmd    *exec.Cmd
	socket string
	output *strings.Builder
}

func compileV3Daemon(t *testing.T, testBuild bool) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "native-owner-authority"))
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "native-owner-authority-v3")
	args := []string{"-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,relro,-z,now"}
	if testBuild {
		args = append(args, "-DVIRKI_OWNER_TEST_BUILD")
	}
	args = append(args, "-o", output, "native-owner-authority.c")
	cmd := exec.Command("gcc", args...)
	cmd.Dir = root
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile V3 daemon: %v\n%s", err, raw)
	}
	return output
}

func writeV3KeyFile(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path, value, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
}

func startV3Daemon(t *testing.T, binary string, testSigning bool,
	approvalPublicKey ed25519.PublicKey, approvalPin string,
	receiptPrivateKey ed25519.PrivateKey) *v3Daemon {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.Mkdir(ledgerDir, 0700); err != nil {
		t.Fatal(err)
	}
	approvalPath := filepath.Join(dir, "approval.pub")
	writeV3KeyFile(t, approvalPath, approvalPublicKey)
	args := []string{
		"--socket", filepath.Join(dir, "owner.sock"),
		"--ledger-dir", ledgerDir,
		"--dev-allow-same-uid",
		"--approval-public-key-file", approvalPath,
		"--approval-key-id", "owner-test-key",
		"--approval-pin-sha256", approvalPin,
	}
	if testSigning {
		keyPath := filepath.Join(dir, "receipt.key")
		writeV3KeyFile(t, keyPath, receiptPrivateKey)
		args = append(args, "--key-file", keyPath, "--key-id", "c4-test-receipt")
	}
	cmd := exec.Command(binary, args...)
	var output strings.Builder
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start C4 V3 daemon: %v", err)
	}
	daemon := &v3Daemon{cmd: cmd, socket: filepath.Join(dir, "owner.sock"), output: &output}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(daemon.socket); err == nil {
			return daemon
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("C4 V3 daemon did not create socket; output: %s", output.String())
	return nil
}

func makeV3Fixture(t *testing.T, ownerPublic ed25519.PublicKey, ownerPrivate ed25519.PrivateKey) (V3ApprovalEnvelope, []byte, V3ApprovalInput, [][]byte) {
	t.Helper()
	input, streams := testV3ApprovalInput(t, ownerPublic)
	// Every BEGIN consumes its signed nonce, including an aborted scope. Give
	// each independent fixture a fresh nonce so replay protection remains real.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	input.Nonce = hex.EncodeToString(nonce)
	envelopeRaw, err := BuildV3ApprovalEnvelope(input, ownerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DecodeV3ApprovalEnvelope(envelopeRaw)
	if err != nil {
		t.Fatal(err)
	}
	return envelope, envelopeRaw, input, streams
}

func sealedFD(t *testing.T, name string, data []byte) int {
	t.Helper()
	fd, err := CreateSealedMemfd(name, data)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return fd
}

func v3EvidenceWithPayload(t *testing.T, envelopeRaw []byte, input V3ApprovalInput, tamperProof bool) ([]byte, string) {
	t.Helper()
	approvalSHA := sha256.Sum256(envelopeRaw)
	exporterJSON := fmt.Sprintf(`{"schemaVersion":2,"id":0,"type":"image","destination":"virki-dev","attributesDigest":"sha256:%s"}`, input.ExporterIntentSHA256)
	rootVertex := "sha256:" + strings.Repeat("a", 64)
	var ctxParts, pathParts []string
	for i, c := range input.Contexts {
		name, identity, session := CString(c.Name[:]), CString(c.Identity[:]), CString(c.SessionID[:])
		vertex := "sha256:" + strings.Repeat(fmt.Sprintf("%x", i+1), 64)
		snapshot := fmt.Sprintf("snapshot-%d", i)
		ctxParts = append(ctxParts, fmt.Sprintf(`{"name":"%s","generation":"%s","contextIdentity":"%s","workerId":"%s","sessionId":"%s","vertexDigest":"%s","vertexOutputIndex":0,"snapshotId":"%s","treeDigestSchema":"buildkit-worker-local-context-v2","treeDigest":"%s","streamDigest":"%s","streamLength":%d}`,
			name, input.Nonce, identity, input.WorkerID, session, vertex, snapshot, CString(c.TreeDigest[:]), CString(c.StreamDigest[:]), c.StreamLength))
		pathParts = append(pathParts, fmt.Sprintf(`{"name":"%s","generation":"%s","contextIdentity":"%s","snapshotId":"%s","treeDigest":"%s","sourceVertexDigest":"%s","sourceOutputIndex":0,"edges":[{"parentVertexDigest":"%s","parentOutputIndex":0,"parentInputIndex":%d,"childVertexDigest":"%s","childOutputIndex":0}]}`,
			name, input.Nonce, identity, snapshot, CString(c.TreeDigest[:]), vertex, rootVertex, i, vertex))
	}
	causalityBase := fmt.Sprintf(`{"schemaVersion":3,"exporter":%s,"roots":[{"workerId":"%s","refId":"result-1","vertexDigest":"%s","outputIndex":0,"contextPaths":[%s]}],"proofDigest":""}`,
		exporterJSON, input.WorkerID, rootVertex, strings.Join(pathParts, ","))
	cSum := sha256.Sum256(append([]byte("virki-c1-export-causality-v3\x00"), causalityBase...))
	cHex := hex.EncodeToString(cSum[:])
	if tamperProof {
		cHex = strings.Repeat("0", 64)
	}
	causalityJSON := strings.Replace(causalityBase, `"proofDigest":""`, `"proofDigest":"sha256:`+cHex+`"`, 1)

	ociBase := fmt.Sprintf(`{"schemaVersion":1,"root":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":2048},"nodes":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":2048,"role":"root"}],"proofDigest":""}`,
		input.OutputImageID, input.OutputImageID)
	oSum := sha256.Sum256(append([]byte("virki-c1-oci-dag-v1\x00"), ociBase...))
	oHex := hex.EncodeToString(oSum[:])
	ociJSON := strings.Replace(ociBase, `"proofDigest":""`, `"proofDigest":"sha256:`+oHex+`"`, 1)

	feBase := `{"schemaVersion":1,"frontend":"dockerfile","proofDigest":""}`
	fSum := sha256.Sum256(append([]byte("virki-c1-frontend-proof-v1\x00"), feBase...))
	fHex := hex.EncodeToString(fSum[:])
	feJSON := strings.Replace(feBase, `"proofDigest":""`, `"proofDigest":"sha256:`+fHex+`"`, 1)

	payload := []byte(fmt.Sprintf(
		`{"schemaVersion":2,"epoch":%d,"binding":{"jobId":"%s","role":"%s","nonce":"%s","approvalId":"%s","exporter":%s},"contexts":[%s],"output":{"workerId":"%s","image":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":2048},"causality":%s,"ociDag":%s},"frontendProof":%s}`,
		input.Epoch, input.JobID, input.Role, input.Nonce, input.ApprovalID, exporterJSON,
		strings.Join(ctxParts, ","), input.WorkerID, input.OutputImageID,
		causalityJSON, ociJSON, feJSON))
	bundle, digest, err := EncodeV3Evidence(V3EvidenceInput{
		ApprovalEnvelopeSHA256: hex.EncodeToString(approvalSHA[:]),
		JobID:                  input.JobID, Role: input.Role, Nonce: input.Nonce, WorkerID: input.WorkerID,
		OutputImageID: input.OutputImageID, ExporterIntentSHA256: input.ExporterIntentSHA256,
		FileSyncManifestSHA256: input.FileSyncManifestSHA256,
		CausalityProofSHA256:   cHex,
		OCIDAGSHA256:           oHex,
		FrontendProofSHA256:    fHex,
		Contexts:               input.Contexts, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle, digest
}

func v3Evidence(t *testing.T, envelopeRaw []byte, input V3ApprovalInput) ([]byte, string) {
	t.Helper()
	return v3EvidenceWithPayload(t, envelopeRaw, input, false)
}

func v3Begin(t *testing.T, daemon *v3Daemon, envelope V3ApprovalEnvelope, envelopeRaw []byte) (string, int) {
	t.Helper()
	approvalFD := sealedFD(t, "v3-approval", envelopeRaw)
	req, err := BuildV3Request(envelope, envelopeRaw, CmdV3Begin, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendC4Request(daemon.socket, req, []int{approvalFD}, true)
	if err != nil {
		t.Fatalf("V3_BEGIN transport failed: %v; daemon output: %s", err, daemon.output.String())
	}
	if resp.Status != StatusOK {
		t.Fatalf("V3_BEGIN status=%d; daemon output: %s", resp.Status, daemon.output.String())
	}
	token := CString(resp.ScopeToken[:])
	if !isLowerHex(token, 64) {
		t.Fatalf("invalid V3 scope token %q", token)
	}
	return token, approvalFD
}

func v3Verify(t *testing.T, daemon *v3Daemon, envelope V3ApprovalEnvelope, envelopeRaw []byte,
	input V3ApprovalInput, streams [][]byte, token string, approvalFD int) ResponseFrame {
	t.Helper()
	evidence, _ := v3Evidence(t, envelopeRaw, input)
	evidenceFD := sealedFD(t, "v3-evidence", evidence)
	fds := make([]int, 0, ContextCount+2)
	for i, stream := range streams {
		fds = append(fds, sealedFD(t, fmt.Sprintf("v3-context-%d", i), stream))
	}
	fds = append(fds, approvalFD, evidenceFD)
	req, err := BuildV3Request(envelope, envelopeRaw, CmdV3VerifyCandidate, token, evidence)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendC4Request(daemon.socket, req, fds, true)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func v3Abort(t *testing.T, daemon *v3Daemon, epoch uint64, token, nonce string) {
	t.Helper()
	req, err := BuildV3AbortRequest(epoch, token, nonce)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendC4Request(daemon.socket, req, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusOK {
		t.Fatalf("V3_ABORT status=%d", resp.Status)
	}
}

func TestV3NativeDaemonVerifiesSealedEvidenceAndKeepsReleaseDisabled(t *testing.T) {
	ownerPublic, ownerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prodBinary := compileV3Daemon(t, false)
	testBinary := compileV3Daemon(t, true)
	approvalPin := testSPKIPin(ownerPublic)

	t.Run("test-only candidate receipt is signed but non-authorizing", func(t *testing.T) {
		daemon := startV3Daemon(t, testBinary, true, ownerPublic, approvalPin, receiptPrivate)
		envelope, envelopeRaw, input, streams := makeV3Fixture(t, ownerPublic, ownerPrivate)
		token, approvalFD := v3Begin(t, daemon, envelope, envelopeRaw)
		resp := v3Verify(t, daemon, envelope, envelopeRaw, input, streams, token, approvalFD)
		receipt, err := VerifyV3CandidateReceipt(resp, receiptPublic, "c4-test-receipt")
		if err != nil {
			t.Fatalf("verify signed V3 candidate receipt: %v", err)
		}
		if receipt.EvidenceSHA256 == "" || receipt.OutputImageID != input.OutputImageID ||
			receipt.OwnerKeyID != "c4-test-receipt" || receipt.ApprovalKeyID != input.KeyID ||
			receipt.ApprovalID != input.ApprovalID || receipt.ScopeToken != token ||
			len(receipt.ContextTreeDigests) != ContextCount || len(receipt.ContextStreamDigests) != ContextCount ||
			receipt.DeployAuthorized || receipt.WorkerReceiptPairAdmitted || receipt.ReleaseSignature {
			t.Fatalf("candidate receipt violated deny-by-default: %+v", receipt)
		}
		// Aborted scope must fail with ERR_SCOPE_ABORTED (21).
		abEnv, abRaw, abIn, abStreams := makeV3Fixture(t, ownerPublic, ownerPrivate)
		abToken, abFD := v3Begin(t, daemon, abEnv, abRaw)
		v3Abort(t, daemon, abEnv.Epoch, abToken, abIn.Nonce)
		abResp := v3Verify(t, daemon, abEnv, abRaw, abIn, abStreams, abToken, abFD)
		if abResp.Status != StatusErrScopeAborted {
			t.Fatalf("verify after V3_ABORT status=%d, want %d", abResp.Status, StatusErrScopeAborted)
		}
		// Mismatched signed approval envelope for an active scope must fail with ERR_PROVENANCE_FAIL (19).
		mEnv1, mRaw1, mIn1, _ := makeV3Fixture(t, ownerPublic, ownerPrivate)
		mToken, _ := v3Begin(t, daemon, mEnv1, mRaw1)
		mIn2 := mIn1
		mIn2.ApprovalSerial = "ser-other-02"
		mRaw2, err := BuildV3ApprovalEnvelope(mIn2, ownerPrivate)
		if err != nil {
			t.Fatal(err)
		}
		mEnv2, err := DecodeV3ApprovalEnvelope(mRaw2)
		if err != nil {
			t.Fatal(err)
		}
		mFD2 := sealedFD(t, "v3-approval-other", mRaw2)
		mResp := v3Verify(t, daemon, mEnv2, mRaw2, mIn2, abStreams, mToken, mFD2)
		if mResp.Status != StatusErrProvenanceFail {
			t.Fatalf("verify with mismatched approval envelope status=%d, want %d", mResp.Status, StatusErrProvenanceFail)
		}
		v3Abort(t, daemon, mEnv1.Epoch, mToken, mIn1.Nonce)

		// Forged causality proofDigest (with valid header/payload SHA-256) must be rejected semantically.
		tEnv, tRaw, tIn, tStreams := makeV3Fixture(t, ownerPublic, ownerPrivate)
		tToken, tAppFD := v3Begin(t, daemon, tEnv, tRaw)
		tEvBundle, _ := v3EvidenceWithPayload(t, tRaw, tIn, true)
		var tFDs []int
		for i, s := range tStreams {
			tFDs = append(tFDs, sealedFD(t, fmt.Sprintf("v3-tamper-ctx-%d", i), s))
		}
		tFDs = append(tFDs, tAppFD, sealedFD(t, "v3-tamper-ev", tEvBundle))
		tReq, err := BuildV3Request(tEnv, tRaw, CmdV3VerifyCandidate, tToken, tEvBundle)
		if err != nil {
			t.Fatal(err)
		}
		tResp, err := SendC4Request(daemon.socket, tReq, tFDs, true)
		if err != nil {
			t.Fatal(err)
		}
		if tResp.Status != StatusErrProvenanceFail {
			t.Fatalf("forged causality proofDigest status=%d, want %d", tResp.Status, StatusErrProvenanceFail)
		}
		v3Abort(t, daemon, tEnv.Epoch, tToken, tIn.Nonce)
		// V2 SIGN_ACK remains hard-disabled even in the test build with an ephemeral key.
		meta := syntheticMeta()
		v2Req, err := BuildC4Request(meta, CmdSignAck, strings.Repeat("d", 64))
		if err != nil {
			t.Fatal(err)
		}
		var v2FDs []int
		for i, ctx := range meta.Contexts {
			v2FDs = append(v2FDs, sealedFD(t, fmt.Sprintf("v2-context-%d", i), ctx.Data))
		}
		v2Resp, err := SendC4Request(daemon.socket, v2Req, v2FDs, true)
		if err != nil {
			t.Fatal(err)
		}
		if v2Resp.Status != StatusErrSigningDisabled {
			t.Fatalf("SIGN_ACK status=%d, want 22", v2Resp.Status)
		}
	})

	t.Run("production verifier validates bytes then denies signing", func(t *testing.T) {
		daemon := startV3Daemon(t, prodBinary, false, ownerPublic, approvalPin, nil)
		envelope, envelopeRaw, input, streams := makeV3Fixture(t, ownerPublic, ownerPrivate)
		token, approvalFD := v3Begin(t, daemon, envelope, envelopeRaw)
		resp := v3Verify(t, daemon, envelope, envelopeRaw, input, streams, token, approvalFD)
		if resp.Status != StatusErrSigningDisabled {
			t.Fatalf("valid V3 evidence status=%d, want 22", resp.Status)
		}
		v3Abort(t, daemon, envelope.Epoch, token, input.Nonce)

		// A tampered stream is rejected BEFORE the production signing-disabled result.
		envelope, envelopeRaw, input, streams = makeV3Fixture(t, ownerPublic, ownerPrivate)
		token, approvalFD = v3Begin(t, daemon, envelope, envelopeRaw)
		streams[0] = append([]byte(nil), streams[0]...)
		streams[0][0] ^= 0x01
		resp = v3Verify(t, daemon, envelope, envelopeRaw, input, streams, token, approvalFD)
		if resp.Status != StatusErrStreamMismatch {
			t.Fatalf("tampered context status=%d, want %d", resp.Status, StatusErrStreamMismatch)
		}
		v3Abort(t, daemon, envelope.Epoch, token, input.Nonce)
	})
}
