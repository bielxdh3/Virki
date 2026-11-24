package c1c4bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	input.OutputImageID, _, _, _ = testV3OCIContent()
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

// A small real content-addressed index -> manifest -> config/layer graph.
func testV3OCIContent() (imageID, rootJSON, nodesJSON string, archive []byte) {
	descriptor := func(media string, blob []byte) (string, string) {
		sum := sha256.Sum256(blob)
		id := "sha256:" + hex.EncodeToString(sum[:])
		return id, fmt.Sprintf(`{"mediaType":"%s","digest":"%s","size":%d}`, media, id, len(blob))
	}
	layer := make([]byte, 1024) // empty tar: two zero blocks
	layerID, layerDesc := descriptor("application/vnd.oci.image.layer.v1.tar", layer)
	config := []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["%s"]}}`, layerID))
	_, configDesc := descriptor("application/vnd.oci.image.config.v1+json", config)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":%s,"layers":[%s]}`, configDesc, layerDesc))
	_, manifestDesc := descriptor("application/vnd.oci.image.manifest.v1+json", manifest)
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[%s]}`, manifestDesc))
	imageID, rootJSON = descriptor("application/vnd.oci.image.index.v1+json", index)
	nodesJSON = "[" + strings.TrimSuffix(rootJSON, "}") + `,"role":"root"},` + manifestDesc + "," + configDesc + "," + layerDesc + "]"
	for _, blob := range [][]byte{index, manifest, config, layer} {
		archive = append(archive, blob...)
	}
	return
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

// An otherwise genuine signed C4 receipt must never satisfy a different
// BuildKit job or a different evidence verification request.
func TestV3SignedReceiptBoundToRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approval, _ := testV3ApprovalInput(t, pub)
	raw, err := BuildV3ApprovalEnvelope(approval, priv)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DecodeV3ApprovalEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	req, err := BuildV3Request(envelope, raw, CmdV3VerifyCandidate, strings.Repeat("a", 64), []byte("c1-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := V3CandidateReceipt{
		Version: 3, Status: "CANDIDATE_VERIFIED", OwnerKeyID: "c4-receipt-test",
		ApprovalKeyID: approval.KeyID, ApprovalID: approval.ApprovalID,
		ApprovalSerial: approval.ApprovalSerial, ScopeToken: CString(req.ScopeToken[:]),
		ApprovalEnvelopeSHA256: CString(req.ApprovalEnvelopeSHA256[:]),
		EvidenceSHA256:         CString(req.TranscriptSHA256[:]), JobID: approval.JobID,
		Role: approval.Role, Nonce: approval.Nonce, SourceCommit: approval.SourceCommit,
		BuildPlanSHA256: approval.BuildPlanSHA256, ExecutablePolicySHA256: approval.ExecutablePolicySHA256,
		ExporterIntentSHA256:   approval.ExporterIntentSHA256,
		FileSyncManifestSHA256: approval.FileSyncManifestSHA256, WorkerID: approval.WorkerID,
		OutputImageID: approval.OutputImageID, SequenceNumber: 12, Epoch: approval.Epoch,
	}
	for _, ctx := range approval.Contexts {
		receipt.ContextTreeDigests = append(receipt.ContextTreeDigests, CString(ctx.TreeDigest[:]))
		receipt.ContextStreamDigests = append(receipt.ContextStreamDigests, strings.TrimPrefix(CString(ctx.StreamDigest[:]), "sha256:"))
		receipt.ContextStreamLengths = append(receipt.ContextStreamLengths, ctx.StreamLength)
	}
	rawAck, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var resp ResponseFrame
	copy(resp.Magic[:], ProtocolMagicV3)
	resp.Version, resp.Status, resp.Epoch, resp.SequenceNumber = ProtocolVersionV3, StatusOK, receipt.Epoch, receipt.SequenceNumber
	resp.AckJSONLen = uint32(len(rawAck))
	copy(resp.AckJSON[:], rawAck)
	ackSHA := sha256.Sum256(rawAck)
	if err := copyCString(resp.CanonicalAckSHA256[:], hex.EncodeToString(ackSHA[:])); err != nil {
		t.Fatal(err)
	}
	if err := copyCString(resp.OwnerKeyID[:], receipt.OwnerKeyID); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, append([]byte(ReceiptDomainV3), rawAck...))
	if err := copyCString(resp.SignatureBase64[:], base64.StdEncoding.EncodeToString(sig)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyV3CandidateReceipt(resp, pub, receipt.OwnerKeyID, req); err != nil {
		t.Fatalf("genuine candidate receipt was rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*RequestFrame)
	}{
		{"other job", func(r *RequestFrame) { copy(r.JobID[:], "another-job") }},
		// Each build-identity claim must independently bind the signed C4
		// candidate receipt to the approved source, plan and executable policy.
		// These are defense-in-depth regressions for checks already enforced in
		// VerifyV3CandidateReceipt, not evidence of a previously accepted swap.
		{"other source commit", func(r *RequestFrame) { copy(r.SourceCommit[:], strings.Repeat("b", 40)) }},
		{"other build plan", func(r *RequestFrame) { copy(r.BuildPlanSHA256[:], strings.Repeat("b", 64)) }},
		{"other executable policy", func(r *RequestFrame) { copy(r.ExecutablePolicySHA256[:], strings.Repeat("b", 64)) }},
		{"other worker", func(r *RequestFrame) { copy(r.SessionID[:], "other-worker") }},
		{"other scope", func(r *RequestFrame) { copy(r.ScopeToken[:], strings.Repeat("b", 64)) }},
		{"other evidence", func(r *RequestFrame) { copy(r.TranscriptSHA256[:], strings.Repeat("b", 64)) }},
		{"other approval", func(r *RequestFrame) { copy(r.ApprovalEnvelopeSHA256[:], strings.Repeat("b", 64)) }},
		{"other image", func(r *RequestFrame) { copy(r.OutputImageID[:], "sha256:"+strings.Repeat("b", 64)) }},
		{"other tree", func(r *RequestFrame) { copy(r.ExpectedTreeDigests[0][:], "sha256:"+strings.Repeat("b", 64)) }},
		{"other stream", func(r *RequestFrame) { copy(r.ExpectedStreamDigests[0][:], "sha256:"+strings.Repeat("b", 64)) }},
		{"other length", func(r *RequestFrame) { r.ExpectedStreamLengths[0]++ }},
		{"other epoch", func(r *RequestFrame) { r.Epoch++ }},
		{"wrong command", func(r *RequestFrame) { r.Cmd = CmdV3Abort }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := req
			tc.edit(&other)
			if _, err := VerifyV3CandidateReceipt(resp, pub, receipt.OwnerKeyID, other); err == nil {
				t.Fatal("validly signed receipt was accepted for a different request")
			}
		})
	}
	for _, tc := range []struct {
		name string
		edit func(*ResponseFrame)
	}{
		{"altered frame epoch", func(r *ResponseFrame) { r.Epoch++ }},
		{"altered frame sequence", func(r *ResponseFrame) { r.SequenceNumber++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := resp
			tc.edit(&other)
			if _, err := VerifyV3CandidateReceipt(other, pub, receipt.OwnerKeyID, req); err == nil {
				t.Fatal("signed receipt mismatches its response frame")
			}
		})
	}
}
