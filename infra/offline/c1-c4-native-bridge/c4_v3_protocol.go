package c1c4bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	ProtocolVersionV3  = uint32(3)
	ProtocolMagicV3    = "VROA_V3\x00"
	ApprovalMagicV3    = "VROA_AP3"
	EvidenceMagicV3    = "VROA_EV3"
	ApprovalDomainV3   = "VIRKI_OFFLINE_OWNER_APPROVAL_V3\x00"
	ReceiptDomainV3    = "VIRKI_C4_CANDIDATE_RECEIPT_V3\x00"
	MaxEvidenceBytesV3 = 4 * 1024 * 1024

	CmdV3Begin           = uint32(0x11)
	CmdV3VerifyCandidate = uint32(0x12)
	CmdV3Abort           = uint32(0x13)
)

// V3ContextClaim is byte-for-byte compatible with virki_owner_v3_context_claim_t.
type V3ContextClaim struct {
	Name         [32]byte
	SessionID    [65]byte
	Identity     [65]byte
	TreeDigest   [73]byte
	StreamDigest [73]byte
	StreamLength uint64
}

// V3ApprovalEnvelope is the signed, fixed-layout owner approval passed to C4.
// Signature covers ApprovalDomainV3 followed by all fields before Signature.
type V3ApprovalEnvelope struct {
	Magic                  [8]byte
	Version                uint32
	Epoch                  uint64
	ExpiresUnix            uint64
	KeyID                  [65]byte
	PublicKeyPinSHA256     [65]byte
	ApprovalID             [65]byte
	ApprovalSerial         [65]byte
	JobID                  [65]byte
	Role                   [16]byte
	Nonce                  [33]byte
	SourceCommit           [41]byte
	BuildPlanSHA256        [65]byte
	ExecutablePolicySHA256 [65]byte
	ExporterIntentSHA256   [65]byte
	OutputImageID          [73]byte
	FileSyncManifestSHA256 [65]byte
	IgnorePolicySHA256     [65]byte
	WorkerID               [65]byte
	WorkerUID              uint32
	WorkerGID              uint32
	DockerfileSHA256       [65]byte
	IgnorePath             [257]byte
	IgnoreSHA256           [65]byte
	IgnorePresent          uint32
	IgnoreSource           [32]byte
	ContextCount           uint32
	Contexts               [ContextCount]V3ContextClaim
	Signature              [64]byte
}

// V3CandidateEvidenceHeader matches virki_owner_candidate_evidence_v3_t.
// A canonical JSON payload follows the fixed header and carries the complete
// solver causality, OCI descriptor graph and built-in frontend proof.
type V3CandidateEvidenceHeader struct {
	Magic                     [8]byte
	Version                   uint32
	ApprovalEnvelopeSHA256    [65]byte
	JobID                     [65]byte
	Role                      [16]byte
	Nonce                     [33]byte
	WorkerID                  [65]byte
	OutputImageID             [73]byte
	ExporterIntentSHA256      [65]byte
	FileSyncManifestSHA256    [65]byte
	CausalityProofSHA256      [65]byte
	OCIDAGSHA256              [65]byte
	FrontendProofSHA256       [65]byte
	ContextTreeDigests        [ContextCount][73]byte
	ContextStreamDigests      [ContextCount][73]byte
	ContextStreamLengths      [ContextCount]uint64
	DeployAuthorized          uint32
	WorkerReceiptPairAdmitted uint32
	EvidencePayloadBytes      uint32
	EvidencePayloadSHA256     [65]byte
}

type V3ApprovalInput struct {
	Epoch                  uint64
	ExpiresUnix            uint64
	KeyID                  string
	PublicKeyPinSHA256     string
	ApprovalID             string
	ApprovalSerial         string
	JobID                  string
	Role                   string
	Nonce                  string
	SourceCommit           string
	BuildPlanSHA256        string
	ExecutablePolicySHA256 string
	ExporterIntentSHA256   string
	OutputImageID          string
	FileSyncManifestSHA256 string
	IgnorePolicySHA256     string
	WorkerID               string
	WorkerUID              uint32
	WorkerGID              uint32
	DockerfileSHA256       string
	IgnorePath             string
	IgnoreSHA256           string
	IgnorePresent          bool
	IgnoreSource           string
	Contexts               [ContextCount]V3ContextClaim
}

type V3EvidenceInput struct {
	ApprovalEnvelopeSHA256 string
	JobID                  string
	Role                   string
	Nonce                  string
	WorkerID               string
	OutputImageID          string
	ExporterIntentSHA256   string
	FileSyncManifestSHA256 string
	CausalityProofSHA256   string
	OCIDAGSHA256           string
	FrontendProofSHA256    string // empty only for direct LLB mode
	Contexts               [ContextCount]V3ContextClaim
	Payload                []byte // canonical JSON with full solver/OCI/frontend proof
}

type V3CandidateReceipt struct {
	Version                   uint32   `json:"version"`
	Status                    string   `json:"status"`
	OwnerKeyID                string   `json:"ownerKeyId,omitempty"`
	ApprovalKeyID             string   `json:"approvalKeyId,omitempty"`
	ApprovalID                string   `json:"approvalId,omitempty"`
	ApprovalSerial            string   `json:"approvalSerial,omitempty"`
	ScopeToken                string   `json:"scopeToken,omitempty"`
	ApprovalEnvelopeSHA256    string   `json:"approvalEnvelopeSha256"`
	EvidenceSHA256            string   `json:"evidenceSha256"`
	JobID                     string   `json:"jobId"`
	Role                      string   `json:"role"`
	Nonce                     string   `json:"nonce"`
	SourceCommit              string   `json:"sourceCommit,omitempty"`
	BuildPlanSHA256           string   `json:"buildPlanSha256,omitempty"`
	ExecutablePolicySHA256    string   `json:"executablePolicySha256,omitempty"`
	ExporterIntentSHA256      string   `json:"exporterIntentSha256,omitempty"`
	FileSyncManifestSHA256    string   `json:"fileSyncManifestSha256,omitempty"`
	WorkerID                  string   `json:"workerId"`
	OutputImageID             string   `json:"outputImageId"`
	ContextTreeDigests        []string `json:"contextTreeDigests,omitempty"`
	ContextStreamDigests      []string `json:"contextStreamDigests,omitempty"`
	ContextStreamLengths      []uint64 `json:"contextStreamLengths,omitempty"`
	SequenceNumber            uint64   `json:"sequenceNumber"`
	Epoch                     uint64   `json:"epoch"`
	DeployAuthorized          bool     `json:"deployAuthorized"`
	WorkerReceiptPairAdmitted bool     `json:"workerReceiptPairAdmitted"`
	ReleaseSignature          bool     `json:"releaseSignature"`
}

func fixedString(dst []byte, value string) error {
	if len(value) >= len(dst) || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("fixed field length/NUL violation (%d >= %d)", len(value), len(dst))
	}
	clear(dst)
	copy(dst, value)
	return nil
}

func fixedValue(src []byte) string { return CString(src) }

func encodeBinary(value any) ([]byte, error) {
	var out bytes.Buffer
	if err := binary.Write(&out, binary.LittleEndian, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func DecodeV3ApprovalEnvelope(raw []byte) (V3ApprovalEnvelope, error) {
	var envelope V3ApprovalEnvelope
	if len(raw) != binary.Size(envelope) {
		return envelope, fmt.Errorf("V3 approval envelope size mismatch: got %d, want %d", len(raw), binary.Size(envelope))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &envelope); err != nil {
		return envelope, err
	}
	if string(envelope.Magic[:]) != ApprovalMagicV3 || envelope.Version != ProtocolVersionV3 || envelope.ContextCount != ContextCount {
		return envelope, errors.New("invalid VROA_AP3 magic, version or context count")
	}
	return envelope, nil
}

func BuildV3ApprovalEnvelope(input V3ApprovalInput, ownerPrivateKey ed25519.PrivateKey) ([]byte, error) {
	var envelope V3ApprovalEnvelope
	if len(ownerPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("owner Ed25519 private key must be 64 bytes")
	}
	if input.Epoch == 0 || input.ExpiresUnix == 0 || input.WorkerUID == 0 || input.WorkerGID == 0 {
		return nil, errors.New("epoch, expiry and non-root worker UID/GID are required")
	}
	copy(envelope.Magic[:], ApprovalMagicV3)
	envelope.Version = ProtocolVersionV3
	envelope.Epoch = input.Epoch
	envelope.ExpiresUnix = input.ExpiresUnix
	envelope.WorkerUID = input.WorkerUID
	envelope.WorkerGID = input.WorkerGID
	envelope.ContextCount = ContextCount
	fields := []struct {
		dst   []byte
		value string
	}{
		{envelope.KeyID[:], input.KeyID},
		{envelope.PublicKeyPinSHA256[:], input.PublicKeyPinSHA256},
		{envelope.ApprovalID[:], input.ApprovalID},
		{envelope.ApprovalSerial[:], input.ApprovalSerial},
		{envelope.JobID[:], input.JobID},
		{envelope.Role[:], input.Role},
		{envelope.Nonce[:], input.Nonce},
		{envelope.SourceCommit[:], input.SourceCommit},
		{envelope.BuildPlanSHA256[:], input.BuildPlanSHA256},
		{envelope.ExecutablePolicySHA256[:], input.ExecutablePolicySHA256},
		{envelope.ExporterIntentSHA256[:], input.ExporterIntentSHA256},
		{envelope.OutputImageID[:], input.OutputImageID},
		{envelope.FileSyncManifestSHA256[:], input.FileSyncManifestSHA256},
		{envelope.IgnorePolicySHA256[:], input.IgnorePolicySHA256},
		{envelope.WorkerID[:], input.WorkerID},
		{envelope.DockerfileSHA256[:], input.DockerfileSHA256},
		{envelope.IgnorePath[:], input.IgnorePath},
		{envelope.IgnoreSHA256[:], input.IgnoreSHA256},
		{envelope.IgnoreSource[:], input.IgnoreSource},
	}
	for _, field := range fields {
		if err := fixedString(field.dst, field.value); err != nil {
			return nil, err
		}
	}
	if input.IgnorePresent {
		envelope.IgnorePresent = 1
	}
	envelope.Contexts = input.Contexts
	unsigned, err := encodeBinary(envelope)
	if err != nil {
		return nil, err
	}
	bodyLen := len(unsigned) - ed25519.SignatureSize
	message := append([]byte(ApprovalDomainV3), unsigned[:bodyLen]...)
	copy(envelope.Signature[:], ed25519.Sign(ownerPrivateKey, message))
	return encodeBinary(envelope)
}

func VerifyV3ApprovalEnvelope(raw []byte, publicKey ed25519.PublicKey, expectedKeyID, expectedPin string) (V3ApprovalEnvelope, error) {
	envelope, err := DecodeV3ApprovalEnvelope(raw)
	if err != nil {
		return envelope, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return envelope, errors.New("owner Ed25519 public key must be 32 bytes")
	}
	if fixedValue(envelope.KeyID[:]) != expectedKeyID || fixedValue(envelope.PublicKeyPinSHA256[:]) != expectedPin {
		return envelope, errors.New("owner approval key ID or SPKI pin mismatch")
	}
	spkiPrefix := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	spki := append(spkiPrefix, publicKey...)
	pin := sha256.Sum256(spki)
	if hex.EncodeToString(pin[:]) != expectedPin {
		return envelope, errors.New("owner public key does not match pinned SPKI SHA-256")
	}
	rawBody := append([]byte(nil), raw[:len(raw)-ed25519.SignatureSize]...)
	message := append([]byte(ApprovalDomainV3), rawBody...)
	if !ed25519.Verify(publicKey, message, envelope.Signature[:]) {
		return envelope, errors.New("VROA_AP3 owner signature invalid")
	}
	return envelope, nil
}

func EncodeV3Evidence(input V3EvidenceInput) ([]byte, string, error) {
	var header V3CandidateEvidenceHeader
	if len(input.Payload) == 0 {
		return nil, "", errors.New("V3 evidence payload must contain the canonical solver/OCI/frontend proof")
	}
	copy(header.Magic[:], EvidenceMagicV3)
	header.Version = ProtocolVersionV3
	fields := []struct {
		dst   []byte
		value string
	}{
		{header.ApprovalEnvelopeSHA256[:], input.ApprovalEnvelopeSHA256},
		{header.JobID[:], input.JobID}, {header.Role[:], input.Role},
		{header.Nonce[:], input.Nonce}, {header.WorkerID[:], input.WorkerID},
		{header.OutputImageID[:], input.OutputImageID},
		{header.ExporterIntentSHA256[:], input.ExporterIntentSHA256},
		{header.FileSyncManifestSHA256[:], input.FileSyncManifestSHA256},
		{header.CausalityProofSHA256[:], input.CausalityProofSHA256},
		{header.OCIDAGSHA256[:], input.OCIDAGSHA256},
		{header.FrontendProofSHA256[:], input.FrontendProofSHA256},
	}
	for _, field := range fields {
		if err := fixedString(field.dst, field.value); err != nil {
			return nil, "", err
		}
	}
	for i, ctx := range input.Contexts {
		header.ContextTreeDigests[i] = ctx.TreeDigest
		header.ContextStreamDigests[i] = ctx.StreamDigest
		header.ContextStreamLengths[i] = ctx.StreamLength
	}
	if len(input.Payload) > MaxEvidenceBytesV3-binary.Size(header) {
		return nil, "", errors.New("V3 evidence payload exceeds 4 MiB")
	}
	header.EvidencePayloadBytes = uint32(len(input.Payload))
	payloadSHA := sha256.Sum256(input.Payload)
	if err := fixedString(header.EvidencePayloadSHA256[:], hex.EncodeToString(payloadSHA[:])); err != nil {
		return nil, "", err
	}
	rawHeader, err := encodeBinary(header)
	if err != nil {
		return nil, "", err
	}
	bundle := append(rawHeader, input.Payload...)
	sum := sha256.Sum256(bundle)
	return bundle, hex.EncodeToString(sum[:]), nil
}

func BuildV3Request(envelope V3ApprovalEnvelope, envelopeRaw []byte, cmd uint32, scopeToken string, evidenceRaw []byte) (RequestFrame, error) {
	var req RequestFrame
	if len(envelopeRaw) != binary.Size(envelope) {
		return req, errors.New("invalid V3 approval envelope byte length")
	}
	if cmd != CmdV3Begin && cmd != CmdV3VerifyCandidate && cmd != CmdV3Abort {
		return req, fmt.Errorf("unsupported V3 command %d", cmd)
	}
	if cmd == CmdV3Begin && scopeToken != "" {
		return req, errors.New("V3_BEGIN scope token must be empty")
	}
	if (cmd == CmdV3VerifyCandidate || cmd == CmdV3Abort) && !isLowerHex(scopeToken, 64) {
		return req, errors.New("V3 command requires a 64-character scope token")
	}
	copy(req.Magic[:], ProtocolMagicV3)
	req.Version = ProtocolVersionV3
	req.Cmd = cmd
	req.Epoch = envelope.Epoch
	fields := []struct {
		dst   []byte
		value string
	}{
		{req.ScopeToken[:], scopeToken}, {req.SessionID[:], fixedValue(envelope.WorkerID[:])},
		{req.JobID[:], fixedValue(envelope.JobID[:])}, {req.Role[:], fixedValue(envelope.Role[:])},
		{req.Nonce[:], fixedValue(envelope.Nonce[:])}, {req.SourceCommit[:], fixedValue(envelope.SourceCommit[:])},
		{req.BuildPlanSHA256[:], fixedValue(envelope.BuildPlanSHA256[:])},
		{req.ExecutablePolicySHA256[:], fixedValue(envelope.ExecutablePolicySHA256[:])},
		{req.OutputImageID[:], fixedValue(envelope.OutputImageID[:])},
		{req.ArchiveSHA256[:], fixedValue(envelope.FileSyncManifestSHA256[:])},
		{req.ApprovalKeyID[:], fixedValue(envelope.KeyID[:])},
		{req.ApprovalID[:], fixedValue(envelope.ApprovalID[:])},
		{req.ApprovalSerial[:], fixedValue(envelope.ApprovalSerial[:])},
	}
	for _, field := range fields {
		if err := copyCString(field.dst, field.value); err != nil {
			return req, err
		}
	}
	approvalSHA := sha256.Sum256(envelopeRaw)
	if err := copyCString(req.ApprovalEnvelopeSHA256[:], hex.EncodeToString(approvalSHA[:])); err != nil {
		return req, err
	}
	var total uint64
	for i, ctx := range envelope.Contexts {
		req.ExpectedTreeDigests[i] = ctx.TreeDigest
		req.ExpectedStreamDigests[i] = ctx.StreamDigest
		req.ExpectedStreamLengths[i] = ctx.StreamLength
		if total > ^uint64(0)-ctx.StreamLength {
			return req, errors.New("context stream length overflow")
		}
		total += ctx.StreamLength
	}
	req.ArchiveBytes = total
	if cmd == CmdV3VerifyCandidate {
		if len(evidenceRaw) == 0 || len(evidenceRaw) > MaxEvidenceBytesV3 {
			return req, errors.New("V3_VERIFY_CANDIDATE requires bounded evidence bytes")
		}
		sum := sha256.Sum256(evidenceRaw)
		if err := copyCString(req.TranscriptSHA256[:], hex.EncodeToString(sum[:])); err != nil {
			return req, err
		}
	} else if len(evidenceRaw) != 0 {
		return req, errors.New("evidence bytes are only valid for V3_VERIFY_CANDIDATE")
	}
	return req, nil
}

func BuildV3AbortRequest(epoch uint64, scopeToken, nonce string) (RequestFrame, error) {
	var req RequestFrame
	if epoch == 0 || !isLowerHex(scopeToken, 64) || !isLowerHex(nonce, 32) {
		return req, errors.New("V3_ABORT requires a nonzero epoch, scope token and nonce")
	}
	copy(req.Magic[:], ProtocolMagicV3)
	req.Version = ProtocolVersionV3
	req.Cmd = CmdV3Abort
	req.Epoch = epoch
	if err := copyCString(req.ScopeToken[:], scopeToken); err != nil {
		return req, err
	}
	if err := copyCString(req.Nonce[:], nonce); err != nil {
		return req, err
	}
	return req, nil
}

func DecodeResponseFrameV3(raw []byte) (ResponseFrame, error) {
	var resp ResponseFrame
	expected := binary.Size(resp)
	if len(raw) != expected {
		return resp, fmt.Errorf("V3 response frame size mismatch: got %d, want %d", len(raw), expected)
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &resp); err != nil {
		return resp, err
	}
	if string(resp.Magic[:]) != ProtocolMagicV3 || resp.Version != ProtocolVersionV3 {
		return resp, errors.New("invalid VROA_V3 response magic or version")
	}
	if resp.AckJSONLen > uint32(len(resp.AckJSON)) {
		return resp, fmt.Errorf("invalid V3 AckJSONLen %d", resp.AckJSONLen)
	}
	for _, cstr := range [][]byte{resp.ScopeToken[:], resp.OwnerKeyID[:], resp.SignatureBase64[:], resp.CanonicalAckSHA256[:]} {
		if bytes.IndexByte(cstr, 0) < 0 {
			return resp, errors.New("unterminated C-string in VROA_V3 response")
		}
	}
	return resp, nil
}

func VerifyV3CandidateReceipt(resp ResponseFrame, receiptPublicKey ed25519.PublicKey, expectedKeyID string) (V3CandidateReceipt, error) {
	var receipt V3CandidateReceipt
	if len(receiptPublicKey) != ed25519.PublicKeySize {
		return receipt, errors.New("receipt Ed25519 public key must be 32 bytes")
	}
	if resp.Status != StatusOK || resp.AckJSONLen == 0 || resp.AckJSONLen > uint32(len(resp.AckJSON)) {
		return receipt, fmt.Errorf("V3 candidate verification failed with status %d", resp.Status)
	}
	if fixedValue(resp.OwnerKeyID[:]) != expectedKeyID {
		return receipt, errors.New("C4 receipt key ID mismatch")
	}
	ack := resp.AckJSON[:resp.AckJSONLen]
	ackSHA := sha256.Sum256(ack)
	if fixedValue(resp.CanonicalAckSHA256[:]) != hex.EncodeToString(ackSHA[:]) {
		return receipt, errors.New("C4 candidate receipt canonical SHA-256 mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(fixedValue(resp.SignatureBase64[:]))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return receipt, errors.New("C4 candidate receipt signature malformed")
	}
	message := append([]byte(ReceiptDomainV3), ack...)
	if !ed25519.Verify(receiptPublicKey, message, signature) {
		return receipt, errors.New("C4 candidate receipt signature invalid")
	}
	if err := json.Unmarshal(ack, &receipt); err != nil {
		return receipt, err
	}
	if receipt.Version != 3 || receipt.Status != "CANDIDATE_VERIFIED" || receipt.DeployAuthorized || receipt.WorkerReceiptPairAdmitted || receipt.ReleaseSignature {
		return receipt, errors.New("V3 receipt violates non-authorizing invariant")
	}
	return receipt, nil
}
