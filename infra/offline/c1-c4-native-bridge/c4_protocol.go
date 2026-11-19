package c1c4bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	ProtocolVersion = uint32(2)
	ProtocolMagic   = "VROA_V2\x00"
	ContextCount    = 4
	MaxContextBytes = 64 * 1024 * 1024 // C1 FSSyncSealedV15 & C4 VIRKI_OWNER_MAX_PAYLOAD_BYTES

	CmdStatus     = uint32(0x01)
	CmdScopeBegin = uint32(0x02)
	CmdSignAck    = uint32(0x03)
	CmdScopeAbort = uint32(0x04)

	StatusOK                 = uint32(0)
	StatusErrBadFrame        = uint32(11)
	StatusErrNonceReplay     = uint32(15)
	StatusErrStaleEpoch      = uint32(16)
	StatusErrScopeNotFound   = uint32(20)
	StatusErrSigningDisabled = uint32(22)
)

var CanonicalContextNames = [ContextCount]string{
	"source",
	"dockerfile",
	"offline-npm-cacache",
	"offline-prisma-engines",
}

// RequestFrame matches virki_owner_request_frame_t in native-owner-authority-protocol.h (1526 bytes).
type RequestFrame struct {
	Magic                  [8]byte
	Version                uint32
	Cmd                    uint32
	Epoch                  uint64
	ScopeToken             [65]byte
	SessionID              [65]byte
	JobID                  [65]byte
	Role                   [16]byte
	Nonce                  [33]byte
	SourceCommit           [41]byte
	BuildPlanSHA256        [65]byte
	ExecutablePolicySHA256 [65]byte
	OutputImageID          [73]byte
	ExpectedTreeDigests    [ContextCount][73]byte
	ExpectedStreamDigests  [ContextCount][73]byte
	ExpectedStreamLengths  [ContextCount]uint64
	ArchiveSHA256          [65]byte
	ArchiveBytes           uint64
	TranscriptSHA256       [65]byte
	ApprovalKeyID          [65]byte
	ApprovalID             [65]byte
	ApprovalSerial         [65]byte
	ApprovalEnvelopeSHA256 [65]byte
}

// ResponseFrame matches virki_owner_response_frame_t in native-owner-authority-protocol.h (4455 bytes).
type ResponseFrame struct {
	Magic              [8]byte
	Version            uint32
	Status             uint32
	Epoch              uint64
	SequenceNumber     uint64
	ScopeToken         [65]byte
	OwnerKeyID         [65]byte
	SignatureBase64    [128]byte
	CanonicalAckSHA256 [65]byte
	AckJSONLen         uint32
	AckJSON            [4096]byte
}

type C1ContextInput struct {
	Name       string
	TreeDigest string
	Data       []byte
}

type C1BuildMetadata struct {
	Epoch                     uint64
	SessionID                 string
	JobID                     string
	Role                      string
	Nonce                     string
	SourceCommit              string
	BuildPlanSHA256           string
	ExecutablePolicySHA256    string
	OutputImageID             string
	ArchiveSHA256             string
	ArchiveBytes              uint64
	TranscriptSHA256          string
	ApprovalKeyID             string
	ApprovalID                string
	ApprovalSerial            string
	ApprovalEnvelopeSHA256    string
	DeployAuthorized          bool
	WorkerReceiptPairAdmitted bool
	Contexts                  [ContextCount]C1ContextInput
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isDigest(s string) bool {
	return len(s) == 71 && s[:7] == "sha256:" && isLowerHex(s[7:], 64)
}

func isSafeJSONIdentifier(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func copyCString(dst []byte, val string) error {
	if len(val) >= len(dst) {
		return fmt.Errorf("field exceeds buffer capacity (%d >= %d)", len(val), len(dst))
	}
	for i := 0; i < len(val); i++ {
		if val[i] == 0 {
			return errors.New("embedded NUL byte forbidden")
		}
	}
	copy(dst, val)
	return nil
}

func CString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx >= 0 {
		return string(b[:idx])
	}
	return string(b)
}

func BuildC4Request(meta C1BuildMetadata, cmd uint32, scopeToken string) (RequestFrame, error) {
	var req RequestFrame
	if meta.DeployAuthorized || meta.WorkerReceiptPairAdmitted {
		return req, errors.New("non-authorizing invariant violated: deployAuthorized and workerReceiptPairAdmitted must remain false")
	}
	switch cmd {
	case CmdStatus, CmdScopeBegin:
		if scopeToken != "" {
			return req, errors.New("scopeToken must be empty for STATUS and SCOPE_BEGIN")
		}
	case CmdSignAck, CmdScopeAbort:
		if !isLowerHex(scopeToken, 64) {
			return req, errors.New("scopeToken must be 64 lowercase hex chars for SIGN_ACK and SCOPE_ABORT")
		}
	default:
		return req, fmt.Errorf("unsupported command: %d", cmd)
	}
	if meta.Epoch == 0 {
		return req, errors.New("epoch must be >= 1")
	}
	if meta.Role != "runtime" && meta.Role != "migrator" {
		return req, fmt.Errorf("invalid role: %q", meta.Role)
	}
	if !isLowerHex(meta.Nonce, 32) {
		return req, errors.New("nonce must be 32 lowercase hex chars")
	}
	if !isLowerHex(meta.SourceCommit, 40) {
		return req, errors.New("sourceCommit must be 40 lowercase hex chars")
	}
	if !isLowerHex(meta.BuildPlanSHA256, 64) || !isLowerHex(meta.ExecutablePolicySHA256, 64) {
		return req, errors.New("buildPlanSha256 and executablePolicySha256 must be 64 lowercase hex chars")
	}
	if !isDigest(meta.OutputImageID) {
		return req, errors.New("outputImageId must be sha256:<64 hex>")
	}
	for _, optHex := range []string{meta.ArchiveSHA256, meta.TranscriptSHA256, meta.ApprovalEnvelopeSHA256} {
		if optHex != "" && !isLowerHex(optHex, 64) {
			return req, errors.New("optional digest field must be empty or 64 lowercase hex chars")
		}
	}
	for _, id := range []string{meta.SessionID, meta.JobID, meta.ApprovalKeyID, meta.ApprovalID, meta.ApprovalSerial} {
		if !isSafeJSONIdentifier(id) {
			return req, errors.New("identifier contains unsafe JSON or control character")
		}
	}

	copy(req.Magic[:], ProtocolMagic)
	req.Version = ProtocolVersion
	req.Cmd = cmd
	req.Epoch = meta.Epoch

	for i := 0; i < ContextCount; i++ {
		ctx := meta.Contexts[i]
		if ctx.Name != CanonicalContextNames[i] {
			return req, fmt.Errorf("context[%d] must be %q, got %q", i, CanonicalContextNames[i], ctx.Name)
		}
		if !isDigest(ctx.TreeDigest) {
			return req, fmt.Errorf("context %q invalid treeDigest", ctx.Name)
		}
		if len(ctx.Data) == 0 || len(ctx.Data) > MaxContextBytes {
			return req, fmt.Errorf("context %q length %d out of bounds (1..%d)", ctx.Name, len(ctx.Data), MaxContextBytes)
		}
		sum := sha256.Sum256(ctx.Data)
		streamDigest := "sha256:" + hex.EncodeToString(sum[:])
		if err := copyCString(req.ExpectedTreeDigests[i][:], ctx.TreeDigest); err != nil {
			return req, err
		}
		if err := copyCString(req.ExpectedStreamDigests[i][:], streamDigest); err != nil {
			return req, err
		}
		req.ExpectedStreamLengths[i] = uint64(len(ctx.Data))
	}

	fields := []struct {
		dst []byte
		val string
	}{
		{req.ScopeToken[:], scopeToken},
		{req.SessionID[:], meta.SessionID},
		{req.JobID[:], meta.JobID},
		{req.Role[:], meta.Role},
		{req.Nonce[:], meta.Nonce},
		{req.SourceCommit[:], meta.SourceCommit},
		{req.BuildPlanSHA256[:], meta.BuildPlanSHA256},
		{req.ExecutablePolicySHA256[:], meta.ExecutablePolicySHA256},
		{req.OutputImageID[:], meta.OutputImageID},
		{req.ArchiveSHA256[:], meta.ArchiveSHA256},
		{req.TranscriptSHA256[:], meta.TranscriptSHA256},
		{req.ApprovalKeyID[:], meta.ApprovalKeyID},
		{req.ApprovalID[:], meta.ApprovalID},
		{req.ApprovalSerial[:], meta.ApprovalSerial},
		{req.ApprovalEnvelopeSHA256[:], meta.ApprovalEnvelopeSHA256},
	}
	for _, f := range fields {
		if err := copyCString(f.dst, f.val); err != nil {
			return req, err
		}
	}
	req.ArchiveBytes = meta.ArchiveBytes
	return req, nil
}

func EncodeRequestFrame(req RequestFrame) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &req); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DecodeResponseFrame(raw []byte) (ResponseFrame, error) {
	var resp ResponseFrame
	expected := binary.Size(resp)
	if len(raw) != expected {
		return resp, fmt.Errorf("response frame size mismatch: got %d, want %d", len(raw), expected)
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &resp); err != nil {
		return resp, err
	}
	if string(resp.Magic[:]) != ProtocolMagic || resp.Version != ProtocolVersion {
		return resp, errors.New("invalid VROA_V2 response magic or version")
	}
	if resp.AckJSONLen > uint32(len(resp.AckJSON)) {
		return resp, fmt.Errorf("invalid AckJSONLen: %d > %d", resp.AckJSONLen, len(resp.AckJSON))
	}
	for _, cstr := range [][]byte{resp.ScopeToken[:], resp.OwnerKeyID[:], resp.SignatureBase64[:], resp.CanonicalAckSHA256[:]} {
		if bytes.IndexByte(cstr, 0) < 0 {
			return resp, errors.New("unterminated C-string in VROA_V2 response")
		}
	}
	return resp, nil
}
