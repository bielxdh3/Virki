//go:build linux && amd64

package c1c4bridge

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestLiveGoToNativeC4DaemonBridge(t *testing.T) {
	sock := os.Getenv("VIRKI_C4_TEST_SOCKET")
	if sock == "" {
		t.Skip("VIRKI_C4_TEST_SOCKET not set; run via c1-c4-native-bridge.test.mjs")
	}

	meta := syntheticMeta()

	// 1. STATUS
	reqStatus, err := BuildC4Request(meta, CmdStatus, "")
	if err != nil {
		t.Fatalf("BuildC4Request(STATUS): %v", err)
	}
	resp, err := SendC4Request(sock, reqStatus, nil, true)
	if err != nil || resp.Status != StatusOK || resp.Epoch < 1 {
		t.Fatalf("STATUS failed: err=%v status=%d epoch=%d", err, resp.Status, resp.Epoch)
	}
	meta.Epoch = resp.Epoch

	// 2. SCOPE_BEGIN
	reqBegin, err := BuildC4Request(meta, CmdScopeBegin, "")
	if err != nil {
		t.Fatalf("BuildC4Request(SCOPE_BEGIN): %v", err)
	}
	respBegin, err := SendC4Request(sock, reqBegin, nil, true)
	if err != nil || respBegin.Status != StatusOK {
		t.Fatalf("SCOPE_BEGIN failed: err=%v status=%d", err, respBegin.Status)
	}
	scopeToken := CString(respBegin.ScopeToken[:])
	if len(scopeToken) != 64 {
		t.Fatalf("expected 64-char scope_token, got %q", scopeToken)
	}

	// 3. Create 4 sealed O_RDONLY memfds, verify O_RDONLY + seals + contents, and send SIGN_ACK (must deny with 22)
	var fds [ContextCount]int
	for i := 0; i < ContextCount; i++ {
		fd, err := CreateSealedMemfd(meta.Contexts[i].Name, meta.Contexts[i].Data)
		if err != nil {
			t.Fatalf("CreateSealedMemfd(%s): %v", meta.Contexts[i].Name, err)
		}
		fds[i] = fd
		defer syscall.Close(fd)

		fl, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
		if errno != 0 || (fl&syscall.O_ACCMODE) != syscall.O_RDONLY {
			t.Fatalf("memfd %s not O_RDONLY (fl=%#x errno=%v)", meta.Contexts[i].Name, fl, errno)
		}
		seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), fcntlGetSeals, 0)
		if errno != 0 || (seals&sealAll) != sealAll {
			t.Fatalf("memfd %s missing seals (seals=%#x errno=%v)", meta.Contexts[i].Name, seals, errno)
		}
		buf := make([]byte, len(meta.Contexts[i].Data))
		n, err := syscall.Pread(fd, buf, 0)
		if err != nil || n != len(buf) || !bytes.Equal(buf, meta.Contexts[i].Data) {
			t.Fatalf("memfd %s content mismatch: n=%d err=%v", meta.Contexts[i].Name, n, err)
		}
	}
	reqSign, err := BuildC4Request(meta, CmdSignAck, scopeToken)
	if err != nil {
		t.Fatalf("BuildC4Request(SIGN_ACK): %v", err)
	}
	respSign, err := SendC4Request(sock, reqSign, fds[:], true)
	if err != nil {
		t.Fatalf("SendC4Request(SIGN_ACK): %v", err)
	}
	if respSign.Status != StatusErrSigningDisabled {
		t.Fatalf("SIGN_ACK status = %d, want %d (ERR_SIGNING_DISABLED)", respSign.Status, StatusErrSigningDisabled)
	}
	if CString(respSign.SignatureBase64[:]) != "" || respSign.AckJSONLen != 0 {
		t.Fatal("denied SIGN_ACK must not emit signature or ACK JSON")
	}

	// 4. SCOPE_ABORT
	reqAbort, err := BuildC4Request(meta, CmdScopeAbort, scopeToken)
	if err != nil {
		t.Fatalf("BuildC4Request(SCOPE_ABORT): %v", err)
	}
	respAbort, err := SendC4Request(sock, reqAbort, nil, true)
	if err != nil || respAbort.Status != StatusOK {
		t.Fatalf("SCOPE_ABORT failed: err=%v status=%d", err, respAbort.Status)
	}

	// 5. Unknown SCOPE_ABORT must fail with ERR_SCOPE_NOT_FOUND (20)
	reqUnknownAbort, err := BuildC4Request(meta, CmdScopeAbort, strings.Repeat("9", 64))
	if err != nil {
		t.Fatalf("BuildC4Request(unknown ABORT): %v", err)
	}
	respUnknownAbort, err := SendC4Request(sock, reqUnknownAbort, nil, true)
	if err != nil || respUnknownAbort.Status != StatusErrScopeNotFound {
		t.Fatalf("unknown SCOPE_ABORT status = %d (err=%v), want %d", respUnknownAbort.Status, err, StatusErrScopeNotFound)
	}

	// 6. Replay same nonce must fail with ERR_NONCE_REPLAY (15)
	respReplay, err := SendC4Request(sock, reqBegin, nil, true)
	if err != nil || respReplay.Status != StatusErrNonceReplay {
		t.Fatalf("nonce replay status = %d (err=%v), want %d", respReplay.Status, err, StatusErrNonceReplay)
	}

	// 7. Stale epoch must fail with ERR_STALE_EPOCH (16)
	staleMeta := syntheticMeta()
	staleMeta.Epoch = meta.Epoch + 99
	staleMeta.Nonce = "fedcba9876543210fedcba9876543210"
	reqStale, err := BuildC4Request(staleMeta, CmdScopeBegin, "")
	if err != nil {
		t.Fatalf("BuildC4Request(stale): %v", err)
	}
	respStale, err := SendC4Request(sock, reqStale, nil, true)
	if err != nil || respStale.Status != StatusErrStaleEpoch {
		t.Fatalf("stale epoch status = %d (err=%v), want %d", respStale.Status, err, StatusErrStaleEpoch)
	}

	// 8. Missing SHUT_WR half-close must fail with ERR_BAD_FRAME (11)
	respNoFin, err := SendC4Request(sock, reqStatus, nil, false)
	if err != nil || respNoFin.Status != StatusErrBadFrame {
		t.Fatalf("no-FIN status = %d (err=%v), want %d", respNoFin.Status, err, StatusErrBadFrame)
	}
}
