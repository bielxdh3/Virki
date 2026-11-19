//go:build linux && amd64

package c1c4bridge

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const (
	sysMemfdCreate  = 319 // linux/amd64 __NR_memfd_create
	mfdCloexec      = 0x0001
	mfdAllowSealing = 0x0002
	fcntlAddSeals   = 1033 // F_ADD_SEALS
	fcntlGetSeals   = 1034 // F_GET_SEALS
	sealAll         = 0x0001 | 0x0002 | 0x0004 | 0x0008
)

func CreateSealedMemfd(name string, data []byte) (int, error) {
	cname, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	fdRaw, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(cname)), mfdCloexec|mfdAllowSealing, 0)
	if errno != 0 {
		return -1, fmt.Errorf("memfd_create(%s): %w", name, errno)
	}
	rwFD := int(fdRaw)
	defer func() { _ = syscall.Close(rwFD) }()

	for off := 0; off < len(data); {
		n, err := syscall.Write(rwFD, data[off:])
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return -1, err
		}
		if n <= 0 {
			return -1, errors.New("short write to memfd")
		}
		off += n
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(rwFD), fcntlAddSeals, sealAll); errno != 0 {
		return -1, fmt.Errorf("F_ADD_SEALS(%s): %w", name, errno)
	}
	// Reopen via /proc/self/fd as O_RDONLY | O_CLOEXEC to match C4's F_GETFL == O_RDONLY requirement.
	roFD, err := syscall.Open(fmt.Sprintf("/proc/self/fd/%d", rwFD), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("reopen sealed memfd read-only: %w", err)
	}
	if _, err := syscall.Seek(roFD, 0, io.SeekStart); err != nil {
		_ = syscall.Close(roFD)
		return -1, err
	}
	return roFD, nil
}

func SendC4Request(socketPath string, req RequestFrame, fds []int, closeWrite bool) (ResponseFrame, error) {
	var resp ResponseFrame
	if req.Cmd == CmdSignAck && len(fds) != ContextCount {
		return resp, fmt.Errorf("SIGN_ACK requires %d descriptors, got %d", ContextCount, len(fds))
	}
	if req.Cmd != CmdSignAck && len(fds) != 0 {
		return resp, fmt.Errorf("command %d forbids SCM_RIGHTS descriptors", req.Cmd)
	}
	for _, fd := range fds {
		if fd <= 2 {
			return resp, fmt.Errorf("invalid context descriptor %d", fd)
		}
	}

	payload, err := EncodeRequestFrame(req)
	if err != nil {
		return resp, err
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return resp, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return resp, err
	}
	var oob []byte
	if len(fds) > 0 {
		oob = syscall.UnixRights(fds...)
	}
	var sendErr error
	ctrlErr := rawConn.Write(func(sockFD uintptr) bool {
		for len(payload) > 0 {
			n, err := syscall.SendmsgN(int(sockFD), payload, oob, nil, 0)
			if n > 0 {
				payload = payload[n:]
				oob = nil
			}
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				return false
			}
			if err != nil {
				sendErr = err
				return true
			}
			if n == 0 {
				sendErr = errors.New("zero-byte sendmsg progress")
				return true
			}
		}
		return true
	})
	if ctrlErr != nil {
		return resp, ctrlErr
	}
	earlyPeerClose := sendErr == syscall.EPIPE || sendErr == syscall.ECONNRESET
	if sendErr != nil && !earlyPeerClose {
		return resp, sendErr
	}
	if closeWrite && !earlyPeerClose {
		if err := conn.CloseWrite(); err != nil && !errors.Is(err, syscall.ENOTCONN) && !errors.Is(err, syscall.EPIPE) {
			return resp, err
		}
	}

	respBuf := make([]byte, binary.Size(resp))
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		if earlyPeerClose {
			return resp, fmt.Errorf("peer closed early (%w) without response: %v", sendErr, err)
		}
		return resp, err
	}
	return DecodeResponseFrame(respBuf)
}
