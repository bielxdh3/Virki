/*
 * Fixed-size binary v2 frame transport over Linux AF_UNIX SOCK_STREAM.
 * A SOCK_STREAM read can be arbitrarily fragmented even when the peer used
 * one sendmsg. No prefix, env/client flag or alternate framing is trusted.
 *
 * Must be included exactly once in native-owner-authority.c after its
 * protocol type definitions. This is an exact-length reader with a TOTAL
 * CLOCK_MONOTONIC deadline (not a fresh 2-second window per fragment).
 * SCM_RIGHTS may accompany any fragment: handles above the explicit V3
 * transport ceiling are closed;
 * malformed, unexpected, duplicated or truncated control messages deny.
 */
#ifndef VIRKI_OWNER_FRAME_V21_H
#define VIRKI_OWNER_FRAME_V21_H

#include <poll.h>

static bool owner_monotonic_ms_v21(uint64_t *out) {
  struct timespec now;
  if (!out || clock_gettime(CLOCK_MONOTONIC,&now) != 0 ||
      now.tv_sec < 0 || now.tv_nsec < 0) return false;
  uint64_t sec = (uint64_t)now.tv_sec;
  if (sec > (UINT64_MAX-999)/1000) return false;
  *out = sec*1000+(uint64_t)now.tv_nsec/1000000;
  return true;
}

static bool owner_receive_exact_frame_v21(int fd,
    virki_owner_request_frame_t *req, int *fds, size_t *out_fd_count,
    unsigned timeout_ms) {
  if (fd < 0 || !req || !fds || !out_fd_count || timeout_ms == 0) return false;
  uint64_t started=0,now=0;
  if (!owner_monotonic_ms_v21(&started) ||
      started > UINT64_MAX-timeout_ms) return false;
  const uint64_t deadline = started+timeout_ms;
  size_t offset=0;
  size_t received_fds=0;
  bool valid=true;
  while (offset < sizeof(*req) && valid && !g_stop) {
    if (!owner_monotonic_ms_v21(&now) || now>=deadline) {
      valid=false; break;
    }
    const uint64_t remaining=deadline-now;
    struct pollfd pfd={ .fd=fd, .events=POLLIN, .revents=0 };
    const int ready=poll(&pfd,1,remaining>INT_MAX ? INT_MAX : (int)remaining);
    if (ready<0 && errno==EINTR && !g_stop) continue;
    if (ready <= 0 || !(pfd.revents & POLLIN)) {
      valid=false; break;
    }
    struct iovec iov={
      .iov_base=((unsigned char *)req)+offset,
      .iov_len=sizeof(*req)-offset,
    };
    union {
      struct cmsghdr align;
      char bytes[CMSG_SPACE(sizeof(int)*8)];
    } control = {0};
    struct msghdr msg={
      .msg_iov=&iov,.msg_iovlen=1,
      .msg_control=control.bytes,.msg_controllen=sizeof(control.bytes),
    };
    const ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
    if (n<0 && errno==EINTR && !g_stop) continue;
    if (n <= 0) {
      if (n < 0 && (errno==EAGAIN || errno==EWOULDBLOCK)) continue;
      valid=false; break;
    }
    if (msg.msg_flags & (MSG_CTRUNC|MSG_TRUNC)) valid=false;

    for (struct cmsghdr *cmsg=CMSG_FIRSTHDR(&msg);cmsg;cmsg=CMSG_NXTHDR(&msg,cmsg)) {
      if (cmsg->cmsg_len < CMSG_LEN(0)) {
        valid=false;
        continue;
      }
      if (cmsg->cmsg_level!=SOL_SOCKET || cmsg->cmsg_type!=SCM_RIGHTS) {
        valid=false;
        continue;
      }
      const size_t bytes=cmsg->cmsg_len-CMSG_LEN(0);
      if (bytes % sizeof(int) != 0) valid=false;
      const size_t count=bytes/sizeof(int);
      for (size_t i=0;i<count;i++) {
        int received=-1;
        memcpy(&received,(const unsigned char *)CMSG_DATA(cmsg)+i*sizeof(int),sizeof(int));
        if (received<0) {
          valid=false;
        } else if (received_fds < VIRKI_OWNER_MAX_FD_COUNT) {
          fds[received_fds]=received;
        } else {
          close(received);
          valid=false;
        }
        received_fds++;
      }
    }
    offset+=(size_t)n;
  }
  *out_fd_count=received_fds;
  if (!valid || g_stop || offset!=sizeof(*req)) return false;

  /* A fixed-size frame on SOCK_STREAM is not self-delimiting against a
   * malicious client that sends sizeof(frame) followed by delayed garbage.
   * Require peer write-half-close after precisely one request. It proves
   * there cannot be a second fragment after we authorize a BEGIN/ABORT.
   * This deliberately REJECTS legacy v2 senders that keep their write side
   * open while awaiting the reply; no release path depends on this DEV-only
   * transport yet. A future negotiated v3 can make this explicit. */
  for (;;) {
    if (g_stop || !owner_monotonic_ms_v21(&now) || now>=deadline) return false;
    const uint64_t remaining=deadline-now;
    struct pollfd pfd={.fd=fd,.events=POLLIN,.revents=0};
    const int ready=poll(&pfd,1,remaining>INT_MAX ? INT_MAX : (int)remaining);
    if (ready<0 && errno==EINTR && !g_stop) continue;
    if (ready<=0 || !(pfd.revents & POLLIN)) return false;
    unsigned char trailing=0;
    struct iovec iov={.iov_base=&trailing,.iov_len=1};
    union {
      struct cmsghdr align;
      char bytes[CMSG_SPACE(sizeof(int)*8)];
    } control = {0};
    struct msghdr msg={
      .msg_iov=&iov,.msg_iovlen=1,
      .msg_control=control.bytes,.msg_controllen=sizeof(control.bytes),
    };
    const ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
    if (n<0 && errno==EINTR && !g_stop) continue;
    /* Any post-frame ancillary rights must be closed even on denial. */
    for (struct cmsghdr *cmsg=CMSG_FIRSTHDR(&msg);cmsg;cmsg=CMSG_NXTHDR(&msg,cmsg)) {
      if (cmsg->cmsg_level!=SOL_SOCKET || cmsg->cmsg_type!=SCM_RIGHTS ||
          cmsg->cmsg_len<CMSG_LEN(0)) continue;
      const size_t count=(cmsg->cmsg_len-CMSG_LEN(0))/sizeof(int);
      for (size_t i=0;i<count;i++) {
        int extra=-1;
        memcpy(&extra,(unsigned char *)CMSG_DATA(cmsg)+i*sizeof(int),sizeof(int));
        if (extra>=0) close(extra);
      }
    }
    if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) continue;
    return n==0 && !(msg.msg_flags & (MSG_CTRUNC|MSG_TRUNC)) &&
           CMSG_FIRSTHDR(&msg)==NULL;
  }
}

/* A full response is one native binary frame. Never deliver it with a
 * single unchecked send(0): the peer can close while we reply (SIGPIPE),
 * an OS write can be partial, or a slow peer can stall the serial owner.
 * Use a monotonic total deadline and per-call MSG_NOSIGNAL. An ambiguous
 * lost response is NOT license for the caller to replay a used nonce. */
static bool owner_send_response_v21(int fd,
    const virki_owner_response_frame_t *resp) {
  if (fd < 0 || !resp) return false;
  uint64_t start=0,now=0;
  if (!owner_monotonic_ms_v21(&start) || start>UINT64_MAX-2000) return false;
  const uint64_t end=start+2000;
  size_t offset=0;
  while (offset < sizeof(*resp) && !g_stop) {
    if (!owner_monotonic_ms_v21(&now) || now>=end) return false;
    struct pollfd pfd={.fd=fd,.events=POLLOUT,.revents=0};
    const int poll_result=poll(&pfd,1,(int)(end-now));
    if (poll_result<0 && errno==EINTR && !g_stop) continue;
    if (poll_result<=0 || !(pfd.revents & POLLOUT)) return false;
    const ssize_t wrote=send(fd,(const unsigned char *)resp+offset,
        sizeof(*resp)-offset,MSG_DONTWAIT|MSG_NOSIGNAL);
    if (wrote<0 && errno==EINTR && !g_stop) continue;
    if (wrote<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) continue;
    if (wrote<=0) return false;
    offset+=(size_t)wrote;
  }
  return offset==sizeof(*resp);
}

#endif
