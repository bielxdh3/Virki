/*
 * Native Owner Authority Client Test Fixture for PR #88
 * Can perform STATUS, SCOPE_BEGIN, SIGN_ACK (with 4 sealed memfds), and adversarial cases.
 */

#define _GNU_SOURCE
#include "native-owner-authority-protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/memfd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "buildkit-context-abi.h"

static int connect_owner_socket(const char *sock_path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  if (strlen(sock_path) >= sizeof(sun.sun_path)) {
    close(fd);
    return -1;
  }
  strcpy(sun.sun_path, sock_path);

  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int create_sealed_memfd(const char *name, const void *data, size_t len, bool missing_seal) {
  int fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (fd < 0) return -1;

  if (len > 0) {
    if (write(fd, data, len) != (ssize_t)len) {
      close(fd);
      return -1;
    }
  }

  int seals = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL;
  if (missing_seal) {
    seals &= ~F_SEAL_WRITE; // Intentionally omit WRITE seal for negative test
  }
  if (fcntl(fd, F_ADD_SEALS, seals) != 0) {
    close(fd);
    return -1;
  }

  /* Reopen via /proc/self/fd as strictly O_RDONLY */
  char proc_path[64];
  snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
  int ro_fd = open(proc_path, O_RDONLY | O_CLOEXEC);
  close(fd);
  return ro_fd;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <socket_path> <cmd: status|begin|sign|sign-corrupt-stream|sign-missing-seal|sign-duplicate-fd|sign-bad-image|abort> [nonce] [scope_token] [epoch]\n", argv[0]);
    return 2;
  }

  const char *sock_path = argv[1];
  const char *action = argv[2];
  const char *nonce = (argc > 3) ? argv[3] : "11223344556677889900aabbccddeeff";
  const char *scope_token_arg = (argc > 4) ? argv[4] : "";
  uint64_t epoch = (argc > 5) ? (uint64_t)strtoull(argv[5], NULL, 10) : 1;

  int sock = connect_owner_socket(sock_path);
  if (sock < 0) {
    fprintf(stderr, "CLIENT_CONNECT_FAILED: %s\n", strerror(errno));
    return 3;
  }

  virki_owner_request_frame_t req;
  memset(&req, 0, sizeof(req));
  memcpy(req.magic, VIRKI_OWNER_PROTOCOL_MAGIC, sizeof(req.magic));
  req.version = VIRKI_OWNER_PROTOCOL_VERSION;
  req.epoch = epoch;

  int fds[9] = {-1, -1, -1, -1, -1, -1, -1, -1, -1};
  bool send_fds = false;

  const bool fragmented = strstr(action,"-fragmented") != NULL;
  if (!strcmp(action, "status") || !strcmp(action, "status-fragmented") ||
      !strcmp(action, "status-with-fd") || !strcmp(action, "status-trailing") ||
      !strcmp(action, "status-delayed-tail") ||
      !strcmp(action, "status-disconnect") || !strcmp(action, "status-no-fin")) {
    req.cmd = VIRKI_OWNER_CMD_STATUS;
    if (!strcmp(action, "status-with-fd")) {
      fds[0]=create_sealed_memfd("malformed-status-fd","X",1,false);
      if (fds[0]<0) return 3;
      send_fds=true;
    }
  } else if (!strcmp(action, "begin") || !strcmp(action, "begin-fragmented") ||
             !strcmp(action, "begin-trailing") ||
             !strcmp(action, "begin-disconnect") ||
             !strcmp(action, "begin-no-fin")) {
    req.cmd = VIRKI_OWNER_CMD_SCOPE_BEGIN;
    snprintf(req.nonce, sizeof(req.nonce), "%s", nonce);
  } else if (!strcmp(action, "abort") || !strcmp(action, "abort-fragmented")) {
    req.cmd = VIRKI_OWNER_CMD_SCOPE_ABORT;
    snprintf(req.scope_token, sizeof(req.scope_token), "%s", scope_token_arg);
    // ABORT must prove the same nonce as the original prepared generation.
    snprintf(req.nonce, sizeof(req.nonce), "%s", nonce);
  } else if (strstr(action, "sign")) {
    req.cmd = VIRKI_OWNER_CMD_SIGN_ACK;
    snprintf(req.scope_token, sizeof(req.scope_token), "%s", scope_token_arg);
    snprintf(req.nonce, sizeof(req.nonce), "%s", nonce);
    strcpy(req.role, "runtime");
    strcpy(req.session_id, "session-test-01");
    strcpy(req.job_id, "job-test-01");
    strcpy(req.source_commit, "1111222233334444555566667777888899990000");
    strcpy(req.build_plan_sha256, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    strcpy(req.executable_policy_sha256, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    if (!strcmp(action, "sign-bad-image")) {
      strcpy(req.output_image_id, "invalid_image_id_no_sha_prefix");
    } else {
      strcpy(req.output_image_id, "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    }

    strcpy(req.archive_sha256, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    req.archive_bytes = 1024;
    strcpy(req.transcript_sha256, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    strcpy(req.approval_envelope_sha256, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    strcpy(req.approval_id, "app-001");
    strcpy(req.approval_serial, "serial-001");

    /* Create 4 sample contexts */
    const char *contexts[VIRKI_OWNER_CONTEXT_COUNT] = {
      "CONTEXT_PAYLOAD_SOURCE_DATA_V2",
      "CONTEXT_PAYLOAD_DOCKERFILE_DATA_V2",
      "CONTEXT_PAYLOAD_NPM_CACACHE_DATA_V2",
      "CONTEXT_PAYLOAD_PRISMA_ENGINES_DATA_V2"
    };

    send_fds = true;
    for (int i = 0; i < VIRKI_OWNER_CONTEXT_COUNT; i++) {
      size_t len = strlen(contexts[i]);
      bool missing_seal = (!strcmp(action, "sign-missing-seal") && i == 1);
      fds[i] = create_sealed_memfd(VIRKI_OWNER_CONTEXT_NAMES[i], contexts[i], len, missing_seal);
      req.expected_stream_lengths[i] = len;

      /* Compute flat SHA-256 for expected */
      virki_abi_sha256_ctx c;
      virki_abi_sha256_init(&c);
      virki_abi_sha256_update(&c, (const uint8_t *)contexts[i], len);
      uint8_t d[32];
      virki_abi_sha256_final(&c, d);

      static const char hex[] = "0123456789abcdef";
      strcpy(req.expected_stream_digests[i], "sha256:");
      for (size_t k = 0; k < 32; k++) {
        req.expected_stream_digests[i][7 + k * 2] = hex[d[k] >> 4];
        req.expected_stream_digests[i][7 + k * 2 + 1] = hex[d[k] & 0x0f];
      }
      req.expected_stream_digests[i][71] = '\0';

      /* Provide valid tree digest string */
      strcpy(req.expected_tree_digests[i], req.expected_stream_digests[i]);
    }

    if (!strcmp(action, "sign-corrupt-stream")) {
      /* Corrupt expected stream digest so it mismatches */
      req.expected_stream_digests[0][10] ^= 0x01;
    }

    if (!strcmp(action, "sign-duplicate-fd")) {
      /* Close FD 1 and duplicate FD 0 into it */
      close(fds[1]);
      fds[1] = dup(fds[0]);
    }
    if (!strcmp(action, "sign-fifth-fd") || !strcmp(action, "sign-excess-fd")) {
      const size_t additional = !strcmp(action, "sign-fifth-fd") ? 1 : 5;
      for (size_t i=0;i<additional;i++) {
        fds[VIRKI_OWNER_CONTEXT_COUNT+i]=create_sealed_memfd(
          "unapproved-fifth-context", "UNAPPROVED", 10, false);
        if (fds[VIRKI_OWNER_CONTEXT_COUNT+i] < 0) {
          fprintf(stderr, "EXTRA_FD_CREATION_FAILED\n");
          return 3;
        }
      }
    }
  } else {
    fprintf(stderr, "Unknown action: %s\n", action);
    close(sock);
    return 2;
  }

  /* Send request */
  struct iovec iov = { .iov_base = &req, .iov_len = sizeof(req) };
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  char cmsg_buf[CMSG_SPACE(sizeof(int) * 9)];
  if (send_fds) {
    memset(cmsg_buf, 0, sizeof(cmsg_buf));
    msg.msg_control = cmsg_buf;
    size_t send_count = !strcmp(action, "status-with-fd") ? 1 :
      !strcmp(action, "sign-fifth-fd") ? 5 :
      !strcmp(action, "sign-excess-fd") ? 9 : VIRKI_OWNER_CONTEXT_COUNT;
    msg.msg_controllen = CMSG_SPACE(sizeof(int) * send_count);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * send_count);
    memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * send_count);
  }

  /* For V21 tests, split the request at non-field-aligned offsets even when
   * SCM_RIGHTS is present. The descriptor rides the FIRST one-byte message,
   * with the rest delivered in separate stream writes. A daemon requiring a
   * single recvmsg(sizeof req) rejects this completely valid transport. */
  ssize_t s;
  if (fragmented) {
    iov.iov_len=1;
    s=sendmsg(sock,&msg,MSG_NOSIGNAL);
    if (s == 1) {
      size_t offset=1;
      const size_t parts[]={2,5,17,31,sizeof(req)};
      const struct timespec pause={.tv_sec=0,.tv_nsec=10000000};
      for (size_t i=0;i<sizeof(parts)/sizeof(parts[0]) && offset<sizeof(req);i++) {
        size_t end=parts[i];
        if (end > sizeof(req)) end=sizeof(req);
        if (end <= offset) continue;
        size_t remaining=end-offset;
        while (remaining>0) {
          ssize_t n=send(sock,(const unsigned char *)&req+offset,remaining,MSG_NOSIGNAL);
          if (n<=0) {s=-1;break;}
          offset+=(size_t)n;
          remaining-=(size_t)n;
        }
        if (s<0) break;
        nanosleep(&pause,NULL);
      }
      if (offset==sizeof(req)) s=(ssize_t)sizeof(req);
    }
  } else {
    s=sendmsg(sock,&msg,MSG_NOSIGNAL);
  }
  if (send_fds) {
    for (int i = 0; i < 9; i++) {
      if (fds[i] >= 0) close(fds[i]);
    }
  }

  if (s != (ssize_t)sizeof(req)) {
    fprintf(stderr, "CLIENT_SEND_FAILED: %s\n", strerror(errno));
    close(sock);
    return 4;
  }
  if (!strcmp(action,"status-trailing") || !strcmp(action,"begin-trailing") ||
      !strcmp(action,"status-delayed-tail")) {
    if (!strcmp(action,"status-delayed-tail")) {
      const struct timespec pause={.tv_sec=0,.tv_nsec=45000000};
      nanosleep(&pause,NULL);
    }
    const char extra[]="EXTRA_FRAME_BYTES";
    if (send(sock,extra,sizeof(extra),MSG_NOSIGNAL)!=(ssize_t)sizeof(extra)) {
      close(sock);
      return 4;
    }
  }
  const bool keep_writable = !strcmp(action,"status-no-fin") ||
                             !strcmp(action,"begin-no-fin");
  if (!keep_writable && shutdown(sock,SHUT_WR)!=0) {
    close(sock);
    return 4;
  }
  if (!strcmp(action,"status-disconnect") || !strcmp(action,"begin-disconnect")) {
    /* For the SIGPIPE regression, closing the read half before the server
     * replies must not crash the owner daemon or release its ledger flock. */
    shutdown(sock,SHUT_RD);
    close(sock);
    puts("V21_TEST_PEER_DISCONNECTED");
    return 0;
  }

  /* Receive response */
  virki_owner_response_frame_t resp;
  memset(&resp, 0, sizeof(resp));
  struct timeval deadline={.tv_sec=4,.tv_usec=0};
  setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&deadline,sizeof(deadline));
  size_t received=0;
  while (received<sizeof(resp)) {
    ssize_t n=recv(sock,(unsigned char *)&resp+received,sizeof(resp)-received,0);
    if (n>0) {
      received+=(size_t)n;
    } else if (n<0 && errno==EINTR) {
      continue;
    } else break;
  }
  close(sock);

  if (received != sizeof(resp)) {
    fprintf(stderr, "CLIENT_RECV_FAILED: expected %zu bytes, got %zu\n", sizeof(resp), received);
    return 5;
  }

  printf("STATUS=%u\n", resp.status);
  printf("EPOCH=%" PRIu64 "\n", resp.epoch);
  printf("SEQ=%" PRIu64 "\n", resp.sequence_number);
  printf("SCOPE_TOKEN=%s\n", resp.scope_token);
  printf("KEY_ID=%s\n", resp.owner_key_id);
  printf("SIG_B64=%s\n", resp.signature_base64);
  printf("ACK_SHA=%s\n", resp.canonical_ack_sha256);
  if (resp.ack_json_len > 0) {
    printf("ACK_JSON=%s\n", resp.ack_json);
  }

  return 0;
}
