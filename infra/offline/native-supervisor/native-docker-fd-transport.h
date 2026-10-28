/*
 * Linux only, non-authorizing Docker HTTP transport building block.
 * The caller owns the already-connected AF_UNIX socket and supplies a daemon
 * PID from independent provenance. This library NEVER connects to a pathname,
 * starts dockerd, grants trust or calls the production Docker CLI.
 *
 * This proves socket/peer continuity and bounded protocol I/O only.
 * It does NOT prove daemon isolation, archive authenticity, owner-installed
 * binary, service ownership, policy signer, or deploy admission.
 * A failed load may already have mutated the peer daemon: use only with a
 * separately durable, irrevocable attempt latch before sending any bytes.
 * The intentionally strict response subset requires HTTP/1.1 200 and either
 * a unique Content-Length or exact Transfer-Encoding: chunked. It refuses
 * combined framing, upgrades, compression and trailers.
 * Real daemon protocol compatibility has NOT been established.
 */
#ifndef VIRKI_NATIVE_DOCKER_FD_TRANSPORT_H
#define VIRKI_NATIVE_DOCKER_FD_TRANSPORT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum vdt_command { VDT_PING, VDT_INFO, VDT_LOAD, VDT_IMAGE_INSPECT };
struct vdt_session {
  int fd;
  int borrowed_fd;
  int pidfd;
  pid_t peer_pid;
  uid_t peer_uid;
  gid_t peer_gid;
  dev_t socket_device;
  ino_t socket_inode;
  unsigned long long start_ticks;
  char mount_ns[80], net_ns[80], pid_ns[80], cgroup[512];
  bool active;
};

/* Initialize exactly once at declaration. Reattach on a live or poisoned
 * session refuses without altering the original socket/pidfd ownership.
 * Call vdt_detach before attempting to reuse after any failure. */
#define VDT_SESSION_INIT { .fd = -1, .borrowed_fd = -1, .pidfd = -1 }
/* Duplicates the caller's socket into a private CLOEXEC FD and owns only that
 * duplicate. Caller retains the borrowed FD and must leave it intact until
 * detach; closing or replacing it poisons every subsequent exchange. */
bool vdt_attach(struct vdt_session *session, int already_connected_fd,
                pid_t independently_expected_pid, uid_t expected_uid,
                gid_t expected_gid);
/* Input FD must be a verified regular open file, never an input pathname.
 * For VDT_LOAD, image_hex64 is the SHA-256 fixed independently by the
 * trusted outer verifier before attaching. Before any POST, this transport
 * creates a fully detached, SHA-256 checked, immutable sealed memfd snapshot
 * with a 64 MiB maximum and an absolute deadline before any Docker POST.
 * Source pread may block inside the kernel despite the deadline checks:
 * installed usage requires a separately supervised, interruptible staging
 * boundary before any trust or production authority can be claimed.
 * For VDT_IMAGE_INSPECT, image_hex64 is the exact image digest in the URL.
 * The response must be fully consumed; caller interprets it as untrusted.
 * A failed exchange permanently invalidates this session. */
bool vdt_exchange(struct vdt_session *session, enum vdt_command command,
                  int archive_fd, uint64_t archive_size,
                  const char *image_hex64, char *response, size_t response_cap,
                  size_t *response_size);
void vdt_detach(struct vdt_session *session);
#endif
