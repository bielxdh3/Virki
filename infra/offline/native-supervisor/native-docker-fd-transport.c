#define _GNU_SOURCE
#include "native-docker-fd-transport.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/memfd.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(SO_PEERCRED) || !defined(SYS_pidfd_open)
#error Linux SO_PEERCRED and pidfd_open are mandatory
#endif

#define VDT_TIMEOUT_MS 3000
#define VDT_MAX_LOAD_BUDGET_MS 240000
#define VDT_MAX_HEADER 8192
#define VDT_MAX_BODY (256 * 1024)
#define VDT_MAX_UPLOAD (64ULL * 1024 * 1024)
#define VDT_MAX_DETACHED_UPLOAD (8ULL * 1024 * 1024 * 1024)
#define VDT_STAGING_BASE_MS 3000
#define VDT_STAGING_BYTES_PER_SECOND (16ULL * 1024 * 1024)
#define VDT_STAGING_MAX_MS 8000

static long long clock_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
  return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static bool ready(int fd, short events, long long deadline) {
  for (;;) {
    long long now = clock_ms();
    if (now < 0 || now >= deadline) return false;
    struct pollfd item = {.fd = fd, .events = events};
    long long remain = deadline - now;
    int rc = poll(&item, 1, remain > INT_MAX ? INT_MAX : (int)remain);
    if (rc < 0 && errno == EINTR) continue;
    return rc == 1 && (item.revents & events) &&
      !(item.revents & (POLLERR | POLLNVAL | POLLHUP));
  }
}
static bool pidfd_alive(int fd) {
  struct pollfd item = {.fd = fd, .events = POLLIN};
  return fd >= 0 && poll(&item, 1, 0) == 0;
}
static bool start_ticks(pid_t pid, unsigned long long *out) {
  char filename[64], value[8192];
  if (snprintf(filename, sizeof filename, "/proc/%ld/stat", (long)pid) >=
      (int)sizeof filename) return false;
  int fd = open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return false;
  ssize_t n = read(fd, value, sizeof value - 1);
  close(fd);
  if (n < 1 || n >= (ssize_t)sizeof value - 1) return false;
  value[n] = 0;
  char *end = strrchr(value, ')');
  if (!end || end[1] != ' ') return false;
  char *save = NULL, *field = strtok_r(end + 2, " \n", &save);
  for (int i = 0; i < 19 && field; i++)
    field = strtok_r(NULL, " \n", &save);
  if (!field) return false;
  errno = 0;
  char *tail = NULL;
  unsigned long long ticks = strtoull(field, &tail, 10);
  if (errno || tail == field || *tail || ticks == 0) return false;
  *out = ticks;
  return true;
}
static bool proc_link(pid_t pid, const char *kind, char *out, size_t cap) {
  char filename[64];
  if (snprintf(filename, sizeof filename, "/proc/%ld/ns/%s", (long)pid, kind) >=
      (int)sizeof filename) return false;
  ssize_t n = readlink(filename, out, cap - 1);
  if (n <= 0 || (size_t)n >= cap - 1) return false;
  out[n] = 0;
  return true;
}
static bool proc_cgroup(pid_t pid, char *out, size_t cap) {
  char filename[64];
  if (snprintf(filename, sizeof filename, "/proc/%ld/cgroup", (long)pid) >=
      (int)sizeof filename) return false;
  int fd = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  ssize_t n = read(fd, out, cap - 1);
  close(fd);
  if (n < 1 || (size_t)n >= cap - 1) return false;
  out[n] = 0;
  return true;
}
static bool same_peer(struct vdt_session *s) {
  struct ucred peer = {0};
  struct stat socket_state, borrowed_state;
  socklen_t length = sizeof peer;
  unsigned long long ticks = 0;
  char mount[80], net[80], pid[80], cgroup[512];
  return s->active && s->fd >= 0 && pidfd_alive(s->pidfd) &&
    fstat(s->fd, &socket_state) == 0 && S_ISSOCK(socket_state.st_mode) &&
    socket_state.st_dev == s->socket_device &&
    socket_state.st_ino == s->socket_inode &&
    fstat(s->borrowed_fd, &borrowed_state) == 0 &&
    S_ISSOCK(borrowed_state.st_mode) &&
    borrowed_state.st_dev == s->socket_device &&
    borrowed_state.st_ino == s->socket_inode &&
    getsockopt(s->fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) == 0 &&
    length == sizeof peer && peer.pid == s->peer_pid &&
    peer.uid == s->peer_uid && peer.gid == s->peer_gid &&
    start_ticks(peer.pid, &ticks) && ticks == s->start_ticks &&
    proc_link(peer.pid, "mnt", mount, sizeof mount) &&
    proc_link(peer.pid, "net", net, sizeof net) &&
    proc_link(peer.pid, "pid", pid, sizeof pid) &&
    proc_cgroup(peer.pid, cgroup, sizeof cgroup) &&
    strcmp(mount, s->mount_ns) == 0 &&
    strcmp(net, s->net_ns) == 0 &&
    strcmp(pid, s->pid_ns) == 0 &&
    strcmp(cgroup, s->cgroup) == 0;
}
void vdt_detach(struct vdt_session *s) {
  if (!s) return;
  if (s->pidfd >= 0) close(s->pidfd);
  if (s->fd >= 0) close(s->fd);
  memset(s, 0, sizeof *s);
  s->fd = -1;
  s->borrowed_fd = -1;
  s->pidfd = -1;
}
bool vdt_attach(struct vdt_session *s, int fd, pid_t pid,
                uid_t expected_uid, gid_t expected_gid) {
  /* VDT_SESSION_INIT is mandatory before first use. Reject active and
   * poisoned sessions without touching their tracked descriptors. */
  if (!s || s->active || s->fd != -1 || s->pidfd != -1 ||
      s->borrowed_fd != -1) return false;
  if (fd < 0 || pid <= 1) return false;
  struct sockaddr_un peer_address = {0};
  socklen_t address_len = sizeof peer_address;
  int type = 0, yes = 1;
  socklen_t type_len = sizeof type;
  struct ucred peer = {0};
  struct stat socket_state;
  socklen_t peer_len = sizeof peer;
  if (fstat(fd, &socket_state) || !S_ISSOCK(socket_state.st_mode) ||
      getpeername(fd, (struct sockaddr *)&peer_address, &address_len) ||
      peer_address.sun_family != AF_UNIX ||
      getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len) ||
      type_len != sizeof type || type != SOCK_STREAM ||
      setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &yes, sizeof yes) ||
      getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) ||
      peer_len != sizeof peer || peer.pid != pid ||
      peer.uid != expected_uid || peer.gid != expected_gid) return false;
  s->fd = fcntl(fd, F_DUPFD_CLOEXEC, 64);
  if (s->fd < 0) return false;
  s->borrowed_fd = fd;
  s->pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
  if (s->pidfd < 0) { vdt_detach(s); return false; }
  s->peer_pid = pid;
  s->peer_uid = peer.uid;
  s->peer_gid = peer.gid;
  s->socket_device = socket_state.st_dev;
  s->socket_inode = socket_state.st_ino;
  s->active = start_ticks(pid, &s->start_ticks) &&
    proc_link(pid, "mnt", s->mount_ns, sizeof s->mount_ns) &&
    proc_link(pid, "net", s->net_ns, sizeof s->net_ns) &&
    proc_link(pid, "pid", s->pid_ns, sizeof s->pid_ns) &&
    proc_cgroup(pid, s->cgroup, sizeof s->cgroup);
  if (!same_peer(s)) { vdt_detach(s); return false; }
  return true;
}
static bool transmit(int fd, const void *value, size_t size,
                     long long deadline) {
  const char *bytes = value;
  for (size_t offset = 0; offset < size;) {
    if (!ready(fd, POLLOUT, deadline)) return false;
    ssize_t n = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
    if (n <= 0) return false;
    offset += (size_t)n;
  }
  return true;
}
/* Every read authenticates the actual Linux sender rather than only the
 * connect-time SO_PEERCRED. recv() would silently admit inherited FD writers. */
static ssize_t trusted_read(struct vdt_session *s, void *bytes, size_t size,
                            long long deadline) {
  while (ready(s->fd, POLLIN, deadline)) {
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct ucred))]; }
      control = {0};
    struct iovec iov = {.iov_base = bytes, .iov_len = size};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
      .msg_control = control.bytes, .msg_controllen = sizeof control.bytes};
    ssize_t n = recvmsg(s->fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
    if (n <= 0 || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC))) return -1;
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_CREDENTIALS ||
        header->cmsg_len != CMSG_LEN(sizeof(struct ucred)) ||
        CMSG_NXTHDR(&message, header)) return -1;
    struct ucred sender;
    memcpy(&sender, CMSG_DATA(header), sizeof sender);
    if (sender.pid != s->peer_pid || sender.uid != s->peer_uid ||
        sender.gid != s->peer_gid || !same_peer(s)) return -1;
    return n;
  }
  return -1;
}
static bool trusted_exact(struct vdt_session *s, char *bytes, size_t size,
                          long long deadline) {
  for (size_t used = 0; used < size;) {
    ssize_t got = trusted_read(s, bytes + used, size - used, deadline);
    if (got <= 0) return false;
    used += (size_t)got;
  }
  return true;
}
static bool response_headers(struct vdt_session *s, size_t *body_size,
                             bool *chunked, long long deadline) {
  char headers[VDT_MAX_HEADER + 1];
  size_t n = 0;
  while (n < VDT_MAX_HEADER) {
    if (trusted_read(s, headers + n, 1, deadline) != 1) return false;
    n++;
    if (n >= 4 && memcmp(headers + n - 4, "\r\n\r\n", 4) == 0) break;
  }
  if (n < 4 || n >= VDT_MAX_HEADER) return false;
  headers[n] = 0;
  const char *start = "HTTP/1.1 200 OK\r\n";
  if (strncmp(headers, start, strlen(start)) != 0) return false;
  bool saw_length = false, keep_alive = false, saw_type = false;
  bool saw_transfer = false;
  size_t declared = 0;
  char *line = headers + strlen(start);
  size_t count = 0;
  while (line[0] != '\r' || line[1] != '\n') {
    if (++count > 32) return false;
    char *end = strstr(line, "\r\n");
    if (!end) return false;
    *end = 0;
    if (strncmp(line, "Content-Length: ", 16) == 0) {
      if (saw_length) return false;
      saw_length = true;
      const char *digits = line + 16;
      if (!*digits) return false;
      for (; *digits; digits++) {
        if (*digits < '0' || *digits > '9') return false;
        if (declared > (VDT_MAX_BODY - (size_t)(*digits - '0')) / 10) return false;
        declared = declared * 10 + (size_t)(*digits - '0');
      }
    } else if (strcasecmp(line, "Connection: keep-alive") == 0) {
      if (keep_alive) return false;
      keep_alive = true;
    } else if (strcasecmp(line, "Transfer-Encoding: chunked") == 0) {
      if (saw_transfer) return false;
      saw_transfer = true;
    } else if (strncasecmp(line, "Content-Type: ", 14) == 0) {
      if (saw_type) return false;
      saw_type = true;
      const char *value = line + 14;
      if (strcmp(value, "application/json") &&
          strcmp(value, "text/plain; charset=utf-8") &&
          strcmp(value, "application/x-ndjson")) return false;
    } else {
      /* Avoid TE/CL request smuggling, upgrade, trailers, duplicate headers,
       * unsupported transfer encodings and side channels. Extend only after
       * inspecting actual pinned-daemon responses in an isolated Linux lab. */
      return false;
    }
    line = end + 2;
  }
  if (!keep_alive || saw_length == saw_transfer ||
      (saw_length && declared == 0)) return false;
  *chunked = saw_transfer;
  *body_size = declared;
  return true;
}
static bool receive_chunked(struct vdt_session *s, char *out,
                            size_t capacity, size_t *length,
                            long long deadline) {
  size_t used = 0;
  for (;;) {
    char line[20] = {0};
    size_t n = 0;
    for (;;) {
      if (n >= sizeof line - 1 ||
          trusted_read(s, line + n, 1, deadline) != 1) return false;
      if (line[n++] == '\n') break;
    }
    if (n < 3 || line[n - 2] != '\r') return false;
    line[n - 2] = 0;
    size_t chunk = 0;
    for (size_t i = 0; line[i]; i++) {
      char c = line[i];
      int digit = c >= '0' && c <= '9' ? c - '0' :
        c >= 'a' && c <= 'f' ? c - 'a' + 10 :
        c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
      if (digit < 0 || chunk > (VDT_MAX_BODY - (size_t)digit) / 16)
        return false;
      chunk = 16 * chunk + (size_t)digit;
    }
    if (chunk == 0) {
      char end[2];
      if (!trusted_exact(s, end, 2, deadline) ||
          memcmp(end, "\r\n", 2) != 0 || used == 0) return false;
      out[used] = 0;
      *length = used;
      return true;
    }
    if (chunk > VDT_MAX_BODY - used || chunk >= capacity - used)
      return false;
    for (size_t offset = 0; offset < chunk;) {
      ssize_t got = trusted_read(s, out + used + offset,
                                  chunk - offset, deadline);
      if (got <= 0) return false;
      offset += (size_t)got;
    }
    used += chunk;
    char delimiter[2];
    if (!trusted_exact(s, delimiter, 2, deadline) ||
        memcmp(delimiter, "\r\n", 2) != 0) return false;
  }
}
static bool no_pending_bytes(int fd) {
  char extra;
  ssize_t got = recv(fd, &extra, 1, MSG_PEEK | MSG_DONTWAIT);
  return got < 0 && (errno == EWOULDBLOCK || errno == EAGAIN);
}
static bool file_unchanged(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
    a->st_size == b->st_size &&
    a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
    a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
    a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
    a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
    a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
    a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool hex64(const char *value) {
  if (!value || strnlen(value, 65) != 64) return false;
  for (size_t i = 0; i < 64; i++)
    if (!((value[i] >= '0' && value[i] <= '9') ||
          (value[i] >= 'a' && value[i] <= 'f'))) return false;
  return true;
}
#ifdef VDT_DISPOSABLE_TEST_SOURCE_FAULT
/* Compiled exclusively by the explicit disposable fixture test. Production
 * builds use the ordinary libc pread directly, without test-only hooks. */
extern ssize_t vdt_disposable_test_pread(int fd, void *, size_t, off_t);
extern ssize_t vdt_disposable_test_pwrite(int fd, const void *, size_t, off_t);
#define VDT_SOURCE_PREAD vdt_disposable_test_pread
#define VDT_SOURCE_PWRITE vdt_disposable_test_pwrite
#else
#define VDT_SOURCE_PREAD pread
#define VDT_SOURCE_PWRITE pwrite
#endif
static bool before_deadline(long long deadline) {
  long long current = clock_ms();
  return current >= 0 && current < deadline;
}
static long long stage_deadline(uint64_t length) {
  if (length == 0 || length > VDT_MAX_UPLOAD) return -1;
  long long now = clock_ms();
  if (now < 0) return -1;
  long long budget = VDT_STAGING_BASE_MS +
    (long long)((length + VDT_STAGING_BYTES_PER_SECOND - 1) /
      VDT_STAGING_BYTES_PER_SECOND) * 1000;
  if (budget > VDT_STAGING_MAX_MS) budget = VDT_STAGING_MAX_MS;
  return now + budget;
}
/* Large sealed-memory snapshot staging uses a separate deadline.
 * 16MiB/s minimum budget + 10s grace, capped at
 * 10 minutes. This is an absolute time bound, not guaranteed interruptibility
 * for a kernel pread; a killable native supervisor remains compulsory. */
static long long detached_stage_deadline(uint64_t length) {
  if (!length || length > VDT_MAX_DETACHED_UPLOAD) return -1;
  long long now = clock_ms();
  if (now < 0) return -1;
  long long seconds = 10 + (long long)((length + VDT_STAGING_BYTES_PER_SECOND - 1) /
    VDT_STAGING_BYTES_PER_SECOND);
  if (seconds > 600) seconds = 600;
  return now + seconds * 1000;
}
/* Admission is deliberately memory conservative, not a memory reservation:
 * reject whenever actual kernel MemAvailable or cgroup v2 available headroom
 * cannot accommodate the next full sealed snapshot PLUS 50% and 512MiB
 * operating reserve. The host supervisor must still handle concurrent OOM.
 * Caller never sends a POST until the complete snapshot is sealed+rehash-pinned.
 * Missing/unreadable cgroup controls fail closed (no optimism from /proc). */
static bool read_memory_value(const char *filename, uint64_t *value,
                              bool *unlimited) {
  int fd = open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return false;
  char contents[64] = {0};
  ssize_t n = read(fd, contents, sizeof contents - 1);
  close(fd);
  if (n <= 0 || n >= (ssize_t)sizeof contents - 1) return false;
  contents[n] = 0;
  if (!strcmp(contents, "max\n") || !strcmp(contents, "max")) {
    if (!unlimited) return false;
    *unlimited = true;
    return true;
  }
  errno = 0;
  char *end = NULL;
  unsigned long long number = strtoull(contents, &end, 10);
  if (errno || end == contents || (*end && strcmp(end, "\n"))) return false;
  *value = (uint64_t)number;
  if (unlimited) *unlimited = false;
  return true;
}
static bool large_snapshot_memory_budget(uint64_t length) {
#if defined(VIRKI_DISPOSABLE_MANUAL_BATCH) && defined(VIRKI_DISPOSABLE_DENY_LARGE_MEMORY)
  (void)length;
  return false; /* Disposable-only TDD: force fail-closed before any POST. */
#endif
  if (length <= VDT_MAX_UPLOAD || length > VDT_MAX_DETACHED_UPLOAD) return
    length <= VDT_MAX_UPLOAD;
  uint64_t required = length + length / 2 + (512ULL << 20);
  FILE *mem = fopen("/proc/meminfo", "r");
  if (!mem) return false;
  char line[256] = {0};
  unsigned long long kib = 0;
  bool found = false;
  while (fgets(line, sizeof line, mem)) {
    if (sscanf(line, "MemAvailable: %llu kB", &kib) == 1) {
      found = true; break;
    }
  }
  fclose(mem);
  if (!found || kib > UINT64_MAX / 1024 ||
      kib * 1024ULL < required) return false;
  /* cgroup v2 unified hierarchy; walk ancestor limits, not just leaf. */
  FILE *cg = fopen("/proc/self/cgroup", "r");
  if (!cg) return false;
  char group[512] = {0};
  found = false;
  while (fgets(line, sizeof line, cg)) {
    if (!strncmp(line, "0::/", 4)) {
      size_t size = strcspn(line + 3, "\n");
      if (size >= sizeof group) break;
      memcpy(group, line + 3, size);
      group[size] = 0;
      found = true; break;
    }
  }
  fclose(cg);
  if (!found || group[0] != '/' || strstr(group, "..") ||
      strpbrk(group, "\\ 	")) return false;
  char directory[768];
  if (snprintf(directory, sizeof directory, "/sys/fs/cgroup%s", group) >=
      (int)sizeof directory) return false;
  bool checked = false;
  for (;;) {
    char maximum[896], usage[896];
    if (snprintf(maximum, sizeof maximum, "%s/memory.max", directory) >=
        (int)sizeof maximum ||
        snprintf(usage, sizeof usage, "%s/memory.current", directory) >=
        (int)sizeof usage) return false;
    uint64_t max = 0, current = 0;
    bool unlimited = false;
    if (access(maximum, F_OK) == 0) {
      if (!read_memory_value(maximum, &max, &unlimited) ||
          !read_memory_value(usage, &current, NULL) ||
          (!unlimited && (max < current || max - current < required)))
        return false;
      checked = true;
    } else if (strcmp(directory, "/sys/fs/cgroup")) return false;
    if (!strcmp(directory, "/sys/fs/cgroup")) break;
    char *slash = strrchr(directory, '/');
    if (!slash || slash <= directory + strlen("/sys/fs/cgroup")) {
      strcpy(directory, "/sys/fs/cgroup");
    } else *slash = 0;
  }
  return checked;
}
/* Snapshot is complete, independently SHA-pinned, and sealed BEFORE any
 * Docker HTTP mutation request is transmitted. Original archive FD changes
 * afterwards cannot influence the bytes emitted by this session. */
static bool verify_sealed_digest(int fd, uint64_t length,
                                 const char *expected_hex, long long deadline) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  bool good = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
  char block[65536];
  for (uint64_t at = 0; good && at < length;) {
    if (!before_deadline(deadline)) { good = false; break; }
    size_t amount = length - at > sizeof block ?
      sizeof block : (size_t)(length - at);
    ssize_t got = pread(fd, block, amount, (off_t)at);
    if (got <= 0 || !before_deadline(deadline) ||
        EVP_DigestUpdate(ctx, block, (size_t)got) != 1) {
      good = false; break;
    }
    at += (uint64_t)got;
  }
  unsigned char digest[EVP_MAX_MD_SIZE] = {0};
  unsigned digest_length = 0;
  if (good) good = EVP_DigestFinal_ex(ctx, digest, &digest_length) == 1 &&
    digest_length == 32 && before_deadline(deadline);
  if (ctx) EVP_MD_CTX_free(ctx);
  char actual[65] = {0};
  static const char hex[] = "0123456789abcdef";
  if (good) for (size_t i = 0; i < 32; i++) {
    actual[2 * i] = hex[digest[i] >> 4];
    actual[2 * i + 1] = hex[digest[i] & 15];
  }
  return good && !strcmp(actual, expected_hex);
}
static int make_verified_snapshot(int source, uint64_t length,
                                  const char *expected_hex,
                                  long long deadline, bool large) {
  if (!hex64(expected_hex) || length == 0 ||
      length > (large ? VDT_MAX_DETACHED_UPLOAD : VDT_MAX_UPLOAD) ||
      (large && !large_snapshot_memory_budget(length)) ||
      !before_deadline(deadline))
    return -1;
  struct stat before, after, copy_state;
  if (fstat(source, &before) || !before_deadline(deadline) ||
      !S_ISREG(before.st_mode) ||
      before.st_nlink != (large ? 0U : 1U) ||
      (large && (before.st_uid != geteuid() ||
                 (before.st_mode & 07777) != 0600 ||
                 (fcntl(source, F_GETFL) & O_ACCMODE) != O_RDONLY)) ||
      before.st_size < 0 ||
      (uint64_t)before.st_size != length) return -1;
  int sealed = memfd_create("virki-untrusted-archive-snapshot",
                            MFD_ALLOW_SEALING | MFD_CLOEXEC);
  if (sealed < 0) return -1;
  EVP_MD_CTX *hash = EVP_MD_CTX_new();
  bool good = hash && before_deadline(deadline) &&
    EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1;
  char bytes[16384];
  for (uint64_t pos = 0; good && pos < length;) {
    if (!before_deadline(deadline)) { good = false; break; }
    size_t amount = length - pos > sizeof bytes ?
      sizeof bytes : (size_t)(length - pos);
    ssize_t read_bytes = VDT_SOURCE_PREAD(source, bytes, amount, (off_t)pos);
    /* No late bytes may reach the daemon even if a kernel source read
     * eventually completes after its absolute staging deadline. */
    if (!before_deadline(deadline)) { good = false; break; }
    if (read_bytes <= 0) { good = false; break; }
    if (EVP_DigestUpdate(hash, bytes, (size_t)read_bytes) != 1) {
      good = false; break;
    }
    if (!before_deadline(deadline)) { good = false; break; }
    for (ssize_t offset = 0; offset < read_bytes;) {
      if (!before_deadline(deadline)) { good = false; break; }
      ssize_t written = VDT_SOURCE_PWRITE(sealed, bytes + offset,
        (size_t)(read_bytes - offset), (off_t)(pos + (uint64_t)offset));
      if (!before_deadline(deadline)) { good = false; break; }
      if (written < 0 && errno == EINTR) continue;
      if (written <= 0) { good = false; break; }
      offset += written;
    }
    pos += (uint64_t)read_bytes;
  }
  unsigned char digest[EVP_MAX_MD_SIZE] = {0};
  unsigned int digest_length = 0;
  if (good) good = before_deadline(deadline) &&
    EVP_DigestFinal_ex(hash, digest, &digest_length) == 1 &&
    digest_length == 32 && before_deadline(deadline);
  if (hash) EVP_MD_CTX_free(hash);
  char actual[65] = {0};
  static const char hex[] = "0123456789abcdef";
  if (good) for (size_t i = 0; i < 32; i++) {
    actual[2 * i] = hex[digest[i] >> 4];
    actual[2 * i + 1] = hex[digest[i] & 15];
  }
  const int seals = F_SEAL_WRITE | F_SEAL_SHRINK |
    F_SEAL_GROW | F_SEAL_SEAL;
  if (!good || !before_deadline(deadline) ||
      strcmp(actual, expected_hex) ||
      fstat(source, &after) || !file_unchanged(&before, &after) ||
      !before_deadline(deadline) ||
      fsync(sealed) ||
      !before_deadline(deadline) ||
      fcntl(sealed, F_ADD_SEALS, seals) != 0 ||
      !before_deadline(deadline) ||
      fcntl(sealed, F_GET_SEALS) != seals ||
      fstat(sealed, &copy_state) || !S_ISREG(copy_state.st_mode) ||
      (uint64_t)copy_state.st_size != length ||
      !before_deadline(deadline) ||
      !verify_sealed_digest(sealed, length, expected_hex, deadline)) {
    close(sealed);
    return -1;
  }
  return sealed;
}

/* Consume an RFC 3629 UTF-8 scalar in JSON string payloads. In particular,
 * reject forbidden lead octets, overlong forms, surrogate code points and
 * values greater than U+10FFFF; these bytes are otherwise invisible to the
 * narrow JSON field-name parser. `at` advances only within the bounded line. */
static bool load_escape_hex16(const char *bytes, size_t end, size_t *at,
                               unsigned *value) {
  if (!bytes || !at || !value || *at > end || end - *at < 4) return false;
  unsigned parsed = 0;
  for (unsigned n = 0; n < 4; n++) {
    const unsigned char digit = (unsigned char)bytes[(*at)++];
    unsigned nibble;
    if (digit >= '0' && digit <= '9') nibble = digit - '0';
    else if (digit >= 'a' && digit <= 'f') nibble = digit - 'a' + 10;
    else if (digit >= 'A' && digit <= 'F') nibble = digit - 'A' + 10;
    else return false;
    parsed = (parsed << 4) | nibble;
  }
  *value = parsed;
  return true;
}

static bool load_utf8_scalar(const char *bytes, size_t end, size_t *at,
                             unsigned char lead) {
  unsigned count = 0;
  unsigned char first_low = 0x80, first_high = 0xbf;
  if (lead >= 0xc2 && lead <= 0xdf) count = 1;
  else if (lead == 0xe0) { count = 2; first_low = 0xa0; }
  else if (lead >= 0xe1 && lead <= 0xec) count = 2;
  else if (lead == 0xed) { count = 2; first_high = 0x9f; }
  else if (lead >= 0xee && lead <= 0xef) count = 2;
  else if (lead == 0xf0) { count = 3; first_low = 0x90; }
  else if (lead >= 0xf1 && lead <= 0xf3) count = 3;
  else if (lead == 0xf4) { count = 3; first_high = 0x8f; }
  else return false;
  if (end - *at < count) return false;
  for (unsigned n = 0; n < count; n++) {
    unsigned char continuation = (unsigned char)bytes[(*at)++];
    if (continuation < (n == 0 ? first_low : 0x80) ||
        continuation > (n == 0 ? first_high : 0xbf)) return false;
  }
  return true;
}

/* Docker may return HTTP 200 yet report image-load failures in its NDJSON
 * body. Accept only the narrow, observed {"stream":"..."} subset for the
 * disposable transport. Any extra field (especially error/errorDetail),
 * malformed JSON, incomplete final line, or oversized line fails closed.
 * This is a receipt grammar check, never proof of image identity or admission;
 * the caller must independently check the loaded image before considering
 * any later action. Other daemon response formats remain UNVERIFIED. */
static bool load_stream_receipt(const char *bytes, size_t size) {
  if (!bytes || size == 0 || size > VDT_MAX_BODY) return false;
  size_t pos = 0, lines = 0;
  while (pos < size) {
    if (++lines > 512) return false;
    size_t start = pos;
    while (pos < size && bytes[pos] != '\n') {
      if (pos - start >= 16384) return false;
      pos++;
    }
    if (pos == size) return false; /* NDJSON records require LF terminators. */
    size_t end = pos++;
    if (end > start && bytes[end - 1] == '\r') end--;
    size_t at = start;
#define SKIP_JSON_SPACE() while (at < end && (bytes[at] == ' ' || bytes[at] == '\t')) at++
    SKIP_JSON_SPACE();
    if (at >= end || bytes[at++] != '{') return false;
    SKIP_JSON_SPACE();
    static const char field[] = "\"stream\"";
    if (end - at < sizeof field - 1 ||
        memcmp(bytes + at, field, sizeof field - 1) != 0) return false;
    at += sizeof field - 1;
    SKIP_JSON_SPACE();
    if (at >= end || bytes[at++] != ':') return false;
    SKIP_JSON_SPACE();
    if (at >= end || bytes[at++] != '"') return false;
    bool has_content = false, terminated = false;
    while (at < end) {
      unsigned char c = (unsigned char)bytes[at++];
      if (c == '"') { terminated = true; break; }
      if (c < 0x20) return false;
      if (c >= 0x80 && !load_utf8_scalar(bytes, end, &at, c)) return false;
      has_content = true;
      if (c == '\\') {
        if (at >= end) return false;
        char escaped = bytes[at++];
        if (escaped == 'u') {
          unsigned unicode;
          if (!load_escape_hex16(bytes, end, &at, &unicode)) return false;
          if (unicode >= 0xdc00 && unicode <= 0xdfff) return false;
          if (unicode >= 0xd800 && unicode <= 0xdbff) {
            /* RFC 8259's ABNF tolerates lone UTF-16 surrogates although
             * they cannot form a Unicode scalar and consumers disagree on
             * interpretation. Require immediately adjacent low surrogate. */
            if (end - at < 6 || bytes[at] != '\\' || bytes[at + 1] != 'u')
              return false;
            at += 2;
            unsigned low;
            if (!load_escape_hex16(bytes, end, &at, &low) ||
                low < 0xdc00 || low > 0xdfff) return false;
          }
        } else if (!(escaped == '"' || escaped == '\\' ||
                     escaped == '/' || escaped == 'b' || escaped == 'f' ||
                     escaped == 'n' || escaped == 'r' || escaped == 't'))
          return false;
      }
    }
    if (!terminated || !has_content) return false;
    SKIP_JSON_SPACE();
    if (at >= end || bytes[at++] != '}') return false;
    SKIP_JSON_SPACE();
    if (at != end) return false;
#undef SKIP_JSON_SPACE
  }
  return lines > 0;
}

static bool exchange(struct vdt_session *s, enum vdt_command command,
                     int archive_fd, uint64_t archive_size,
                     const char *image, char *response, size_t capacity,
                     size_t *response_size, bool detached) {
  if (!s || !s->active) return false;
  /* Any invalid call poisons the session until detach and fresh supervision. */
  s->active = false;
  if (response_size) *response_size = 0;
  if (response && capacity) response[0] = 0;
#ifdef VDT_DISPOSABLE_READONLY
  /* Separate DEV-only build: even a mistaken future callsite may never
   * transmit Docker POST/load or image-inspect requests. Poison on misuse. */
  if (command != VDT_PING && command != VDT_INFO) return false;
#endif
  if (!response || capacity == 0 || !response_size || !no_pending_bytes(s->fd))
    return false;
  s->active = true;
  int sealed_fd = -1;
  if (!same_peer(s)) goto fail;
  struct stat before = {0}, after = {0};
  if (command == VDT_LOAD) {
    const long long staging_expires_at = detached ?
      detached_stage_deadline(archive_size) : stage_deadline(archive_size);
    if (staging_expires_at < 0) goto fail;
    if (archive_fd < 0 || archive_size == 0 ||
        archive_size > (detached ? VDT_MAX_DETACHED_UPLOAD : VDT_MAX_UPLOAD))
      goto fail;
    if (fstat(archive_fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_size < 0 || (uint64_t)before.st_size != archive_size ||
        !before_deadline(staging_expires_at)) goto fail;
    /* Both paths send exclusively from a full, immutable F_SEAL_WRITE
     * snapshot. For large archives, require measured per-host memory
     * headroom BEFORE allocating, then seal+rehash before first POST.
     * NEVER rely on F_SETLEASE: another same-UID process can force-break it. */
    sealed_fd = make_verified_snapshot(archive_fd, archive_size, image,
                                      staging_expires_at, detached);
    if (sealed_fd < 0) goto fail;
  } else if (archive_fd != -1 || archive_size != 0) goto fail;
  char path[160];
  switch (command) {
    case VDT_PING: strcpy(path, "/_ping"); break;
    case VDT_INFO: strcpy(path, "/v1.45/info"); break;
    case VDT_LOAD: strcpy(path, "/v1.45/images/load?quiet=1"); break;
    case VDT_IMAGE_INSPECT:
      if (!hex64(image)) goto fail;
      if (snprintf(path, sizeof path, "/v1.45/images/sha256:%s/json", image) >=
          (int)sizeof path) goto fail;
      break;
    default: goto fail;
  }
  char request[384];
  int n = snprintf(request, sizeof request,
    "%s %s HTTP/1.1\r\nHost: virki-native\r\nConnection: keep-alive\r\n"
    "%sContent-Length: %llu\r\n\r\n",
    command == VDT_LOAD ? "POST" : "GET", path,
    command == VDT_LOAD ? "Content-Type: application/x-tar\r\n" : "",
    (unsigned long long)archive_size);
  if (n <= 0 || n >= (int)sizeof request) goto fail;
  long long budget = VDT_TIMEOUT_MS;
  if (command == VDT_LOAD) {
    /* Detached disk-backed path needs independently bounded real TAR upload;
     * fixed 64MiB/s assumption would terminate 1.33GiB staging too early. */
    budget = detached ? 15000 + (long long)((archive_size + (8ULL << 20) - 1) /
      (8ULL << 20)) * 1000 :
      5000 + (long long)((archive_size + (64ULL << 20) - 1) /
        (64ULL << 20)) * 1000;
    if (budget > VDT_MAX_LOAD_BUDGET_MS) budget = VDT_MAX_LOAD_BUDGET_MS;
  }
  long long deadline = clock_ms() + budget;
  if (!same_peer(s) || !transmit(s->fd, request, (size_t)n, deadline)) goto fail;
  if (command == VDT_LOAD) {
    char block[16384];
    for (uint64_t offset = 0; offset < archive_size;) {
      if ((offset % (1024 * 1024) == 0) && !same_peer(s)) goto fail;
      size_t size = archive_size - offset > sizeof block ?
        sizeof block : (size_t)(archive_size - offset);
      ssize_t got = pread(sealed_fd, block, size, (off_t)offset);
      if (got <= 0 || !transmit(s->fd, block, (size_t)got, deadline)) goto fail;
      offset += (uint64_t)got;
    }
    if (fstat(sealed_fd, &after) || !S_ISREG(after.st_mode) ||
        (uint64_t)after.st_size != archive_size ||
        fcntl(sealed_fd, F_GET_SEALS) !=
          (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL))
      goto fail;
  }
  size_t body = 0;
  bool chunked = false;
  if (!response_headers(s, &body, &chunked, deadline)) goto fail;
  if (chunked) {
    if (!receive_chunked(s, response, capacity, &body, deadline)) goto fail;
  } else {
    if (body >= capacity) goto fail;
    for (size_t offset = 0; offset < body;) {
      ssize_t got = trusted_read(s, response + offset, body - offset, deadline);
      if (got <= 0) goto fail;
      offset += (size_t)got;
    }
    response[body] = 0;
  }
  if (command == VDT_LOAD && !load_stream_receipt(response, body)) goto fail;
  *response_size = body;
  if (!no_pending_bytes(s->fd) || !same_peer(s)) goto fail;
  if (sealed_fd >= 0) close(sealed_fd);
  return true;
fail:
  if (sealed_fd >= 0) close(sealed_fd);
  if (response && capacity) response[0] = 0;
  if (response_size) *response_size = 0;
  s->active = false;
  return false;
}

bool vdt_exchange(struct vdt_session *s, enum vdt_command command,
                  int archive_fd, uint64_t archive_size,
                  const char *image, char *response, size_t capacity,
                  size_t *response_size) {
  return exchange(s, command, archive_fd, archive_size,
                  image, response, capacity, response_size, false);
}

bool vdt_exchange_detached(struct vdt_session *s, int archive_fd,
                           uint64_t archive_size, const char *archive_sha256,
                           char *response, size_t response_cap,
                           size_t *response_size) {
  return exchange(s, VDT_LOAD, archive_fd, archive_size, archive_sha256,
                  response, response_cap, response_size, true);
}
