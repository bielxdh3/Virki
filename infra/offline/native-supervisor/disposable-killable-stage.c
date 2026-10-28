/*
 * DEV-ONLY Linux staging experiment. Runs only inside a disposable root
 * container with a pre-existing finite kernel cgroup-v2 memory/pids budget,
 * private tmpfs and no service/daemon/production import capabilities.
 * No host Docker socket, network, SQL or production APIs are accessed.
 * A killable, dedicated process performs all untrusted archive I/O.
 *
 * IMPORTANT: A kernel task in TASK_UNINTERRUPTIBLE (D state) might remain
 * unreapable even after pidfd SIGKILL. We NEVER report success in that case:
 * an exclusive, fsynced attempt journal remains for manual reconciliation.
 * This is NOT a hard real-time or production-authorizing supervisor.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/memfd.h>
#include <linux/magic.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(SYS_pidfd_open) || !defined(SYS_pidfd_send_signal)
#error Native Linux pidfd support is mandatory
#endif
#define MAX_ARCHIVE (64ULL * 1024 * 1024)
#define MAX_CGROUP_MEMORY (256ULL * 1024 * 1024)
#define MAX_CGROUP_PIDS 64
#define WATCHDOG_MS 1500
#define KILL_REAP_MS 500
#define FILEMODE 0600
#define DIRMODO 0700

static const char *const blocked =
  "{\"status\":\"BLOCKED_DEV_ONLY\",\"deployAuthorized\":false,"
  "\"dockerLoadAuthorized\":false,\"transferAuthorized\":false}";
static const char *const staged =
  "{\"status\":\"STAGED_DEV_ONLY\",\"deployAuthorized\":false,"
  "\"dockerLoadAuthorized\":false,\"transferAuthorized\":false,"
  "\"reaped\":true}";

static bool hex64(const char *s) {
  if (!s || strnlen(s, 65) != 64) return false;
  for (int i = 0; i < 64; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
      return false;
  return true;
}
static bool regular_owned(int fd, off_t min, off_t max) {
  struct stat st;
  return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
    st.st_uid == getuid() && st.st_gid == getgid() &&
    (st.st_mode & 07777) == FILEMODE && st.st_nlink == 1 &&
    st.st_size >= min && st.st_size <= max;
}
static bool directory_owned(const char *name) {
  struct stat st;
  return lstat(name, &st) == 0 && S_ISDIR(st.st_mode) &&
    st.st_uid == getuid() && st.st_gid == getgid() &&
    (st.st_mode & 07777) == DIRMODO;
}
static bool directory_fd_owned(int fd) {
  struct stat st;
  return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
    st.st_uid == 0 && st.st_gid == 0 && (st.st_mode & 07777) == DIRMODO;
}
static bool same_dir_entry(int parent, const char *name, int opened) {
  struct stat actual, held;
  return fstat(opened, &held) == 0 &&
    fstatat(parent, name, &actual, AT_SYMLINK_NOFOLLOW) == 0 &&
    S_ISDIR(actual.st_mode) && actual.st_dev == held.st_dev &&
    actual.st_ino == held.st_ino && actual.st_uid == held.st_uid &&
    actual.st_gid == held.st_gid && actual.st_mode == held.st_mode &&
    actual.st_nlink == held.st_nlink && directory_fd_owned(opened);
}
static bool write_all(int fd, const void *buffer, size_t len) {
  const unsigned char *at = buffer;
  while (len) {
    ssize_t n = write(fd, at, len);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    at += n;
    len -= (size_t)n;
  }
  return true;
}
static bool read_cgroup_limit(const char *file, uint64_t *out) {
  int fd = open(file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return false;
  char buffer[64] = {0};
  struct stat st;
  ssize_t n = read(fd, buffer, sizeof buffer - 1);
  bool ok = fstat(fd, &st) == 0 && st.st_uid == 0 &&
    n > 1 && n < (ssize_t)sizeof buffer - 1 && buffer[n - 1] == '\n';
  close(fd);
  if (!ok) return false;
  buffer[n - 1] = 0;
  if (!buffer[0] || strcmp(buffer, "max") == 0) return false;
  for (size_t i = 0; buffer[i]; i++)
    if (buffer[i] < '0' || buffer[i] > '9') return false;
  errno = 0;
  char *end = NULL;
  unsigned long long value = strtoull(buffer, &end, 10);
  if (errno || !end || *end || value == 0) return false;
  *out = (uint64_t)value;
  return true;
}
static bool isolated_gate(void) {
  if (!getenv("VIRKI_DISPOSABLE_KILLABLE_STAGE") ||
      strcmp(getenv("VIRKI_DISPOSABLE_KILLABLE_STAGE"), "1") ||
      access("/.dockerenv", F_OK) != 0 ||
      getuid() != 0 || getgid() != 0) return false;
  if (getenv("VIRKI_TEST_REQUIRE_IMPOSSIBLE_CGROUP")) return false;
  struct statfs fs;
  if (statfs("/tmp", &fs) || fs.f_type != TMPFS_MAGIC) return false;
  /* An attempt latch on tmpfs would disappear when its container exits.
   * Require a separately mounted, private, disposable ext4 volume instead;
   * fsync of the lock AND directory must survive a container restart. */
  struct statfs disk;
  struct stat rootfs, volume;
  if (statfs("/journal", &disk) || disk.f_type != EXT4_SUPER_MAGIC ||
      stat("/", &rootfs) || stat("/journal", &volume) ||
      rootfs.st_dev == volume.st_dev || !directory_owned("/journal"))
    return false;
  uint64_t memory = 0, pids = 0;
  return read_cgroup_limit("/sys/fs/cgroup/memory.max", &memory) &&
    read_cgroup_limit("/sys/fs/cgroup/pids.max", &pids) &&
    memory >= 96ULL * 1024 * 1024 && memory <= MAX_CGROUP_MEMORY &&
    pids >= 4 && pids <= MAX_CGROUP_PIDS;
}
static bool fixture_paths(const char *root, char *plan, char *archive,
                          char *state, char *lock, char *complete) {
  static const char prefix[] = "/journal/virki-killable-stage-";
  const size_t prefix_len = sizeof prefix - 1;
  if (!root || strlen(root) != prefix_len + 6 ||
      strncmp(root, prefix, prefix_len)) return false;
  for (int i = 0; i < 6; i++) {
    const char c = root[prefix_len + (size_t)i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9'))) return false;
  }
  char operator_dir[160];
  if (snprintf(operator_dir, sizeof operator_dir, "%s/operator", root) >=
      (int)sizeof operator_dir ||
      snprintf(state, 160, "%s/state", root) >= 160 ||
      snprintf(plan, 200, "%s/expected.sha256", operator_dir) >= 200 ||
      snprintf(archive, 200, "%s/archive.bin", root) >= 200 ||
      snprintf(lock, 200, "%s/attempt.lock", state) >= 200 ||
      snprintf(complete, 200, "%s/complete.json", state) >= 200 ||
      !directory_owned(root) || !directory_owned(operator_dir) ||
      !directory_owned(state)) return false;
  return true;
}
static bool read_expected_at(int dirfd, char expected[65]) {
  int fd = openat(dirfd, "expected.sha256",
    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) return false;
  char bytes[66] = {0};
  bool ok = regular_owned(fd, 65, 65) &&
    read(fd, bytes, sizeof bytes) == 65 && bytes[64] == '\n';
  close(fd);
  if (!ok) return false;
  bytes[64] = 0;
  if (!hex64(bytes)) return false;
  memcpy(expected, bytes, 65);
  return true;
}
static bool same_source(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
    a->st_size == b->st_size && a->st_uid == b->st_uid &&
    a->st_gid == b->st_gid && a->st_mode == b->st_mode &&
    a->st_nlink == b->st_nlink &&
    a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
    a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
    a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
    a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool hash_matches(const unsigned char digest[32], const char *hex) {
  static const char alphabet[] = "0123456789abcdef";
  char actual[65];
  for (size_t i = 0; i < 32; i++) {
    actual[2 * i] = alphabet[digest[i] >> 4];
    actual[2 * i + 1] = alphabet[digest[i] & 15];
  }
  actual[64] = 0;
  return strcmp(actual, hex) == 0;
}
static int sealed_snapshot(int source, const char *hex) {
  struct stat before, after, snapshot;
  if (fstat(source, &before) || !S_ISREG(before.st_mode) ||
      before.st_nlink != 1 || before.st_uid != 0 ||
      before.st_gid != 0 ||
      (before.st_mode & 07777) != FILEMODE ||
      before.st_size <= 0 || (uint64_t)before.st_size > MAX_ARCHIVE)
    return -1;
  int mem = memfd_create("virki-disposable-staging", MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (mem < 0) return -1;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
  unsigned char block[16384], hash[32];
  unsigned int hash_len = 0;
  for (off_t pos = 0; ok && pos < before.st_size;) {
    size_t want = before.st_size - pos > (off_t)sizeof block ?
      sizeof block : (size_t)(before.st_size - pos);
    ssize_t n = pread(source, block, want, pos);
    if (n <= 0 || EVP_DigestUpdate(ctx, block, (size_t)n) != 1) {
      ok = false; break;
    }
    for (ssize_t copied = 0; ok && copied < n;) {
      ssize_t w = pwrite(mem, block + copied, (size_t)(n - copied), pos + copied);
      if (w < 0 && errno == EINTR) continue;
      if (w <= 0) { ok = false; break; }
      copied += w;
    }
    pos += n;
  }
  if (ok) ok = EVP_DigestFinal_ex(ctx, hash, &hash_len) == 1 &&
    hash_len == 32 && hash_matches(hash, hex);
  if (ctx) EVP_MD_CTX_free(ctx);
  const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  if (!ok || fstat(source, &after) || !same_source(&before, &after) ||
      fsync(mem) || fcntl(mem, F_ADD_SEALS, seals) ||
      fcntl(mem, F_GET_SEALS) != seals ||
      fstat(mem, &snapshot) || snapshot.st_size != before.st_size) {
    close(mem); return -1;
  }
  return mem;
}
static bool send_fd(int socket, int fd) {
  char value = 'S';
  struct iovec io = {.iov_base = &value, .iov_len = 1};
  union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } ctrl = {0};
  struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1,
    .msg_control = ctrl.bytes, .msg_controllen = sizeof ctrl.bytes};
  struct cmsghdr *h = CMSG_FIRSTHDR(&msg);
  if (!h) return false;
  h->cmsg_level = SOL_SOCKET;
  h->cmsg_type = SCM_RIGHTS;
  h->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(h), &fd, sizeof fd);
  return sendmsg(socket, &msg, MSG_NOSIGNAL | MSG_DONTWAIT) == 1;
}
static void close_received_rights(struct msghdr *message) {
  for (struct cmsghdr *c = CMSG_FIRSTHDR(message); c;
       c = CMSG_NXTHDR(message, c)) {
    if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
        c->cmsg_len < CMSG_LEN(0)) continue;
    size_t available = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    for (size_t i = 0; i < available; i++) {
      int received = -1;
      memcpy(&received, (char *)CMSG_DATA(c) + i * sizeof received,
             sizeof received);
      if (received >= 0) close(received);
    }
  }
}
static int take_fd(int socket) {
  char data = 0;
  struct iovec io = {.iov_base = &data, .iov_len = 1};
  union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } ctrl = {0};
  struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1,
    .msg_control = ctrl.bytes, .msg_controllen = sizeof ctrl.bytes};
  ssize_t count = recvmsg(socket, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  /* If unexpected SCM_RIGHTS arrives, close every delivered descriptor on
   * every malformed path; never leave a leaked unverified descriptor. */
  if (count != 1 || data != 'S' ||
      (msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC))) {
    close_received_rights(&msg);
    return -1;
  }
  struct cmsghdr *h = CMSG_FIRSTHDR(&msg);
  if (!h || h->cmsg_level != SOL_SOCKET || h->cmsg_type != SCM_RIGHTS ||
      h->cmsg_len != CMSG_LEN(sizeof(int)) || CMSG_NXTHDR(&msg, h)) {
    close_received_rights(&msg);
    return -1;
  }
  int fd = -1;
  memcpy(&fd, CMSG_DATA(h), sizeof fd);
  return fd;
}
static bool arm_kernel_kill_timer(void) {
  /* This independent kernel POSIX timer delivers SIGKILL to the child even
   * if its supervising parent is SIGSTOPped. A parent-owned timerfd alone
   * cannot enforce a wallclock limit when the supervisor is unscheduled.
   * Neither mechanism can reap a genuine TASK_UNINTERRUPTIBLE kernel wait. */
  struct sigevent event = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGKILL};
  timer_t timer_id;
  if (timer_create(CLOCK_MONOTONIC, &event, &timer_id)) return false;
  struct itimerspec duration = {0};
  duration.it_value.tv_sec = WATCHDOG_MS / 1000;
  duration.it_value.tv_nsec = (WATCHDOG_MS % 1000) * 1000000L;
  if (timer_settime(timer_id, 0, &duration, NULL)) {
    (void)timer_delete(timer_id);
    return false;
  }
  /* The child never disarms this timer: it exits on success or SIGKILL.
   * This makes timer expiry a kernel-enforced failure, not a health report. */
  return true;
}
static bool child_drop_privileges(int *work_fd, int *socket_fd, pid_t parent_pid) {
  /* A root child inherits the journal dirfd after fork unless all unrelated
   * descriptors are closed. Duplicate only its two authorized FDs to a fixed
   * pair, close every remaining descriptor >=3 including journal and plan,
   * THEN irrevocably drop supplemental groups, UIDs, GIDs and capabilities. */
  int data = fcntl(*work_fd, F_DUPFD_CLOEXEC, 64);
  if (data < 0) return false;
  int comm = fcntl(*socket_fd, F_DUPFD_CLOEXEC, 65);
  if (comm < 0) { close(data); return false; }
  if (syscall(SYS_close_range, 3u, (unsigned int)data - 1u, 0u) ||
      ((unsigned int)data + 1u < (unsigned int)comm &&
       syscall(SYS_close_range, (unsigned int)data + 1u,
         (unsigned int)comm - 1u, 0u)) ||
      syscall(SYS_close_range, (unsigned int)comm + 1u, UINT_MAX, 0u))
    return false;
  *work_fd = data;
  *socket_fd = comm;
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      setgroups(0, NULL) ||
      setresgid(65534, 65534, 65534) ||
      setresuid(65534, 65534, 65534) ||
      getuid() != 65534 || geteuid() != 65534 ||
      getgid() != 65534 || getegid() != 65534)
    return false;
  struct __user_cap_header_struct header = {
    .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0,
  };
  struct __user_cap_data_struct capabilities[2] = {0};
  if (syscall(SYS_capget, &header, capabilities) ||
      capabilities[0].effective || capabilities[0].permitted ||
      capabilities[0].inheritable || capabilities[1].effective ||
      capabilities[1].permitted || capabilities[1].inheritable)
    return false;
  /* Linux clears PDEATHSIG on credential changes. Install it only AFTER
   * the drop, and ensure the pinned parent still exists. */
  return prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 &&
    getppid() == parent_pid;
}
static bool verified_received_fd(int fd, off_t expected_size, const char *hex,
                                 const char *fault) {
  const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  struct stat actual;
  if (fd < 0 || fstat(fd, &actual) ||
      !S_ISREG(actual.st_mode) || actual.st_size != expected_size ||
      fcntl(fd, F_GET_SEALS) != seals) return false;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  bool good = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
  unsigned char block[16384], value[32];
  unsigned int length = 0;
  for (off_t at = 0; good && at < actual.st_size;) {
    if (at == 0 && strcmp(fault, "verifier-hash-stall") == 0) {
      /* Deterministic DEV fault at the exact full-file SHA read boundary.
       * A real kernel pipe blocks with a live writer and no data; the
       * verifier's own kernel SIGKILL timer must end this child. */
      int p[2];
      if (pipe2(p, O_CLOEXEC)) { good = false; break; }
      char unused;
      ssize_t blocked_read = read(p[0], &unused, 1);
      (void)blocked_read;
      good = false;
      break;
    }
    size_t want = actual.st_size - at > (off_t)sizeof block ?
      sizeof block : (size_t)(actual.st_size - at);
    ssize_t n = pread(fd, block, want, at);
    if (n <= 0 || EVP_DigestUpdate(ctx, block, (size_t)n) != 1) good = false;
    else at += n;
  }
  if (good) good = EVP_DigestFinal_ex(ctx, value, &length) == 1 &&
    length == 32 && hash_matches(value, hex);
  if (ctx) EVP_MD_CTX_free(ctx);
  return good;
}
static void verifier_work(int fd, int socket, const char *expected,
                          off_t expected_size, const char *fault,
                          pid_t parent_pid) {
  if (!arm_kernel_kill_timer()) _exit(3);
  if (!child_drop_privileges(&fd, &socket, parent_pid)) _exit(3);
  char start;
  if (recv(socket, &start, 1, 0) != 1 || start != 'G') _exit(3);
  if (strcmp(fault, "verifier-blocking-read") == 0) {
    int p[2];
    if (pipe2(p, O_CLOEXEC)) _exit(3);
    char ignored;
    ssize_t n = read(p[0], &ignored, 1);
    (void)n;
    _exit(3);
  }
  if (!verified_received_fd(fd, expected_size, expected, fault)) _exit(3);
  if (send(socket, "V", 1, MSG_DONTWAIT | MSG_NOSIGNAL) != 1) _exit(3);
  _exit(0);
}
static void child_work(int fd, int socket, const char *expected,
                       const char *fault, const char *fixture_root,
                       pid_t parent_pid) {
  /* The timer MUST precede the first blocking recv/start handshake. */
  if (!arm_kernel_kill_timer()) _exit(3);
  if (!child_drop_privileges(&fd, &socket, parent_pid)) _exit(3);
  char start;
  if (recv(socket, &start, 1, 0) != 1 || start != 'G') _exit(3);
  if (strcmp(fault, "child-journal-denial") == 0) {
    char attempt[220];
    if (snprintf(attempt, sizeof attempt, "%s/state/attempt.lock",
                 fixture_root) >= (int)sizeof attempt) _exit(3);
    int denied = open(attempt, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (denied >= 0) { close(denied); _exit(3); }
    if (errno != EACCES) _exit(3);
  }
  if (strcmp(fault, "stopped-child") == 0) raise(SIGSTOP);
  if (strcmp(fault, "child-killed") == 0) raise(SIGKILL);
  if (strcmp(fault, "blocking-read") == 0) {
    int p[2];
    if (pipe2(p, O_CLOEXEC) != 0) _exit(3);
    /* Kernel-blocked read with a live writer but no data. SIGKILL is able to
     * interrupt this class of wait; it DOES NOT emulate an unkillable D state. */
    char ignored;
    ssize_t blocked_read = read(p[0], &ignored, 1);
    (void)blocked_read;
    _exit(3);
  }
  int sealed = sealed_snapshot(fd, expected);
  if (sealed < 0) _exit(3);
  if (strcmp(fault, "late-receipt") == 0) usleep(2500000);
  if (!send_fd(socket, sealed)) _exit(3);
  if (strcmp(fault, "uncertain-outcome") == 0) pause();
  close(sealed);
  _exit(0);
}
static int timer(int milliseconds) {
  int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
  if (fd < 0) return -1;
  struct itimerspec limit = {0};
  limit.it_value.tv_sec = milliseconds / 1000;
  limit.it_value.tv_nsec = (milliseconds % 1000) * 1000000L;
  if (timerfd_settime(fd, 0, &limit, NULL)) { close(fd); return -1; }
  return fd;
}
static bool supervision(int input, const char *expected, off_t expected_size,
                        const char *fault, const char *fixture_root,
                        bool verifying, int *out_memfd) {
  int socketpair_fd[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, socketpair_fd))
    return false;
  const pid_t expected_parent = getpid();
  pid_t pid = fork();
  if (pid < 0) {
    close(socketpair_fd[0]); close(socketpair_fd[1]); return false;
  }
  if (pid == 0) {
    close(socketpair_fd[0]);
    if (verifying)
      verifier_work(input, socketpair_fd[1], expected, expected_size,
                    fault, expected_parent);
    else
      child_work(input, socketpair_fd[1], expected, fault, fixture_root,
                 expected_parent);
    _exit(3);
  }
  close(socketpair_fd[1]);
  int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
  int timerfd = timer(WATCHDOG_MS);
  if ((!verifying && strcmp(fault, "pre-g-parent-stop") == 0) ||
      (verifying && strcmp(fault, "verifier-pre-g-parent-stop") == 0))
    raise(SIGSTOP);
  bool started = pidfd >= 0 && timerfd >= 0 &&
    send(socketpair_fd[0], "G", 1, MSG_NOSIGNAL) == 1;
  struct pollfd events[2] = {
    {.fd = pidfd, .events = POLLIN},
    {.fd = timerfd, .events = POLLIN},
  };
  int rc = started ? poll(events, 2, WATCHDOG_MS + 100) : -1;
  bool success = rc > 0 && (events[0].revents & POLLIN) &&
    !(events[1].revents & POLLIN);
  /* The kernel timer, not a userspace timeout check after a potentially
   * blocking archive syscall, causes the independent supervisor to kill. */
  if (!success) {
    if (pidfd >= 0) (void)syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0);
    else (void)kill(pid, SIGKILL);
    if (getpgid(pid) == pid) (void)kill(-pid, SIGKILL);
  }
  if (!success && pidfd >= 0) {
    struct pollfd killed = {.fd = pidfd, .events = POLLIN};
    (void)poll(&killed, 1, KILL_REAP_MS);
  }
  int wait_status = 0;
  pid_t reaped = waitpid(pid, &wait_status, WNOHANG);
  success = success && reaped == pid &&
    WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0;
  if (success && verifying) {
    char verified = 0;
    success = recv(socketpair_fd[0], &verified, 1, MSG_DONTWAIT) == 1 &&
      verified == 'V';
  } else if (success) {
    *out_memfd = take_fd(socketpair_fd[0]);
    success = *out_memfd >= 0;
  }
  /* If SIGKILL cannot reap a kernel-D-state child, do NOT block in waitpid.
   * The durable journal remains and return state is always ambiguous/blocked.
   * PR_SET_PDEATHSIG gives the stuck task another SIGKILL when parent exits. */
  if (reaped != pid) (void)waitpid(pid, &wait_status, WNOHANG);
  close(socketpair_fd[0]);
  if (timerfd >= 0) close(timerfd);
  if (pidfd >= 0) close(pidfd);
  return success;
}
int main(int argc, char **argv) {
  bool ok = false;
  int archive = -1, staged_fd = -1;
  int journal_fd = -1, root_fd = -1, operator_fd = -1, state_fd = -1;
  if (argc != 3 || !isolated_gate()) goto end;
  const char *fault = argv[2];
  if (strcmp(fault, "normal") && strcmp(fault, "blocking-read") &&
      strcmp(fault, "stopped-child") && strcmp(fault, "late-receipt") &&
      strcmp(fault, "child-killed") && strcmp(fault, "uncertain-outcome") &&
      strcmp(fault, "pre-g-parent-stop") &&
      strcmp(fault, "verifier-blocking-read") &&
      strcmp(fault, "verifier-hash-stall") &&
      strcmp(fault, "verifier-pre-g-parent-stop") &&
      strcmp(fault, "child-journal-denial") &&
      strcmp(fault, "parent-die-after-latch") &&
      strcmp(fault, "parent-die-after-receipt")) goto end;
  char plan[200], source_path[200], state[160], lock[200], complete[200];
  if (!fixture_paths(argv[1], plan, source_path, state, lock, complete))
    goto end;
  /* Pin /journal/fixture and /state through directory FDs rather than
   * lstat(path) then later open(path). Verify same inodes before each
   * durable journal operation. No child may retain these root-owned FDs. */
  journal_fd = open("/journal", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (journal_fd < 0 || !directory_fd_owned(journal_fd)) goto end;
  const char *dirname = strrchr(argv[1], '/');
  if (!dirname) goto end;
  dirname++;
  root_fd = openat(journal_fd, dirname,
    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root_fd < 0 || !same_dir_entry(journal_fd, dirname, root_fd)) goto end;
  operator_fd = openat(root_fd, "operator",
    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  state_fd = openat(root_fd, "state",
    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (operator_fd < 0 || state_fd < 0 ||
      !same_dir_entry(root_fd, "operator", operator_fd) ||
      !same_dir_entry(root_fd, "state", state_fd)) goto end;
  char expected[65];
  if (!read_expected_at(operator_fd, expected)) goto end;
  archive = openat(root_fd, "archive.bin",
    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (archive < 0 || !regular_owned(archive, 1, (off_t)MAX_ARCHIVE))
    goto end;
  struct stat archive_stat;
  if (fstat(archive, &archive_stat)) goto end;
  if (!same_dir_entry(journal_fd, dirname, root_fd) ||
      !same_dir_entry(root_fd, "state", state_fd)) goto end;
  /* Never clear a prior attempt, including a completed attempt or SIGKILL. */
  int latch = openat(state_fd, "attempt.lock",
    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, FILEMODE);
  if (latch < 0) goto end;
  unsigned char nonce[16];
  if (getrandom(nonce, sizeof nonce, 0) != (ssize_t)sizeof nonce) {
    close(latch); goto end;
  }
  static const char alphabet[] = "0123456789abcdef";
  char hexnonce[33];
  for (size_t i = 0; i < sizeof nonce; i++) {
    hexnonce[i * 2] = alphabet[nonce[i] >> 4];
    hexnonce[i * 2 + 1] = alphabet[nonce[i] & 15];
  }
  hexnonce[32] = 0;
  char attempt[256];
  int n = snprintf(attempt, sizeof attempt,
    "{\"version\":1,\"status\":\"attempted\",\"nonce\":\"%s\","
    "\"archiveSha256\":\"%s\"}", hexnonce, expected);
  bool journaled = n > 0 && n < (int)sizeof attempt &&
    write_all(latch, attempt, (size_t)n) && fsync(latch) == 0;
  close(latch);
  if (!journaled || fsync(state_fd) ||
      !same_dir_entry(journal_fd, dirname, root_fd) ||
      !same_dir_entry(root_fd, "state", state_fd)) goto end;
  if (strcmp(fault, "parent-die-after-latch") == 0)
    (void)kill(getpid(), SIGKILL);
  ok = supervision(archive, expected, archive_stat.st_size, fault,
                   argv[1], false, &staged_fd);
  if (!ok) goto end;
  /* The stage child is reaped before the verifier forks. ALL potentially
   * blocking SHA/pread verification runs in the second independently armed,
   * privilege-dropped child. Parent handles only its one-byte receipt. */
  ok = supervision(staged_fd, expected, archive_stat.st_size, fault,
                   argv[1], true, NULL);
  if (!ok) goto end;
  if (strcmp(fault, "parent-die-after-receipt") == 0)
    (void)kill(getpid(), SIGKILL);
  if (!same_dir_entry(journal_fd, dirname, root_fd) ||
      !same_dir_entry(root_fd, "state", state_fd)) {
    ok = false; goto end;
  }
  int done = openat(state_fd, "complete.json",
    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, FILEMODE);
  if (done < 0) { ok = false; goto end; }
  const char *record = "{\"version\":1,\"stage\":\"verified-dev-only\","
    "\"reaped\":true,\"deployAuthorized\":false}";
  ok = write_all(done, record, strlen(record)) && fsync(done) == 0;
  close(done);
  if (ok) ok = fsync(state_fd) == 0 &&
    same_dir_entry(journal_fd, dirname, root_fd) &&
    same_dir_entry(root_fd, "state", state_fd);
end:
  if (staged_fd >= 0) close(staged_fd);
  if (archive >= 0) close(archive);
  if (state_fd >= 0) close(state_fd);
  if (operator_fd >= 0) close(operator_fd);
  if (root_fd >= 0) close(root_fd);
  if (journal_fd >= 0) close(journal_fd);
  puts(ok ? staged : blocked);
  return ok ? 0 : 2;
}
