/*
 * NON-AUTHORIZING disposable Linux AF_UNIX FD+lifecycle experiment.
 *
 * This executable launches its OWN fake daemon, retains its pidfd and the
 * SAME connected AF_UNIX FD for a bounded synthetic load + inspect exchange.
 * It never invokes dockerd, sends real image data, reaches the Docker host
 * socket, starts containers, or grants production admission.
 *
 * Linux SO_PEERCRED is bound to the accepted connection. That says NOTHING
 * about a forwarding proxy's upstream target or mount/cgroup separation.
 * Namespace isolation must be independently proved before ANY authorizer.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_PEERCRED
#error SO_PEERCRED required
#endif
#ifndef SYS_pidfd_open
#error pidfd_open required
#endif

#define ROOT "/tmp/virki-supervisor-"
#define TIMEOUT_MS 1200
#define TRANSACTION_BUDGET_MS 1800
#define TERM_GRACE_MS 180
#define KILL_REAP_MS 700
#define NONCE_HEX 32
/*
 * This is NOT Docker HTTP. An unpredictable transaction nonce must be echoed
 * with its expected phase, and no surplus response bytes may be buffered.
 * A fake daemon cannot turn uncorrelated success prefixes into approval.
 */
static const char *phases[] = {"LOAD", "INSPECT", "INFO"};
static int child_pidfd = -1;
static pid_t child_pid = -1;
static char rootdir[80];
static char endpoint[108];

static int blocked(void) {
  puts("{\"status\":\"BLOCKED\",\"dockerLoadAuthorized\":false,"
       "\"deployAuthorized\":false}");
  return 2;
}
static long long monotonic_ms(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
  return (long long)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
static bool poll_ready_until(int fd, short event, long long deadline) {
  long long now = monotonic_ms();
  if (now < 0 || now >= deadline) return false;
  int left = (deadline - now > INT_MAX) ? INT_MAX : (int)(deadline - now);
  struct pollfd p = {.fd = fd, .events = event};
  int ready;
  do { ready = poll(&p, 1, left); } while (ready < 0 && errno == EINTR &&
    (left = (int)(deadline - monotonic_ms())) > 0);
  return ready == 1 && (p.revents & event) != 0 &&
    (p.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0;
}
static bool read_exact_until(int fd, const char *expected, long long deadline) {
  size_t total = strlen(expected);
  for (size_t offset = 0; offset < total;) {
    if (!poll_ready_until(fd, POLLIN, deadline)) return false;
    char buffer[128];
    ssize_t got = recv(fd, buffer, total - offset < sizeof(buffer) ?
      total - offset : sizeof(buffer), MSG_DONTWAIT);
    if (got < 0 && (errno == EAGAIN || errno == EINTR)) continue;
    if (got <= 0 || memcmp(buffer, expected + offset, (size_t)got) != 0)
      return false;
    offset += (size_t)got;
  }
  return true;
}
static bool no_surplus(int fd) {
  char extra;
  ssize_t n = recv(fd, &extra, 1, MSG_PEEK | MSG_DONTWAIT);
  return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}
static bool clean_end_of_stream(int fd, long long deadline) {
  /* Unlike no_surplus(), EOF closes the final transaction; no delayed suffix
   * can be silently accepted after the third receipt. */
  while (monotonic_ms() < deadline) {
    struct pollfd p = {.fd = fd, .events = POLLIN | POLLHUP};
    int left = (int)(deadline - monotonic_ms());
    if (left <= 0) return false;
    int ready = poll(&p, 1, left);
    if (ready < 0 && errno == EINTR) continue;
    if (ready != 1 || (p.revents & (POLLERR | POLLNVAL))) return false;
    char byte = 0;
    ssize_t got = recv(fd, &byte, 1, MSG_DONTWAIT);
    if (got == 0) return true;
    if (got > 0) return false;
    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
  }
  return false;
}
static bool write_all_until(int fd, const char *data, long long deadline) {
  size_t offset = 0, total = strlen(data);
  while (offset < total) {
    if (!poll_ready_until(fd, POLLOUT, deadline)) return false;
    ssize_t wrote = send(fd, data + offset, total - offset,
      MSG_NOSIGNAL | MSG_DONTWAIT);
    if (wrote < 0 && (errno == EAGAIN || errno == EINTR)) continue;
    if (wrote <= 0) return false;
    offset += (size_t)wrote;
  }
  return true;
}
static bool nonce_hex(char out[NONCE_HEX + 1]) {
  unsigned char raw[NONCE_HEX / 2];
  if (getrandom(raw, sizeof(raw), 0) != (ssize_t)sizeof(raw)) return false;
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < sizeof(raw); i++) {
    out[i * 2] = hex[raw[i] >> 4];
    out[i * 2 + 1] = hex[raw[i] & 15];
  }
  out[NONCE_HEX] = '\0';
  return true;
}
static bool frame(char *out, size_t capacity, const char *kind,
                  const char *phase, const char *nonce, const char *status) {
  int length = snprintf(out, capacity, "%s %s %s%s%s\n",
    kind, phase, nonce, status ? " " : "", status ? status : "");
  return length > 0 && (size_t)length < capacity;
}
static bool request_frame(int fd, const char *phase, char nonce[NONCE_HEX + 1],
                          long long deadline) {
  char incoming[64], expected[64];
  /* Read one fixed-length request; the nonce is conveyed by this very socket.
   * The fake daemon is never allowed to choose the client's challenge. */
  if (!frame(expected, sizeof(expected), "REQ", phase,
    "00000000000000000000000000000000", NULL)) return false;
  const size_t length = strlen(expected);
  if (length >= sizeof(incoming)) return false;
  for (size_t offset = 0; offset < length;) {
    if (!poll_ready_until(fd, POLLIN, deadline)) return false;
    ssize_t got = recv(fd, incoming + offset, length - offset, MSG_DONTWAIT);
    if (got < 0 && (errno == EAGAIN || errno == EINTR)) continue;
    if (got <= 0) return false;
    offset += (size_t)got;
  }
  const size_t prefix = 4 + strlen(phase) + 1;
  if (memcmp(incoming, expected, prefix) ||
      incoming[length - 1] != '\n') return false;
  for (size_t i = 0; i < NONCE_HEX; i++) {
    const char c = incoming[prefix + i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  memcpy(nonce, incoming + prefix, NONCE_HEX);
  nonce[NONCE_HEX] = '\0';
  return no_surplus(fd);
}
static bool pidfd_alive(int pidfd) {
  struct pollfd p = {.fd = pidfd, .events = POLLIN};
  return poll(&p, 1, 0) == 0;
}
static bool stat_starttime(pid_t pid, unsigned long long *ticks) {
  char filename[64], data[8192];
  if (snprintf(filename, sizeof(filename), "/proc/%ld/stat", (long)pid) >=
      (int)sizeof(filename)) return false;
  int fd = open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return false;
  ssize_t count = read(fd, data, sizeof(data) - 1);
  close(fd);
  if (count <= 0 || count >= (ssize_t)sizeof(data) - 1) return false;
  data[count] = '\0';
  char *end = strrchr(data, ')');
  if (!end || end[1] != ' ') return false;
  char *save = NULL;
  char *field = strtok_r(end + 2, " \n", &save);
  for (int i = 0; i < 19; i++) {
    if (!field) return false;
    field = strtok_r(NULL, " \n", &save);
  }
  if (!field || *field == '0') return false;
  errno = 0;
  char *tail = NULL;
  unsigned long long value = strtoull(field, &tail, 10);
  if (errno || !tail || *tail || value == 0) return false;
  *ticks = value;
  return true;
}
static bool peer_on_same_fd(int sock, pid_t pid, unsigned long long ticks) {
  struct ucred cred;
  socklen_t size = sizeof(cred);
  unsigned long long now = 0;
  return getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &size) == 0 &&
    size == sizeof(cred) && cred.pid == pid &&
    cred.uid == 0 && cred.gid == 0 &&
    pidfd_alive(child_pidfd) && stat_starttime(pid, &now) && now == ticks;
}
static bool proc_namespace(pid_t pid, const char *name, char *out, size_t size) {
  char file[80];
  if (snprintf(file, sizeof(file), "/proc/%ld/ns/%s", (long)pid, name) >=
      (int)sizeof(file)) return false;
  ssize_t n = readlink(file, out, size - 1);
  if (n <= 0 || (size_t)n >= size - 1) return false;
  out[n] = '\0';
  return true;
}
struct provenance {
  char mnt[80];
  char net[80];
  char pid[80];
  char cgroup[512];
};
static bool read_proc_cgroup(pid_t pid, char *out, size_t size) {
  char filename[80];
  if (snprintf(filename, sizeof(filename), "/proc/%ld/cgroup", (long)pid) >=
      (int)sizeof(filename)) return false;
  int fd = open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return false;
  ssize_t count = read(fd, out, size);
  close(fd);
  if (count <= 4 || (size_t)count >= size) return false;
  out[count] = '\0';
  return strncmp(out, "0::/", 4) == 0 &&
    out[count - 1] == '\n' && strchr(out, '\n') == out + count - 1;
}
static bool snapshot_provenance(pid_t pid, struct provenance *snapshot) {
  return proc_namespace(pid, "mnt", snapshot->mnt, sizeof(snapshot->mnt)) &&
    proc_namespace(pid, "net", snapshot->net, sizeof(snapshot->net)) &&
    proc_namespace(pid, "pid", snapshot->pid, sizeof(snapshot->pid)) &&
    read_proc_cgroup(pid, snapshot->cgroup, sizeof(snapshot->cgroup));
}
static bool same_provenance(pid_t pid, const struct provenance *expected) {
  struct provenance actual = {0};
  return snapshot_provenance(pid, &actual) &&
    strcmp(actual.mnt, expected->mnt) == 0 &&
    strcmp(actual.net, expected->net) == 0 &&
    strcmp(actual.pid, expected->pid) == 0 &&
    strcmp(actual.cgroup, expected->cgroup) == 0;
}
static bool isolation_approved(const struct provenance *child) {
  /*
   * Evidence is necessary but not sufficient: namespace IDs and cgroup
   * strings do not attest mount-root ownership, service-unit provenance,
   * seccomp isolation or a separately approved binary. None is installed.
   */
  struct provenance parent = {0};
  if (!snapshot_provenance(getpid(), &parent)) return false;
  const bool namespaces_separate =
    strcmp(child->mnt, parent.mnt) != 0 &&
    strcmp(child->net, parent.net) != 0 &&
    strcmp(child->pid, parent.pid) != 0;
  const bool cgroup_separate =
    strcmp(child->cgroup, parent.cgroup) != 0 &&
    strncmp(child->cgroup, "0::/virki-offline-import", 24) == 0;
  const bool independent_owner_service_pin = false;
  return namespaces_separate && cgroup_separate && independent_owner_service_pin;
}
/* Injection hooks exercise EINTR and unverifiable reap reporting only inside
 * this disposable fixture; neither path can grant production authority. */
static pid_t fixture_waitpid(pid_t pid, int *status) {
  static bool injected_eintr = false;
  const char *eintr = getenv("VIRKI_DISPOSABLE_SUPERVISOR_INJECT_WAITPID_EINTR");
  if (!injected_eintr && eintr && strcmp(eintr, "1") == 0) {
    injected_eintr = true;
    errno = EINTR;
    fputs("DISPOSABLE_FIXTURE_WAITPID_EINTR_INJECTED\n", stderr);
    return -1;
  }
  pid_t result = waitpid(pid, status, WNOHANG);
  const char *masked = getenv("VIRKI_DISPOSABLE_SUPERVISOR_MASK_REAP_PROOF");
  if (result == pid && masked && strcmp(masked, "1") == 0) {
    /* The kernel reaped the process, but the caller has lost its proof. */
    errno = ECHILD;
    return -1;
  }
  return result;
}
static pid_t wait_reap_until(pid_t pid, int *status, long long deadline) {
  while (monotonic_ms() >= 0 && monotonic_ms() < deadline) {
    pid_t done = fixture_waitpid(pid, status);
    if (done == pid || (done < 0 && errno != EINTR)) return done;
    if (done == 0) usleep(10000);
  }
  return 0;
}
static bool teardown(void) {
  bool confirmed_reap = true;
  if (child_pid > 1) {
    int status = 0;
    pid_t done = wait_reap_until(child_pid, &status, monotonic_ms() + 30);
    if (done == 0) {
      /* Only our unreaped fork child may be signaled; no PID reuse until reap.
       * TERM-ignore cannot hang the test or leave its fake daemon alive. */
      kill(child_pid, SIGTERM);
      done = wait_reap_until(child_pid, &status, monotonic_ms() + TERM_GRACE_MS);
      if (done == 0) {
        kill(child_pid, SIGKILL);
        done = wait_reap_until(child_pid, &status, monotonic_ms() + KILL_REAP_MS);
      }
    }
    /* The fake child is NOT authorizing. Never block beyond the kill budget;
     * a failed reap must result in BLOCKED and an operator-visible error. */
    confirmed_reap = done == child_pid;
    if (confirmed_reap)
      fprintf(stderr, "DISPOSABLE_FIXTURE_CHILD_REAPED %ld\n", (long)child_pid);
    else
      fputs("fixture child reap was not confirmed\n", stderr);
    child_pid = -1;
  }
  if (child_pidfd >= 0) {
    close(child_pidfd);
    child_pidfd = -1;
  }
  if (endpoint[0]) unlink(endpoint);
  if (rootdir[0]) rmdir(rootdir);
  return confirmed_reap;
}
static int serve_fake(const char *mode, int readyfd) {
  int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) return 30;
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  strcpy(address.sun_path, endpoint);
  if (bind(listener, (struct sockaddr *)&address,
      offsetof(struct sockaddr_un, sun_path) + strlen(endpoint) + 1) != 0 ||
      chmod(endpoint, 0600) != 0 || listen(listener, 1) != 0) {
    close(listener);
    return 31;
  }
  if (write(readyfd, "R", 1) != 1) return 32;
  close(readyfd);
  if (!poll_ready_until(listener, POLLIN, monotonic_ms() + TIMEOUT_MS)) return 33;
  int conn = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  close(listener);
  if (conn < 0) return 34;
  if (strcmp(mode, "dead-before-load") == 0) {
    close(conn);
    return 0;
  }
  const long long deadline = monotonic_ms() + TRANSACTION_BUDGET_MS;
  char nonce[NONCE_HEX + 1], response[80];
  for (int i = 0; i < 3; i++) {
    if (!request_frame(conn, phases[i], nonce, deadline)) return 35 + i;
    if (i == 1 && (strcmp(mode, "stall-on-inspect") == 0 ||
                   strcmp(mode, "ignore-term") == 0)) {
      if (strcmp(mode, "ignore-term") == 0) signal(SIGTERM, SIG_IGN);
      for (;;) pause();
    }
    const bool wrong = (i == 1 && strcmp(mode, "bad-inspect") == 0) ||
                       (i == 2 && strcmp(mode, "fake-rootdir") == 0);
    if (!frame(response, sizeof(response), "ACK", phases[i], nonce,
      wrong ? "NO" : "OK")) return 38;
    if (i == 1 && strcmp(mode, "slow-trickle") == 0) {
      /* 120ms/byte: a per-byte timeout would reset forever. */
      for (size_t b = 0; b < strlen(response); b++) {
        if (send(conn, response + b, 1, MSG_NOSIGNAL) != 1) return 42;
        usleep(120000);
      }
    } else if (!write_all_until(conn, response, deadline)) return 36;
    if (i == 0 && strcmp(mode, "response-smuggling") == 0 &&
        !write_all_until(conn, "JUNK", deadline)) return 41;
    if (i == 0 && strcmp(mode, "pipeline-valid") == 0) {
      /* Three syntactically valid replies issued for only one request. */
      if (!write_all_until(conn, response, deadline) ||
          !write_all_until(conn, response, deadline)) return 43;
    }
    if (i == 0 && strcmp(mode, "dead-after-load") == 0) {
      close(conn);
      return 0;
    }
  }
  /* Preserve the peer PID until the supervisor closes the SAME socket FD
   * after verifying the final response and pidfd state. */
  char final_byte = 0;
  (void)recv(conn, &final_byte, 1, 0);
  if (strcmp(mode, "late-final-junk") == 0)
    (void)write_all_until(conn, "JUNK", monotonic_ms() + TIMEOUT_MS);
  close(conn);
  return 0;
}
static bool fixture_directory(void) {
  strcpy(rootdir, ROOT "XXXXXXXX");
  if (!mkdtemp(rootdir)) return false;
  struct stat statbuf;
  if (lstat(rootdir, &statbuf) != 0 ||
      !S_ISDIR(statbuf.st_mode) || statbuf.st_uid != 0 ||
      statbuf.st_gid != 0 || (statbuf.st_mode & 07777) != 0700)
    return false;
  if (snprintf(endpoint, sizeof(endpoint), "%s/engine.sock", rootdir) >=
      (int)sizeof(endpoint)) return false;
  return true;
}
static bool approved_disposable_test_environment(void) {
  if (getuid() != 0 || geteuid() != 0 ||
      !getenv("VIRKI_DISPOSABLE_SUPERVISOR_TEST") ||
      strcmp(getenv("VIRKI_DISPOSABLE_SUPERVISOR_TEST"), "1") != 0)
    return false;
  if (access("/.dockerenv", F_OK) == 0) return true;
  /* Independent ephemeral C fixture may run inside the local WSL2 VM without
   * invoking any Docker endpoint. It has no production code path. */
  if (!getenv("VIRKI_DISPOSABLE_SUPERVISOR_WSL_TEST") ||
      strcmp(getenv("VIRKI_DISPOSABLE_SUPERVISOR_WSL_TEST"), "1") != 0)
    return false;
  int fd = open("/proc/sys/kernel/osrelease", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return false;
  char kernel[256] = {0};
  ssize_t n = read(fd, kernel, sizeof(kernel) - 1);
  close(fd);
  if (n <= 0 || n >= (ssize_t)sizeof(kernel) - 1) return false;
  return strstr(kernel, "microsoft-standard-WSL2") != NULL;
}
int main(int argc, char **argv) {
  if (argc != 2 || !approved_disposable_test_environment()) return blocked();
  const char *mode = argv[1];
  if (strcmp(mode, "normal") && strcmp(mode, "bad-inspect") &&
      strcmp(mode, "dead-before-load") && strcmp(mode, "dead-after-load") &&
      strcmp(mode, "fake-rootdir") && strcmp(mode, "stall-on-inspect") &&
      strcmp(mode, "response-smuggling") && strcmp(mode, "pipeline-valid") &&
      strcmp(mode, "slow-trickle") && strcmp(mode, "ignore-term") &&
      strcmp(mode, "late-final-junk"))
    return blocked();
  if (!fixture_directory()) {
    teardown();
    return blocked();
  }
  int ready[2];
  if (pipe2(ready, O_CLOEXEC) != 0) {
    teardown();
    return blocked();
  }
  child_pid = fork();
  if (child_pid < 0) {
    close(ready[0]); close(ready[1]);
    teardown();
    return blocked();
  }
  if (child_pid == 0) {
    close(ready[0]);
    int result = serve_fake(mode, ready[1]);
    close(ready[1]);
    _exit(result);
  }
  close(ready[1]);
  child_pidfd = (int)syscall(SYS_pidfd_open, child_pid, 0);
  char ready_byte = 0;
  struct pollfd readiness = {.fd = ready[0], .events = POLLIN};
  int ready_result = poll(&readiness, 1, TIMEOUT_MS);
  bool ready_ok = ready_result == 1 && (readiness.revents & POLLIN) != 0 &&
    (readiness.revents & (POLLERR | POLLNVAL)) == 0;
  if (child_pidfd < 0 || !ready_ok ||
      read(ready[0], &ready_byte, 1) != 1 || ready_byte != 'R') {
    close(ready[0]); teardown(); return blocked();
  }
  close(ready[0]);
  unsigned long long ticks = 0;
  struct provenance observed = {0};
  if (!stat_starttime(child_pid, &ticks) ||
      !snapshot_provenance(child_pid, &observed)) {
    teardown(); return blocked();
  }
  int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sock < 0) { teardown(); return blocked(); }
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  strcpy(address.sun_path, endpoint);
  bool good = connect(sock, (struct sockaddr *)&address,
    offsetof(struct sockaddr_un, sun_path) + strlen(endpoint) + 1) == 0;
  good = good && peer_on_same_fd(sock, child_pid, ticks) &&
    same_provenance(child_pid, &observed);
  const long long transaction_deadline = monotonic_ms() + TRANSACTION_BUDGET_MS;
  for (int i = 0; good && i < 3; i++) {
    char nonce[NONCE_HEX + 1], request[80], expected[80];
    good = nonce_hex(nonce) &&
      frame(request, sizeof(request), "REQ", phases[i], nonce, NULL) &&
      frame(expected, sizeof(expected), "ACK", phases[i], nonce, "OK") &&
      write_all_until(sock, request, transaction_deadline) &&
      read_exact_until(sock, expected, transaction_deadline) &&
      no_surplus(sock) &&
      peer_on_same_fd(sock, child_pid, ticks) &&
      same_provenance(child_pid, &observed);
  }
  /* End-of-stream, not an instantaneous EAGAIN peek, proves the final reply
   * had no delayed suffix on the one connected kernel socket. */
  good = good && shutdown(sock, SHUT_WR) == 0 &&
    clean_end_of_stream(sock, transaction_deadline);
  bool isolation = isolation_approved(&observed);
  close(sock);
  bool child_reaped = teardown();
  if (!good || !child_reaped) return blocked();
  /* Real kernel-bound mechanics are proven, but not daemon root isolation.
   * Even if isolation were confirmed, this is NOT an owner-installed binary
   * and no release-pinned Docker image was verified. NEVER authorize here. */
  printf("{\"status\":\"SAME_FD_KERNEL_PEER_AND_LIFECYCLE_TEST_ONLY\","
    "\"sameFdAcrossSyntheticLoadAndInspect\":true,"
    "\"supervisedPidfdAcrossExchange\":true,"
    "\"isolatedNamespacesApproved\":%s,"
    "\"dockerLoadAuthorized\":false,\"deployAuthorized\":false}\n",
    isolation ? "true" : "false");
  return 0;
}
