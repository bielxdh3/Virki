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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SO_PEERCRED
#error SO_PEERCRED required
#endif
#ifndef SYS_pidfd_open
#error pidfd_open required
#endif

#define ROOT "/tmp/virki-supervisor-"
#define MAX_REQUEST 400
#define TIMEOUT_MS 1200
static const char load_request[] =
  "POST /images/load HTTP/1.1\r\n"
  "Host: isolated-disposable\r\n"
  "Content-Length: 25\r\n"
  "Connection: keep-alive\r\n\r\n"
  "VIRKI_DISPOSABLE_IMAGE_V1";
static const char inspect_request[] =
  "GET /images/sha256:fixture/json HTTP/1.1\r\n"
  "Host: isolated-disposable\r\n"
  "Connection: keep-alive\r\n\r\n";
static const char info_request[] =
  "GET /info HTTP/1.1\r\nHost: isolated-disposable\r\n"
  "Connection: keep-alive\r\n\r\n";
static const char success_response[] =
  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
  "Connection: keep-alive\r\n\r\nOK";
static const char bad_response[] =
  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
  "Connection: keep-alive\r\n\r\nNO";
static int child_pidfd = -1;
static pid_t child_pid = -1;
static char rootdir[80];
static char endpoint[108];

static int blocked(void) {
  puts("{\"status\":\"BLOCKED\",\"dockerLoadAuthorized\":false,"
       "\"deployAuthorized\":false}");
  return 2;
}
static bool poll_ready(int fd, short event) {
  struct pollfd p = {.fd = fd, .events = event};
  int ready = poll(&p, 1, TIMEOUT_MS);
  return ready == 1 && (p.revents & event) != 0 &&
    (p.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0;
}
static bool read_exact(int fd, const char *expected) {
  size_t left = strlen(expected), offset = 0;
  char buffer[MAX_REQUEST];
  if (left >= sizeof(buffer)) return false;
  while (offset < left) {
    if (!poll_ready(fd, POLLIN)) return false;
    ssize_t got = recv(fd, buffer + offset, left - offset, 0);
    if (got <= 0) return false;
    offset += (size_t)got;
  }
  return memcmp(buffer, expected, left) == 0;
}
static bool write_all(int fd, const char *data) {
  size_t offset = 0, total = strlen(data);
  while (offset < total) {
    if (!poll_ready(fd, POLLOUT)) return false;
    ssize_t wrote = send(fd, data + offset, total - offset, MSG_NOSIGNAL);
    if (wrote <= 0) return false;
    offset += (size_t)wrote;
  }
  return true;
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
static void teardown(void) {
  if (child_pid > 1) {
    kill(child_pid, SIGTERM);
    int status = 0;
    waitpid(child_pid, &status, 0);
    child_pid = -1;
  }
  if (child_pidfd >= 0) {
    close(child_pidfd);
    child_pidfd = -1;
  }
  if (endpoint[0]) unlink(endpoint);
  if (rootdir[0]) rmdir(rootdir);
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
  if (!poll_ready(listener, POLLIN)) return 33;
  int conn = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  close(listener);
  if (conn < 0) return 34;
  if (strcmp(mode, "dead-before-load") == 0) {
    close(conn);
    return 0;
  }
  if (!read_exact(conn, load_request)) return 35;
  if (!write_all(conn, success_response)) return 36;
  if (strcmp(mode, "response-smuggling") == 0 &&
      !write_all(conn, "JUNK")) return 41;
  if (strcmp(mode, "dead-after-load") == 0) {
    close(conn);
    return 0;
  }
  if (!read_exact(conn, inspect_request)) return 37;
  if (strcmp(mode, "stall-on-inspect") == 0) {
    /* Parent enforces a finite kernel poll timeout and then SIGTERM/reaps
     * the child, even when its peer is alive but unresponsive. */
    pause();
    return 42;
  }
  if (!write_all(conn, strcmp(mode, "bad-inspect") == 0 ?
      bad_response : success_response)) return 38;
  if (!read_exact(conn, info_request)) return 39;
  if (!write_all(conn, strcmp(mode, "fake-rootdir") == 0 ?
      bad_response : success_response)) return 40;
  /* Preserve the peer PID until the supervisor closes the SAME socket FD
   * after verifying the final response and pidfd state. */
  char final_byte = 0;
  (void)recv(conn, &final_byte, 1, 0);
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
int main(int argc, char **argv) {
  if (argc != 2 || getuid() != 0 || geteuid() != 0 ||
      !getenv("VIRKI_DISPOSABLE_SUPERVISOR_TEST") ||
      strcmp(getenv("VIRKI_DISPOSABLE_SUPERVISOR_TEST"), "1") != 0 ||
      access("/.dockerenv", F_OK) != 0) return blocked();
  const char *mode = argv[1];
  if (strcmp(mode, "normal") && strcmp(mode, "bad-inspect") &&
      strcmp(mode, "dead-before-load") && strcmp(mode, "dead-after-load") &&
      strcmp(mode, "fake-rootdir") && strcmp(mode, "stall-on-inspect") &&
      strcmp(mode, "response-smuggling"))
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
  good = good && write_all(sock, load_request);
  good = good && read_exact(sock, success_response);
  good = good && peer_on_same_fd(sock, child_pid, ticks) &&
    same_provenance(child_pid, &observed);
  good = good && write_all(sock, inspect_request);
  good = good && read_exact(sock, success_response);
  good = good && peer_on_same_fd(sock, child_pid, ticks) &&
    same_provenance(child_pid, &observed);
  good = good && write_all(sock, info_request);
  good = good && read_exact(sock, success_response);
  good = good && peer_on_same_fd(sock, child_pid, ticks) &&
    same_provenance(child_pid, &observed);
  bool isolation = isolation_approved(&observed);
  close(sock);
  teardown();
  if (!good) return blocked();
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
