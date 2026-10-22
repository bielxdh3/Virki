/*
 * Disposable, READ-ONLY Linux AF_UNIX peer credentials experiment.
 *
 * This is NOT an installed Virki authorizer and never issues a Docker command
 * or transmits a byte to the connected Unix socket. Tests compile this source
 * in a network-disabled, disposable, root-isolated Linux container. Only
 * paths below a private /tmp/virki-peer-fixture-* directory are accepted.
 *
 * Linux SO_PEERCRED identifies the process at connect time; pidfd_open pins
 * its PID across the observation. This STILL DOES NOT attest continuous
 * daemon lifecycle, forwarding proxies, namespace provenance or future CLI
 * connections. The experiment always reports dockerLoadAuthorized:false.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SO_PEERCRED
#error Linux SO_PEERCRED is mandatory
#endif
#ifndef SYS_pidfd_open
#error Linux pidfd_open syscall is mandatory
#endif

#define MAX_PIN 180
#define PIN_MAGIC "VIRKI_DISPOSABLE_PEER_PIN_V1\n"
#define PREFIX "/tmp/virki-peer-fixture-"

static int fail(void) {
  puts("{\"status\":\"BLOCKED\",\"dockerLoadAuthorized\":false,\"deployAuthorized\":false}");
  return 2;
}

static bool read_full(int fd, char *buffer, size_t capacity, ssize_t *length) {
  ssize_t len = read(fd, buffer, capacity);
  if (len <= 0 || (size_t)len >= capacity) return false;
  if (read(fd, buffer + len, 1) != 0) return false;
  buffer[len] = '\0';
  *length = len;
  return true;
}

static bool trusted_fixture_directory(const char *directory) {
  if (strncmp(directory, PREFIX, strlen(PREFIX)) != 0) return false;
  const char *suffix = directory + strlen(PREFIX);
  if (strlen(suffix) != 16) return false;
  for (size_t i = 0; i < 16; i++) {
    if (!((suffix[i] >= 'a' && suffix[i] <= 'f') ||
          (suffix[i] >= '0' && suffix[i] <= '9'))) return false;
  }
  struct stat st;
  return lstat(directory, &st) == 0 && S_ISDIR(st.st_mode) &&
    st.st_uid == 0 && st.st_gid == 0 && (st.st_mode & 07777) == 0700;
}

static bool parse_decimal(const char *raw, unsigned long long *result) {
  if (!*raw || *raw == '0' || strlen(raw) > 20) return false;
  errno = 0;
  char *end = NULL;
  unsigned long long num = strtoull(raw, &end, 10);
  if (errno || *end || num == 0) return false;
  *result = num;
  return true;
}

/* /proc/PID/stat comm can contain spaces and right parentheses. Take the
 * last ')' followed by the fields and read field 22 (index 19 after state). */
static bool read_process_starttime(pid_t pid, unsigned long long *ticks) {
  char filename[80], data[8192];
  snprintf(filename, sizeof(filename), "/proc/%ld/stat", (long)pid);
  int fd = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  ssize_t count = read(fd, data, sizeof(data) - 1);
  close(fd);
  if (count <= 0 || count >= (ssize_t)sizeof(data) - 1) return false;
  data[count] = '\0';
  char *end_comm = strrchr(data, ')');
  if (!end_comm || end_comm[1] != ' ') return false;
  char *save = NULL;
  char *field = strtok_r(end_comm + 2, " \n", &save);
  for (int index = 0; index < 19; index++) {
    if (!field) return false;
    field = strtok_r(NULL, " \n", &save);
  }
  return field && parse_decimal(field, ticks);
}

static bool pin_liveness(int pidfd) {
  struct pollfd poll_fd = {.fd = pidfd, .events = POLLIN};
  return poll(&poll_fd, 1, 0) == 0;
}

int main(int argc, char **argv) {
  if (argc != 2 || getuid() != 0 || geteuid() != 0 ||
      !getenv("VIRKI_DISPOSABLE_PEER_PROBE") ||
      strcmp(getenv("VIRKI_DISPOSABLE_PEER_PROBE"), "1") != 0 ||
      access("/.dockerenv", F_OK) != 0) return fail();

  /* Never accept arbitrary Docker endpoints, including production socket. */
  char *requested = argv[1];
  if (strlen(requested) >= 1024 || strstr(requested, "..")) return fail();
  char directory[PATH_MAX];
  const char *last = strrchr(requested, '/');
  if (!last || strcmp(last, "/docker.sock") != 0) return fail();
  size_t len = (size_t)(last - requested);
  if (len >= sizeof(directory)) return fail();
  memcpy(directory, requested, len);
  directory[len] = '\0';
  if (!trusted_fixture_directory(directory)) return fail();

  char pin_path[PATH_MAX];
  if (snprintf(pin_path, sizeof(pin_path), "%s/peer.pin", directory) >=
      (int)sizeof(pin_path)) return fail();
  int pinfd = open(pin_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (pinfd < 0) return fail();
  struct stat pin_stat;
  bool pin_ok = fstat(pinfd, &pin_stat) == 0 &&
    S_ISREG(pin_stat.st_mode) && pin_stat.st_uid == 0 &&
    pin_stat.st_gid == 0 && pin_stat.st_nlink == 1 &&
    (pin_stat.st_mode & 07777) == 0600;
  char pin[MAX_PIN];
  ssize_t pin_len = 0;
  pin_ok = pin_ok && read_full(pinfd, pin, sizeof(pin), &pin_len);
  struct stat pin_after;
  pin_ok = pin_ok && fstat(pinfd, &pin_after) == 0 &&
    pin_stat.st_ino == pin_after.st_ino && pin_stat.st_dev == pin_after.st_dev &&
    pin_stat.st_size == pin_after.st_size &&
    pin_stat.st_mtim.tv_nsec == pin_after.st_mtim.tv_nsec &&
    pin_stat.st_ctim.tv_nsec == pin_after.st_ctim.tv_nsec;
  close(pinfd);
  if (!pin_ok || strncmp(pin, PIN_MAGIC, strlen(PIN_MAGIC)) != 0) return fail();
  char original_pin[MAX_PIN];
  memcpy(original_pin, pin, (size_t)pin_len);

  unsigned long expected_pid = 0;
  unsigned long long expected_ticks = 0;
  char after[MAX_PIN];
  char *pidline = pin + strlen(PIN_MAGIC);
  if (strncmp(pidline, "pid=", 4) != 0) return fail();
  char *newline = strchr(pidline, '\n');
  if (!newline) return fail();
  *newline = '\0';
  unsigned long long decimal_pid = 0;
  if (!parse_decimal(pidline + 4, &decimal_pid) || decimal_pid > INT_MAX ||
      decimal_pid <= 1) return fail();
  expected_pid = (unsigned long)decimal_pid;
  const char *ticks_line = newline + 1;
  if (strncmp(ticks_line, "start_ticks=", 12) != 0) return fail();
  const char *ticks_raw = ticks_line + 12;
  size_t ticklen = strcspn(ticks_raw, "\n");
  if (ticks_raw[ticklen] != '\n' || ticks_raw[ticklen + 1] != '\0')
    return fail();
  if (ticklen >= sizeof(after)) return fail();
  memcpy(after, ticks_raw, ticklen);
  after[ticklen] = '\0';
  if (!parse_decimal(after, &expected_ticks)) return fail();
  char canonical[MAX_PIN];
  int formatted = snprintf(canonical, sizeof(canonical),
    PIN_MAGIC "pid=%lu\nstart_ticks=%llu\n", expected_pid, expected_ticks);
  if (formatted != pin_len ||
      memcmp(original_pin, canonical, (size_t)pin_len) != 0)
    return fail();

  struct stat sock_stat;
  if (lstat(requested, &sock_stat) != 0 || !S_ISSOCK(sock_stat.st_mode) ||
      sock_stat.st_uid != 0 || sock_stat.st_gid != 0 ||
      (sock_stat.st_mode & 07777) != 0600) return fail();

  /* pin actual FD and kernel credentials of THIS connection. No data is sent. */
  int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (sock < 0) return fail();
  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  if (strlen(requested) >= sizeof(addr.sun_path)) {
    close(sock);
    return fail();
  }
  strcpy(addr.sun_path, requested);
  int connected = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
  if (connected < 0 && errno == EINPROGRESS) {
    struct pollfd pfd = {.fd = sock, .events = POLLOUT};
    if (poll(&pfd, 1, 1000) != 1) {
      close(sock);
      return fail();
    }
    int error = 0;
    socklen_t error_len = sizeof(error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error) {
      close(sock);
      return fail();
    }
  } else if (connected != 0) {
    close(sock);
    return fail();
  }
  struct ucred credential;
  socklen_t cred_len = sizeof(credential);
  bool correct = getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &credential,
    &cred_len) == 0 && cred_len == sizeof(credential) &&
    credential.pid == (pid_t)expected_pid &&
    credential.uid == 0 && credential.gid == 0;
  int pidfd = -1;
  if (correct) pidfd = (int)syscall(SYS_pidfd_open, credential.pid, 0);
  if (pidfd < 0) correct = false;
  unsigned long long first_ticks = 0, last_ticks = 0;
  if (correct) correct = read_process_starttime(credential.pid, &first_ticks) &&
    first_ticks == expected_ticks && pin_liveness(pidfd);
  /* It is the CONNECTED socket FD that stays alive through the final
   * measurement. We never infer credentials from the pathname or from info. */
  if (correct) {
    struct ucred again;
    socklen_t again_len = sizeof(again);
    correct = getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &again, &again_len) == 0 &&
      again_len == sizeof(again) &&
      memcmp(&credential, &again, sizeof(credential)) == 0 &&
      read_process_starttime(credential.pid, &last_ticks) &&
      last_ticks == first_ticks && pin_liveness(pidfd);
  }
  if (pidfd >= 0) close(pidfd);
  close(sock);
  if (!correct) return fail();
  /* Explicitly not a capability: the checked FD is already closed. */
  printf("{\"status\":\"KERNEL_PEER_MATCHES_TEST_PIN_ONLY\","
    "\"peerPid\":%ld,\"peerUid\":0,\"peerGid\":0,"
    "\"pidfdHeldDuringObservation\":true,"
    "\"dockerLoadAuthorized\":false,\"deployAuthorized\":false}\n",
    (long)credential.pid);
  return 0;
}
