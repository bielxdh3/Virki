/*
 * Disposal-only executable. It connects exclusively to an auto-generated
 * /tmp/virki-fd-bound-XXXXXX/daemon.sock owned by this user, and exercises
 * the reusable Linux transport against a mock listener. Never a release tool.
 */
#define _GNU_SOURCE
#include "native-docker-fd-transport.h"
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int blocked(void) {
  puts("{\"status\":\"BLOCKED\",\"dockerLoadAuthorized\":false,"
       "\"deployAuthorized\":false}");
  return 2;
}
static bool private_fixture_path(const char *value) {
  static const char prefix[] = "/tmp/virki-fd-bound-";
  char parent[100];
  size_t base = sizeof prefix - 1;
  if (!value || strlen(value) != base + 6 + strlen("/daemon.sock") ||
      strncmp(value, prefix, base)) return false;
  for (size_t i = 0; i < 6; i++) {
    char c = value[base + i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9'))) return false;
  }
  if (strcmp(value + base + 6, "/daemon.sock")) return false;
  if (snprintf(parent, sizeof parent, "%.*s", (int)(base + 6), value) >=
      (int)sizeof parent) return false;
  struct stat root, socket_file;
  return lstat(parent, &root) == 0 && S_ISDIR(root.st_mode) &&
    root.st_uid == getuid() && (root.st_mode & 07777) == 0700 &&
    lstat(value, &socket_file) == 0 && S_ISSOCK(socket_file.st_mode) &&
    socket_file.st_uid == getuid();
}
static bool private_fixture_archive(const char *socket_path, const char *archive_path) {
  char expected[120];
  size_t prefix = strlen(socket_path) - strlen("daemon.sock");
  struct stat source;
  return snprintf(expected, sizeof expected, "%.*sarchive.data",
           (int)prefix, socket_path) < (int)sizeof expected &&
    strcmp(archive_path, expected) == 0 &&
    lstat(archive_path, &source) == 0 && S_ISREG(source.st_mode) &&
    source.st_uid == getuid() && source.st_nlink == 1 &&
    (source.st_mode & 07777) == 0600;
}
int main(int argc, char **argv) {
  if (argc != 6 || !getenv("VIRKI_DISPOSABLE_FD_TRANSPORT_TEST") ||
      strcmp(getenv("VIRKI_DISPOSABLE_FD_TRANSPORT_TEST"), "1") ||
      !private_fixture_path(argv[1]) ||
      !private_fixture_archive(argv[1], argv[2]) ||
      (strcmp(argv[4], "normal") &&
      strcmp(argv[4], "swap-fd") && strcmp(argv[4], "bad-image-id") &&
      strcmp(argv[4], "swap-midflight") &&
      strcmp(argv[4], "reattach-active") &&
      strcmp(argv[4], "slow-staging") &&
      strcmp(argv[4], "slow-write") &&
      strcmp(argv[4], "bad-digest") &&
      strcmp(argv[4], "wrong-gid") &&
      strcmp(argv[4], "poison-output")))
    return blocked();
  char *end = NULL;
  long daemon_pid = strtol(argv[3], &end, 10);
  if (!end || *end || daemon_pid <= 1 || daemon_pid > INT_MAX) return blocked();
  struct stat archive = {0};
  int archive_fd = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (archive_fd < 0 || fstat(archive_fd, &archive) ||
      !S_ISREG(archive.st_mode) || archive.st_size <= 0) {
    if (archive_fd >= 0) close(archive_fd);
    return blocked();
  }
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  if (fd < 0) { close(archive_fd); return blocked(); }
  memcpy(address.sun_path, argv[1], strlen(argv[1]) + 1);
  if (connect(fd, (struct sockaddr *)&address, sizeof address) != 0) {
    close(fd); close(archive_fd); return blocked();
  }
  struct vdt_session session = VDT_SESSION_INIT;
  bool ok = vdt_attach(&session, fd, (pid_t)daemon_pid, getuid(),
    strcmp(argv[4], "wrong-gid") == 0 ? getgid() + 1 : getgid());
  if (ok && strcmp(argv[4], "reattach-active") == 0) {
    const int pinned_fd = session.fd, pinned_pidfd = session.pidfd;
    if (vdt_attach(&session, fd, (pid_t)daemon_pid, getuid(), getgid()) ||
        session.fd != pinned_fd || session.pidfd != pinned_pidfd ||
        fcntl(pinned_fd, F_GETFD) < 0 || fcntl(pinned_pidfd, F_GETFD) < 0)
      ok = false;
  }
  if (ok && strcmp(argv[4], "swap-fd") == 0) {
    int replacement = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (replacement < 0 || connect(replacement, (struct sockaddr *)&address,
      sizeof address) != 0 || dup2(replacement, fd) < 0) ok = false;
    if (replacement >= 0) close(replacement);
  }
  char reply[4096] = {0};
  size_t length = 0;
  if (strcmp(argv[4], "poison-output") == 0) {
    memcpy(reply, "STALE", 6);
    length = 5;
  }
  if (ok) {
    ok = vdt_exchange(&session, VDT_PING, -1, 0, NULL,
                      reply, sizeof reply, &length) &&
      length == 2 && memcmp(reply, "OK", 2) == 0;
  }
  if (!ok && strcmp(argv[4], "poison-output") == 0 &&
      (reply[0] != 0 || length != 0))
    fputs("STALE_RESPONSE_RETAINED\n", stderr);
  if (ok) ok = vdt_exchange(&session, VDT_INFO, -1, 0, NULL,
                            reply, sizeof reply, &length) &&
    length > 0 && reply[0] == '{';
  if (ok && strcmp(argv[4], "swap-midflight") == 0) {
    int replacement = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (replacement < 0 || connect(replacement, (struct sockaddr *)&address,
      sizeof address) != 0 || dup2(replacement, fd) < 0) ok = false;
    if (replacement >= 0) close(replacement);
  }
  if (ok) ok = vdt_exchange(&session, VDT_LOAD, archive_fd,
                            (uint64_t)archive.st_size,
                            strcmp(argv[4], "bad-digest") == 0 ?
                            "00000000000000000000000000000000"
                            "00000000000000000000000000000000" : argv[5],
                            reply, sizeof reply, &length) &&
    length > 0 && reply[0] == '{';
  if (ok) ok = vdt_exchange(&session, VDT_IMAGE_INSPECT, -1, 0,
                            strcmp(argv[4], "bad-image-id") == 0 ?
                            "../../docker.sock" :
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            reply, sizeof reply, &length) &&
    length > 0 && reply[0] == '{';
  vdt_detach(&session);
  close(fd);
  close(archive_fd);
  if (!ok) return blocked();
  puts("{\"status\":\"DISPOSABLE_FD_TRANSPORT_ONLY\","
       "\"sameFdAcrossApiRequests\":true,"
       "\"kernelPeerAndSenderChecked\":true,"
       "\"dockerLoadAuthorized\":false,\"deployAuthorized\":false}");
  return 0;
}
