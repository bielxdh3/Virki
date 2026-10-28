/*
 * Disposable, Linux-only AF_UNIX read-only diagnostic.
 *
 * Inherits an already-connected socket on FD 3. Never opens an endpoint,
 * invokes Docker, or uses a Docker CLI. The only HTTP requests in this entry
 * point are GET /_ping and GET /v1.45/info over the SAME kernel socket FD.
 * It refuses all normal daemon paths and accepts only a private, disposable
 * /tmp/virki-readonly-fd-XXXXXX/daemon.sock listener belonging to our uid.
 *
 * PID, starttime and listener socket inode here are TEST fixture pins supplied
 * by the developer harness, NOT independent owner-provisioned authorization.
 * There is no attested daemon executable, secure host policy, native cgroup
 * isolation, service lifecycle or delegated release authority. Even success
 * is NOT_AUTHORIZED, and this tool is never suitable for production import.
 */
#define _GNU_SOURCE
#include "native-docker-fd-transport.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef VDT_DISPOSABLE_READONLY
#error This entry point must only be built as a disposable read-only fixture
#endif

#define INHERITED_SOCKET_FD 3

static int refuse(void) {
  puts("{\"status\":\"NOT_AUTHORIZED\",\"diagnosticOk\":false,"
       "\"dockerLoadAuthorized\":false,\"deployAuthorized\":false}");
  return 2;
}

static bool decimal(const char *value, unsigned long long *out) {
  if (!value || value[0] < '1' || value[0] > '9' ||
      strnlen(value, 24) >= 24) return false;
  for (size_t i = 1; value[i]; i++)
    if (value[i] < '0' || value[i] > '9') return false;
  errno = 0;
  char *end = NULL;
  unsigned long long number = strtoull(value, &end, 10);
  if (errno || !end || *end || !number) return false;
  *out = number;
  return true;
}

static bool process_start(pid_t pid, unsigned long long *out) {
  char filename[80], raw[8192];
  if (snprintf(filename, sizeof filename, "/proc/%ld/stat", (long)pid) >=
      (int)sizeof filename) return false;
  FILE *file = fopen(filename, "re");
  if (!file) return false;
  bool ok = fgets(raw, sizeof raw, file) && !ferror(file);
  fclose(file);
  if (!ok) return false;
  char *end = strrchr(raw, ')');
  if (!end || end[1] != ' ') return false;
  char *save = NULL, *word = strtok_r(end + 2, " \n", &save);
  for (int i = 0; i < 19 && word; i++)
    word = strtok_r(NULL, " \n", &save);
  return word && decimal(word, out);
}

/* The full fixture socket pathname is an observation only; never connect to
 * or open it. A path supplied via symlink, shared parent or host Docker path
 * cannot pass these checks even if an FD were handed in with SCM_RIGHTS. */
static bool disposable_endpoint(const char *socket_path) {
  static const char prefix[] = "/tmp/virki-readonly-fd-";
  static const char suffix[] = "/daemon.sock";
  const size_t prefix_len = sizeof prefix - 1, suffix_len = sizeof suffix - 1;
  if (!socket_path || strnlen(socket_path, 256) >= 256 ||
      strlen(socket_path) != prefix_len + 6 + suffix_len ||
      strncmp(socket_path, prefix, prefix_len) ||
      strcmp(socket_path + prefix_len + 6, suffix)) return false;
  for (size_t i = 0; i < 6; i++) {
    char c = socket_path[prefix_len + i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9'))) return false;
  }
  char directory[128];
  if (snprintf(directory, sizeof directory, "%.*s",
               (int)(prefix_len + 6), socket_path) >= (int)sizeof directory)
    return false;
  struct stat parent, endpoint;
  return lstat(directory, &parent) == 0 && S_ISDIR(parent.st_mode) &&
    parent.st_uid == geteuid() && (parent.st_mode & 07777) == 0700 &&
    lstat(socket_path, &endpoint) == 0 && S_ISSOCK(endpoint.st_mode) &&
    endpoint.st_uid == geteuid() && (endpoint.st_mode & 07777) == 0600;
}

/* Cross-check independently supplied listener inode against the kernel's
 * /proc/PID/net/unix and a LISTEN FD actually held by the pinned peer PID.
 * The accepted connection inode differs from the listening socket inode.
 */
static bool listener_owner(pid_t pid, unsigned long long inode,
                           const char *socket_path) {
  char directory[80];
  if (snprintf(directory, sizeof directory, "/proc/%ld/fd", (long)pid) >=
      (int)sizeof directory) return false;
  DIR *fds = opendir(directory);
  if (!fds) return false;
  char target[80];
  if (snprintf(target, sizeof target, "socket:[%llu]", inode) >=
      (int)sizeof target) {
    closedir(fds);
    return false;
  }
  bool owns = false;
  struct dirent *entry;
  while ((entry = readdir(fds))) {
    char filepath[160], held[96];
    if (snprintf(filepath, sizeof filepath, "%s/%s",
                 directory, entry->d_name) >= (int)sizeof filepath) continue;
    ssize_t n = readlink(filepath, held, sizeof held - 1);
    if (n <= 0 || (size_t)n >= sizeof held - 1) continue;
    held[n] = 0;
    if (strcmp(held, target) == 0) { owns = true; break; }
  }
  closedir(fds);
  if (!owns) return false;
  char unix_table[80];
  if (snprintf(unix_table, sizeof unix_table,
               "/proc/%ld/net/unix", (long)pid) >= (int)sizeof unix_table)
    return false;
  FILE *file = fopen(unix_table, "re");
  if (!file) return false;
  char line[1024];
  bool exact = false;
  int matches = 0;
  while (fgets(line, sizeof line, file)) {
    char index[32], refcount[32], protocol[32], flags[32], type[32],
      state[32], raw_inode[32], path[256];
    int parsed = sscanf(line, "%31s %31s %31s %31s %31s %31s %31s %255s",
      index, refcount, protocol, flags, type, state, raw_inode, path);
    if (parsed != 8) continue;
    unsigned long long parsed_inode = 0;
    if (decimal(raw_inode, &parsed_inode) && parsed_inode == inode) {
      matches++;
      exact = strcmp(flags, "00010000") == 0 &&
        strcmp(type, "0001") == 0 && strcmp(state, "01") == 0 &&
        strcmp(path, socket_path) == 0;
    }
  }
  bool complete = !ferror(file);
  fclose(file);
  return complete && matches == 1 && exact;
}

int main(int argc, char **argv) {
  if (argc != 5 || !getenv("VIRKI_DISPOSABLE_DOCKER_RO_BRIDGE_TEST") ||
      strcmp(getenv("VIRKI_DISPOSABLE_DOCKER_RO_BRIDGE_TEST"), "1") ||
      !disposable_endpoint(argv[4])) return refuse();

  unsigned long long pid = 0, start = 0, inode = 0, observed = 0;
  if (!decimal(argv[1], &pid) || pid <= 1 || pid > INT_MAX ||
      !decimal(argv[2], &start) || !decimal(argv[3], &inode) ||
      !process_start((pid_t)pid, &observed) || observed != start ||
      !listener_owner((pid_t)pid, inode, argv[4])) return refuse();

  struct vdt_session session = VDT_SESSION_INIT;
  bool ok = vdt_attach(&session, INHERITED_SOCKET_FD, (pid_t)pid,
                       geteuid(), getegid());
  char body[4096] = {0};
  size_t size = 0;
  if (ok) ok = vdt_exchange(&session, VDT_PING, -1, 0, NULL,
                            body, sizeof body, &size) &&
               size == 2 && memcmp(body, "OK", 2) == 0;
  if (ok) ok = listener_owner((pid_t)pid, inode, argv[4]) &&
               vdt_exchange(&session, VDT_INFO, -1, 0, NULL,
                            body, sizeof body, &size) &&
               size >= 2 && body[0] == '{' && body[size - 1] == '}';
  if (ok) ok = listener_owner((pid_t)pid, inode, argv[4]) &&
               process_start((pid_t)pid, &observed) && observed == start;
  vdt_detach(&session);
  if (!ok) return refuse();
  /* Deliberately do not print daemon-controlled response bytes as evidence. */
  puts("{\"status\":\"NOT_AUTHORIZED\",\"diagnosticOk\":true,"
       "\"sameFdReadOnly\":true,\"independentDaemonPolicyVerified\":false,"
       "\"isolatedLifecycleVerified\":false,"
       "\"dockerLoadAuthorized\":false,\"deployAuthorized\":false}");
  return 0;
}
