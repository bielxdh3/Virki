/*
 * DISPOSABLE Linux-only two-image integration exercise.
 * Reuses the reviewed FD transport and an existing isolated test daemon peer.
 * This program is intentionally impossible to build without a fixture define,
 * accepts only randomized /tmp fixture paths, and grants no host authority.
 * Real host installation still requires independent owner custody and service.
 */
#ifndef VIRKI_DISPOSABLE_MANUAL_BATCH
#error This helper is a disposable test fixture only
#endif
#define _GNU_SOURCE
#include "native-docker-fd-transport.h"
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

struct entry {
  const char *role, *image, *digest;
  int fd;
  uint64_t size;
  char load_sha[65];
  char *inspect_base64;
};
static int test_held_writer = -1;
static bool hex(const char *value, size_t n) {
  if (!value || strnlen(value, n + 1) != n) return false;
  for (size_t i = 0; i < n; i++)
    if (!((value[i] >= '0' && value[i] <= '9') ||
          (value[i] >= 'a' && value[i] <= 'f'))) return false;
  return true;
}
static bool private_dir(const char *directory) {
  static const char prefix[] = "/tmp/virki-native-manual-";
  size_t n = sizeof prefix - 1;
  if (!directory || strlen(directory) != n + 6 ||
      strncmp(directory, prefix, n)) return false;
  for (size_t i = n; i < n + 6; i++) {
    char c = directory[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9'))) return false;
  }
  struct stat st;
  return lstat(directory, &st) == 0 && S_ISDIR(st.st_mode) &&
    st.st_uid == getuid() && (st.st_mode & 07777) == 0700;
}
static bool open_image(const char *dir, struct entry *e,
                       bool hold_writer, bool use_named_source,
                       uint64_t force_sparse_size, bool hash_sparse_extension) {
  char pathname[128];
  struct stat before, after;
  if (snprintf(pathname, sizeof pathname, "%s/%s.data", dir, e->role) >=
      (int)sizeof pathname) return false;
  if (lstat(pathname, &before) || !S_ISREG(before.st_mode) ||
      before.st_nlink != 1 || before.st_uid != getuid() ||
      (before.st_mode & 07777) != 0600 || before.st_size <= 0 ||
      before.st_size > 64 * 1024 * 1024) return false;
  int source = open(pathname, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (source < 0 || fstat(source, &after) ||
      before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
      before.st_size != after.st_size ||
      before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
      before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
      before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
      before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
    if (source >= 0) close(source);
    return false;
  }
  e->size = (uint64_t)after.st_size;
  if (use_named_source) {
    e->fd = source;
    return true;
  }
  /* Rehearse a disk-backed O_TMPFILE copy: original pathname can be mutated
   * later without altering the fully detached, previously verified bytes. */
  int staging = open(dir, O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
  if (staging < 0) { close(source); return false; }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { close(source); close(staging); return false; }
  unsigned char block[65536], hash[EVP_MAX_MD_SIZE];
  unsigned outlen = 0;
  bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
  for (uint64_t pos = 0; ok && pos < e->size;) {
    size_t count = e->size - pos > sizeof block ? sizeof block : (size_t)(e->size - pos);
    ssize_t got = pread(source, block, count, (off_t)pos);
    ok = got > 0 && EVP_DigestUpdate(ctx, block, (size_t)got) == 1;
    if (ok) {
      ssize_t written = pwrite(staging, block, (size_t)got, (off_t)pos);
      ok = written == got;
      if (ok) pos += (size_t)got;
    }
  }
  if (ok && hash_sparse_extension && force_sparse_size > e->size) {
    static const unsigned char zeros[65536] = {0};
    for (uint64_t remaining = force_sparse_size - e->size; ok && remaining;) {
      size_t step = remaining > sizeof zeros ? sizeof zeros : (size_t)remaining;
      ok = EVP_DigestUpdate(ctx, zeros, step) == 1;
      remaining -= step;
    }
  }
  if (ok) ok = EVP_DigestFinal_ex(ctx, hash, &outlen) == 1 && outlen == 32;
  EVP_MD_CTX_free(ctx);
  if (!ok) { close(source); close(staging); return false; }
  char computed[65];
  for (unsigned i = 0; i < 32; i++) snprintf(computed + 2 * i, 3, "%02x", hash[i]);
  if (force_sparse_size > e->size &&
      (force_sparse_size > 8ULL * 1024 * 1024 * 1024 ||
       ftruncate(staging, (off_t)force_sparse_size))) {
    close(source); close(staging); return false;
  }
  if (force_sparse_size > e->size) e->size = force_sparse_size;
  if (strcmp(computed, e->digest) || lstat(pathname, &after) ||
      after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
      after.st_size != before.st_size || fsync(staging)) {
    close(source); close(staging); return false;
  }
  close(source);
  char anonymous[64];
  if (snprintf(anonymous, sizeof anonymous, "/proc/self/fd/%d", staging) >=
      (int)sizeof anonymous) { close(staging); return false; }
  e->fd = open(anonymous, O_RDONLY | O_CLOEXEC);
  if (hold_writer) test_held_writer = staging;
  else close(staging);
  if (e->fd < 0 || fstat(e->fd, &after) || !S_ISREG(after.st_mode) ||
      after.st_nlink != 0 || (after.st_mode & 07777) != 0600 ||
      (uint64_t)after.st_size != e->size) return false;
  return true;
}
static bool load_and_inspect(struct vdt_session *session, struct entry *entry) {
  char response[256 * 1024 + 1];
  size_t length = 0;
  if (!vdt_exchange_detached(session, entry->fd, entry->size,
                            entry->digest, response, sizeof response, &length)) return false;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned hashlen = 0;
  if (!EVP_Digest(response, length, hash, &hashlen, EVP_sha256(), NULL) ||
      hashlen != 32) return false;
  for (unsigned i = 0; i < 32; i++)
    snprintf(entry->load_sha + 2 * i, 3, "%02x", hash[i]);
  if (!vdt_exchange(session, VDT_IMAGE_INSPECT, -1, 0, entry->image + 7,
                    response, sizeof response, &length) || length == 0) return false;
  entry->inspect_base64 = malloc(((length + 2) / 3) * 4 + 1);
  if (!entry->inspect_base64) return false;
  int count = EVP_EncodeBlock((unsigned char *)entry->inspect_base64,
    (const unsigned char *)response, (int)length);
  return count > 0 && (size_t)count == ((length + 2) / 3) * 4;
}
int main(int argc, char **argv) {
  struct entry entries[2] = {
    {.role = "runtime", .fd = -1}, {.role = "migrator", .fd = -1},
  };
  struct vdt_session session = VDT_SESSION_INIT;
  int sock = -1, rc = 2;
  if ((argc != 8 && argc != 9) || !getenv("VIRKI_DISPOSABLE_MANUAL_BATCH") ||
      strcmp(getenv("VIRKI_DISPOSABLE_MANUAL_BATCH"), "1") ||
      !private_dir(argv[1]) || !hex(argv[3], 40)) goto end;
  bool held_writer = argc == 9 && !strcmp(argv[8], "hold-writer");
  bool named_source = argc == 9 && !strcmp(argv[8], "named-source");
  bool large_runtime = argc == 9 && !strcmp(argv[8], "large-runtime");
  bool large_migrator = argc == 9 && !strcmp(argv[8], "large-migrator");
  bool large_stream = argc == 9 && !strcmp(argv[8], "large-stream");
  if (argc == 9 && !held_writer && !named_source &&
      !large_runtime && !large_migrator && !large_stream) goto end;
  char *last = NULL;
  long pid = strtol(argv[2], &last, 10);
  if (!last || *last || pid <= 1 || pid > INT_MAX) goto end;
  for (int i = 0; i < 2; i++) {
    entries[i].image = argv[4 + i];
    entries[i].digest = argv[6 + i];
    if (strlen(entries[i].image) != 71 ||
        strncmp(entries[i].image, "sha256:", 7) ||
        !hex(entries[i].image + 7, 64) || !hex(entries[i].digest, 64) ||
        !open_image(argv[1], &entries[i],
                    i == 0 && held_writer, i == 0 && named_source,
                    i == 0 && large_runtime ? 959170560ULL :
                      i == 0 && large_migrator ? 1330946048ULL :
                        i == 0 && large_stream ? (64ULL * 1024 * 1024 + 512) : 0,
                    i == 0 && large_stream)) goto end;
  }
  if (!strcmp(entries[0].image, entries[1].image) ||
      !strcmp(entries[0].digest, entries[1].digest)) goto end;
  char socket_path[108];
  if (snprintf(socket_path, sizeof socket_path, "%s/daemon.sock", argv[1]) >=
      (int)sizeof socket_path) goto end;
  struct stat st;
  if (lstat(socket_path, &st) || !S_ISSOCK(st.st_mode) ||
      st.st_uid != getuid()) goto end;
  sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  if (sock < 0) goto end;
  memcpy(addr.sun_path, socket_path, strlen(socket_path) + 1);
  if (connect(sock, (struct sockaddr *)&addr, sizeof addr) ||
      !vdt_attach(&session, sock, (pid_t)pid, getuid(), getgid())) goto end;
  char response[8192];
  size_t len = 0;
  if (!vdt_exchange(&session, VDT_PING, -1, 0, NULL,
                    response, sizeof response, &len) ||
      len != 2 || memcmp(response, "OK", 2)) goto end;
  if (!vdt_exchange(&session, VDT_INFO, -1, 0, NULL,
                    response, sizeof response, &len) ||
      len == 0 || response[0] != '{') goto end;
  for (int i = 0; i < 2; i++)
    if (!load_and_inspect(&session, &entries[i])) goto end;
  printf("{\"status\":\"DISPOSABLE_NATIVE_BATCH_COMPLETE\",\"sourceSha\":\"%s\",", argv[3]);
  for (int i = 0; i < 2; i++) {
    struct entry *e = &entries[i];
    printf("\"%s\":{\"role\":\"%s\",\"imageId\":\"%s\","
           "\"archiveSha256\":\"%s\",\"loadReceiptSha256\":\"%s\","
           "\"inspectBase64\":\"%s\"},", e->role, e->role, e->image,
           e->digest, e->load_sha, e->inspect_base64);
  }
  if (test_held_writer >= 0) close(test_held_writer);
  puts("\"dockerLoadAuthorized\":false,\"deployAuthorized\":false}");
  rc = 0;
end:
  vdt_detach(&session);
  if (sock >= 0) close(sock);
  for (int i = 0; i < 2; i++) {
    if (entries[i].fd >= 0) close(entries[i].fd);
    free(entries[i].inspect_base64);
  }
  if (rc) puts("{\"status\":\"BLOCKED_DISPOSABLE_BATCH_UNCERTAIN\","
               "\"dockerLoadAuthorized\":false,\"deployAuthorized\":false}");
  return rc;
}
