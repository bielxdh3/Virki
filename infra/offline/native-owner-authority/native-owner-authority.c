/*
 * Independent Native Owner Authority Service for Virki PR #88
 *
 * Implements:
 * 1. Independent Owner Trust Identity & SO_PEERCRED Enforcement:
 *    - Distinct owner UID vs build daemon UID vs worker UID.
 *    - Rejects root (UID 0 / GID 0).
 *    - Rejects same-UID callers in strict production mode.
 *    - Requires SO_PEERCRED on connected AF_UNIX stream/seqpacket socket.
 * 2. Anchored Directory & Symlink Rejection:
 *    - Pinned path resolution using openat() and O_NOFOLLOW from /.
 *    - Rejects symlinks, world/group-writable directories in socket/ledger paths.
 * 3. Monotonic Durable Ledger & Fencing:
 *    - Crash-safe two-phase commit (PREPARE -> FENCE -> COMMIT / ABORT).
 *    - Monotonic epoch / generation and sequence floor.
 *    - Fsyncs records and directory before granting approval.
 *    - Fences dangling/interrupted scopes via monotonic epoch advance on restart.
 * 4. Protected Secret Key Custody:
 *    - Ed25519 signing key loaded strictly from sealed file descriptor (--key-fd)
 *      or owner-owned 0400 file (--key-file).
 *    - Secret key material is NEVER accepted via argv, environment, or repository files.
 *    - Wiped from memory after use with volatile explicit_wipe.
 * 5. Sealed Context FD Verification & Dual-Digest Binding:
 *    - Receives exactly 4 descriptors via SCM_RIGHTS.
 *    - Enforces F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL and O_RDONLY.
 *    - Enforces distinct inode/dev (rejects duplicate or aliased FDs).
 *    - Streams sealed descriptor bytes to verify linear stream SHA-256.
 *    - Cryptographically signs canonical JSON ACK binding BuildKit v2 tree digests,
 *      FD stream digests, and output image ID.
 */

#define _GNU_SOURCE
#include "native-owner-authority-protocol.h"
#include "buildkit-context-abi.h"
#include "tweetnacl.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <linux/memfd.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

/* Genuine fail-closed kernel CSPRNG for TweetNaCl */
void randombytes(unsigned char *ptr, unsigned long long length);
void randombytes(unsigned char *ptr, unsigned long long length) {
  if (!ptr && length > 0) abort();
  unsigned long long offset = 0;
  while (offset < length) {
    size_t chunk = (length - offset > 256) ? 256 : (size_t)(length - offset);
    long res = syscall(SYS_getrandom, ptr + offset, chunk, 0);
    if (res > 0) {
      offset += (unsigned long long)res;
      continue;
    }
    if (res < 0 && errno == EINTR) continue;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) abort();
    while (offset < length) {
      size_t to_read = (length - offset > 256) ? 256 : (size_t)(length - offset);
      ssize_t n = read(fd, ptr + offset, to_read);
      if (n > 0) {
        offset += (unsigned long long)n;
      } else if (n < 0 && errno == EINTR) {
        continue;
      } else {
        close(fd);
        abort();
      }
    }
    close(fd);
    break;
  }
}

#include "tweetnacl.c"

static void explicit_wipe(void *ptr, size_t len) {
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len--) *p++ = 0;
}

/* Global Service Configuration */
typedef struct {
  char socket_path[1024];
  char ledger_dir[1024];
  uid_t expected_daemon_uid;
  bool has_expected_daemon_uid;
  gid_t expected_daemon_gid;
  bool has_expected_daemon_gid;
  bool allow_same_uid_dev;
  bool test_v9fs_dev;
  bool preview_only;
  int key_fd;
  char key_file[1024];
  uint8_t secret_key[64];
  uint8_t public_key[32];
  bool has_key;
  char owner_key_id[65];
} virki_owner_config_t;

static virki_owner_config_t g_cfg;
static volatile sig_atomic_t g_stop = 0;

static void handle_signal(int sig) {
  (void)sig;
  g_stop = 1;
}

#include "owner-frame-v21.h"

/* Base64 encoding */
static const char B64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static size_t base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_max) {
  size_t out_len = 4 * ((in_len + 2) / 3);
  if (out_len + 1 > out_max) return 0;
  size_t i = 0, j = 0;
  for (i = 0; i < in_len; i += 3) {
    uint32_t a = in[i];
    uint32_t b = (i + 1 < in_len) ? in[i + 1] : 0;
    uint32_t c = (i + 2 < in_len) ? in[i + 2] : 0;
    uint32_t triple = (a << 16) | (b << 8) | c;
    out[j++] = B64_CHARS[(triple >> 18) & 0x3f];
    out[j++] = B64_CHARS[(triple >> 12) & 0x3f];
    out[j++] = (i + 1 < in_len) ? B64_CHARS[(triple >> 6) & 0x3f] : '=';
    out[j++] = (i + 2 < in_len) ? B64_CHARS[triple & 0x3f] : '=';
  }
  out[j] = '\0';
  return j;
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *out_hex) {
  static const char hex_chars[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out_hex[i * 2] = hex_chars[(in[i] >> 4) & 0x0f];
    out_hex[i * 2 + 1] = hex_chars[in[i] & 0x0f];
  }
  out_hex[len * 2] = '\0';
}

static bool is_valid_hex(const char *s, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if ((s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') && (s[i] < 'A' || s[i] > 'F')) {
      return false;
    }
  }
  return true;
}

/* Nonces and owner-generated scope tokens are *binary identities encoded as
 * ASCII hex*. Accepting both A-F and a-f permits textually distinct replay
 * keys for the same 128-bit nonce. Require lowercase at BEGIN, ABORT and
 * ledger recovery; this is deliberately stricter than legacy dev clients. */
static bool is_canonical_lower_hex_v20(const char *s, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (!((s[i] >= '0' && s[i] <= '9') ||
          (s[i] >= 'a' && s[i] <= 'f'))) return false;
  }
  return true;
}

/*
 * Pinned directory resolution using openat and O_NOFOLLOW anchored at /
 */
static bool trusted_dir_fd(int fd, bool final_component, bool allow_v9fs) {
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
      (st.st_uid != 0 && st.st_uid != getuid()) ||
      (final_component && st.st_uid != getuid())) {
    return false;
  }
  if (st.st_mode & (S_IWGRP | S_IWOTH)) {
    if (!final_component && st.st_uid == 0 && (st.st_mode & S_ISVTX) != 0) {
      return true; /* root-owned sticky /tmp parent */
    }
    if (allow_v9fs) {
      struct statfs fs;
      if (fstatfs(fd, &fs) == 0 && (unsigned long)fs.f_type == 0x01021997UL) {
        return true; /* dev test-only v9fs */
      }
    }
    return false;
  }
  return true;
}

static int open_pinned_directory(const char *path, bool allow_v9fs) {
  if (!path || *path != '/' || strlen(path) > 3072) return -1;
  int dirfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (dirfd < 0) return -1;
  if (!trusted_dir_fd(dirfd, false, allow_v9fs)) { close(dirfd); return -1; }

  const char *cursor = path + 1;
  bool has_component = false;
  while (*cursor) {
    const char *end = strchr(cursor, '/');
    size_t len = end ? (size_t)(end - cursor) : strlen(cursor);
    if (len == 0 || len > NAME_MAX ||
        (len == 1 && cursor[0] == '.') ||
        (len == 2 && cursor[0] == '.' && cursor[1] == '.')) {
      close(dirfd);
      return -1;
    }
    char component[NAME_MAX + 1];
    memcpy(component, cursor, len);
    component[len] = '\0';
    const int child = openat(dirfd, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(dirfd);
    if (child < 0) return -1;
    dirfd = child;
    if (!trusted_dir_fd(dirfd, end == NULL, allow_v9fs)) {
      close(dirfd);
      return -1;
    }
    has_component = true;
    if (!end) break;
    cursor = end + 1;
    if (!*cursor) { close(dirfd); return -1; }
  }
  if (!has_component) { close(dirfd); return -1; }
  return dirfd;
}

/*
 * Durable Monotonic Ledger
 */
#define VIRKI_LEDGER_MAGIC "VIRKI_OWNER_LEDGER_V2\n"

typedef enum {
  REC_TYPE_PREPARE   = 1,
  REC_TYPE_COMMITTED = 2,
  REC_TYPE_ABORTED   = 3,
} ledger_rec_type_t;

typedef struct {
  uint32_t type;
  uint64_t epoch;
  uint64_t seq;
  char scope_token[65];
  char nonce[33];
  char image_id[73];
  uint32_t status;
} __attribute__((packed)) ledger_record_t;

typedef struct {
  uint64_t current_epoch;
  uint64_t sequence_floor;
  int ledger_fd;
  int dir_fd;
} owner_ledger_state_t;

static owner_ledger_state_t g_ledger;

/* Ledger is a local durable fence, NOT a signed/witnessed anti-rollback
 * authority. Reject structurally corrupted records before strcmp or any
 * permission to begin/abort; otherwise malformed nonce bytes can cause an
 * out-of-bounds read, or an unknown record type can be ignored at restart.
 * Native SIGN_ACK remains unconditionally denied in this DEV experiment. */
static bool ledger_zero_padded_field_v20(const char *value, size_t capacity) {
  const char *end = memchr(value, '\0', capacity);
  if (!end) return false;
  for (const char *p = end + 1; p < value + capacity; p++) {
    if (*p != '\0') return false;
  }
  return true;
}

static bool ledger_record_shape_valid(const ledger_record_t *rec) {
  if (!rec || rec->epoch == 0 || rec->seq == 0 ||
      !ledger_zero_padded_field_v20(rec->scope_token, sizeof(rec->scope_token)) ||
      !ledger_zero_padded_field_v20(rec->nonce, sizeof(rec->nonce)) ||
      !ledger_zero_padded_field_v20(rec->image_id, sizeof(rec->image_id))) return false;
  if (strcmp(rec->scope_token, "EPOCH_ADVANCE") == 0) {
    return rec->type == REC_TYPE_PREPARE && rec->status == 0 &&
           strcmp(rec->nonce, "00000000000000000000000000000000") == 0 &&
           rec->image_id[0] == '\0';
  }
  if (strlen(rec->scope_token) != 64 || !is_canonical_lower_hex_v20(rec->scope_token, 64)) return false;
  if (rec->type == REC_TYPE_PREPARE || rec->type == REC_TYPE_COMMITTED) {
    /* Older V17 DEV ledgers could legitimately store upper-case hex nonces.
     * Preserve those records on recovery, but normalize semantic replay
     * identity in V20 and refuse any new noncanonical nonce at BEGIN. */
    if (strlen(rec->nonce) != 32 || !is_valid_hex(rec->nonce, 32)) return false;
    if (rec->type == REC_TYPE_PREPARE) return rec->status == 0 && rec->image_id[0] == '\0';
    return rec->status == 0 && strncmp(rec->image_id, "sha256:", 7) == 0 &&
           strlen(rec->image_id) == 71 && is_valid_hex(rec->image_id + 7, 64);
  }
  return rec->type == REC_TYPE_ABORTED && rec->status != 0 &&
         rec->nonce[0] == '\0' && rec->image_id[0] == '\0';
}

#include "owner-ledger-replay-v20.h"

static bool ledger_init(const char *dir_path, bool allow_v9fs, owner_ledger_state_t *st) {
  memset(st, 0, sizeof(*st));
  st->ledger_fd = -1;
  st->dir_fd = open_pinned_directory(dir_path, allow_v9fs);
  if (st->dir_fd < 0) return false;

  int fd = openat(st->dir_fd, "owner_authority_ledger.dat",
                  O_RDWR | O_CREAT | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    close(st->dir_fd);
    st->dir_fd = -1;
    return false;
  }

  /* Single-owner PROCESS fence before scanning, epoch bump or touching the
   * AF_UNIX socket. A second native process must never advance the same
   * ledger epoch or replace the incumbent's socket. The lock is held by
   * ledger_fd for the entire process lifetime (including socket cleanup).
   * A hostile actor with write access to the owner-only ledger directory
   * can still rename the inode; production requires separate UID/custody. */
  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    close(fd);
    close(st->dir_fd);
    st->dir_fd = -1;
    return false;
  }
  st->ledger_fd = fd;

  /* Scan existing records to recover state */
  struct stat s;
  if (fstat(fd, &s) != 0) return false;
  if (!S_ISREG(s.st_mode) || s.st_uid != getuid() || s.st_nlink != 1 ||
      (s.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return false; /* Only owner-exclusive regular ledger with no hard links. */
  }

  uint64_t max_epoch = 0;
  uint64_t max_seq = 0;

  if (s.st_size == 0) {
    /* Initialize new ledger */
    if (write(fd, VIRKI_LEDGER_MAGIC, strlen(VIRKI_LEDGER_MAGIC)) != (ssize_t)strlen(VIRKI_LEDGER_MAGIC)) {
      return false;
    }
    if (fsync(fd) != 0 || fsync(st->dir_fd) != 0) return false;
    max_epoch = 1;
    max_seq = 1000;
  } else {
    /* Verify header */
    if (s.st_size < (off_t)strlen(VIRKI_LEDGER_MAGIC) ||
        (s.st_size - (off_t)strlen(VIRKI_LEDGER_MAGIC)) % (off_t)sizeof(ledger_record_t) != 0) {
      return false; /* Truncated ledger tail is NOT a benign clean restart. */
    }
    char hdr[32] = {0};
    lseek(fd, 0, SEEK_SET);
    if (read(fd, hdr, strlen(VIRKI_LEDGER_MAGIC)) != (ssize_t)strlen(VIRKI_LEDGER_MAGIC)) {
      return false;
    }
    if (strcmp(hdr, VIRKI_LEDGER_MAGIC) != 0) return false;

    /* Recover only an internally consistent transaction history, not a
     * collection of shape-valid but uncorrelated records. PREPARE must
     * precede exactly one terminal record, epochs and sequences must be
     * contiguous, and scope/nonce cannot be reused after restart. */
    if (!ledger_replay_verify_v20(fd, s.st_size-(off_t)strlen(VIRKI_LEDGER_MAGIC),
                                  &max_epoch, &max_seq)) return false;
    /* A durable header without records is a crash-consistent virgin ledger:
     * write the first bump as epoch=1, seq=1001, not epoch=1, seq=1. */
    if (max_epoch == UINT64_MAX || max_seq == UINT64_MAX) return false;
    if (max_epoch == 0) max_epoch = 1;
    else max_epoch++;
  }

  st->current_epoch = max_epoch;
  st->sequence_floor = max_seq;

  /* Write epoch bump record */
  ledger_record_t bump_rec = {
    .type = REC_TYPE_PREPARE,
    .epoch = st->current_epoch,
    .seq = ++st->sequence_floor,
    .status = 0,
  };
  strcpy(bump_rec.scope_token, "EPOCH_ADVANCE");
  strcpy(bump_rec.nonce, "00000000000000000000000000000000");

  if (!ledger_can_append_v20(fd, 1)) return false;
  lseek(fd, 0, SEEK_END);
  if (write(fd, &bump_rec, sizeof(bump_rec)) != (ssize_t)sizeof(bump_rec)) return false;
  if (fsync(fd) != 0 || fsync(st->dir_fd) != 0) return false;

  return true;
}

static bool ledger_record_prepare(owner_ledger_state_t *st, const char *scope_token, const char *nonce, uint64_t *out_seq) {
  if (!st || st->ledger_fd < 0 || st->sequence_floor == UINT64_MAX ||
      !ledger_can_append_v20(st->ledger_fd, 2)) return false;

  /* Check nonce uniqueness in ledger: any prior prepare, commit, or abort with same nonce rejects */
  lseek(st->ledger_fd, strlen(VIRKI_LEDGER_MAGIC), SEEK_SET);
  ledger_record_t scan;
  ssize_t n;
  while ((n = read(st->ledger_fd, &scan, sizeof(scan))) == (ssize_t)sizeof(scan)) {
    if (!ledger_record_shape_valid(&scan)) return false;
    if (ledger_replay_hex_equal_v20(scan.nonce, nonce) ||
        strcmp(scan.scope_token, scope_token) == 0) {
      return false; /* Nonce replayed! */
    }
  }
  if (n != 0) return false;

  /* Record prepare intent */
  uint64_t seq = st->sequence_floor + 1;
  ledger_record_t rec = {
    .type = REC_TYPE_PREPARE,
    .epoch = st->current_epoch,
    .seq = seq,
    .status = 0,
  };
  snprintf(rec.scope_token, sizeof(rec.scope_token), "%s", scope_token);
  snprintf(rec.nonce, sizeof(rec.nonce), "%s", nonce);

  if (lseek(st->ledger_fd, 0, SEEK_END) < 0) return false;
  if (write(st->ledger_fd, &rec, sizeof(rec)) != (ssize_t)sizeof(rec)) return false;
  if (fsync(st->ledger_fd) != 0 || fsync(st->dir_fd) != 0) return false;

  st->sequence_floor = seq;
  *out_seq = seq;
  return true;
}

static bool ledger_record_commit(owner_ledger_state_t *st, const char *scope_token, const char *nonce, const char *image_id, uint64_t seq) {
  if (!st || st->ledger_fd < 0 || !ledger_can_append_v20(st->ledger_fd, 2)) return false;

  ledger_record_t rec = {
    .type = REC_TYPE_COMMITTED,
    .epoch = st->current_epoch,
    .seq = seq,
    .status = 0,
  };
  snprintf(rec.scope_token, sizeof(rec.scope_token), "%s", scope_token);
  snprintf(rec.nonce, sizeof(rec.nonce), "%s", nonce);
  snprintf(rec.image_id, sizeof(rec.image_id), "%s", image_id);

  lseek(st->ledger_fd, 0, SEEK_END);
  if (write(st->ledger_fd, &rec, sizeof(rec)) != (ssize_t)sizeof(rec)) return false;
  if (fsync(st->ledger_fd) != 0) return false;
  if (fsync(st->dir_fd) != 0) return false;

  return true;
}

/* Diagnostic-only scope-state lookup. A reservation is NOT C4 signing
 * authority. Unknown, stale, committed, aborted or truncated records must
 * never appear as a live prepared scope. */
static int ledger_scope_state(owner_ledger_state_t *st, const char *scope_token, const char *expected_nonce) {
  if (!st || st->ledger_fd < 0) return -1;
  if (lseek(st->ledger_fd, strlen(VIRKI_LEDGER_MAGIC), SEEK_SET) < 0) return -1;
  ledger_record_t rec;
  int state = 0;
  ssize_t n;
  while ((n = read(st->ledger_fd, &rec, sizeof(rec))) > 0) {
    if (n != (ssize_t)sizeof(rec) || !ledger_record_shape_valid(&rec)) return -1;
    if (strcmp(rec.scope_token, scope_token) != 0) continue;
    if (rec.epoch != st->current_epoch) return 2;
    if (rec.type == REC_TYPE_PREPARE) {
      if (state != 0) return -1;
      if (!expected_nonce || strcmp(rec.nonce, expected_nonce) != 0) return -1;
      state = 1;
    } else if (rec.type == REC_TYPE_ABORTED || rec.type == REC_TYPE_COMMITTED) {
      if (state != 1) return -1;
      state = 2;
    } else return -1;
  }
  if (n < 0) return -1;
  return state;
}

static bool ledger_record_abort(owner_ledger_state_t *st, const char *scope_token, const char *nonce, uint32_t reason) {
  if (!st || st->ledger_fd < 0 || st->sequence_floor == UINT64_MAX ||
      !ledger_can_append_v20(st->ledger_fd, 2)) return false;
	if (ledger_scope_state(st,scope_token,nonce)!=1) return false;

  uint64_t next_seq = st->sequence_floor + 1;
  ledger_record_t rec = {
    .type = REC_TYPE_ABORTED,
    .epoch = st->current_epoch,
    .seq = next_seq,
    .status = reason,
  };
  snprintf(rec.scope_token, sizeof(rec.scope_token), "%s", scope_token);

  if (lseek(st->ledger_fd, 0, SEEK_END) < 0) return false;
  if (write(st->ledger_fd, &rec, sizeof(rec)) != (ssize_t)sizeof(rec)) return false;
  if (fsync(st->ledger_fd) != 0 || fsync(st->dir_fd) != 0) return false;

  st->sequence_floor = next_seq;
  return true;
}

static bool read_exact_key_bytes(int fd, uint8_t out[64]) {
  size_t off = 0;
  while (off < 64) {
    ssize_t n = read(fd, out + off, 64 - off);
    if (n > 0) {
      off += (size_t)n;
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else {
      explicit_wipe(out, 64);
      return false;
    }
  }
  return true;
}

/*
 * Load Ed25519 Secret Key
 */
static bool load_signing_key(virki_owner_config_t *cfg) {
  if (cfg->key_fd >= 0) {
    struct stat st;
    if (cfg->key_fd <= 2 || fstat(cfg->key_fd, &st) != 0 ||
        (!S_ISREG(st.st_mode) && !S_ISFIFO(st.st_mode))) {
      close(cfg->key_fd);
      cfg->key_fd = -1;
      return false;
    }
    bool ok = read_exact_key_bytes(cfg->key_fd, cfg->secret_key);
    close(cfg->key_fd);
    cfg->key_fd = -1;
    if (!ok) return false;
    memcpy(cfg->public_key, cfg->secret_key + 32, 32);
    cfg->has_key = true;
    return true;
  }
  if (cfg->key_file[0] != '\0') {
    int fd = open(cfg->key_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
      close(fd);
      return false;
    }
    if ((st.st_mode & 0777) != 0400 || st.st_uid != getuid()) {
      /* Refuse unless explicitly running on a WSL v9fs dev mount */
      struct statfs fs;
      if (!cfg->test_v9fs_dev || fstatfs(fd, &fs) != 0 ||
          (unsigned long)fs.f_type != 0x01021997UL) {
        close(fd);
        return false;
      }
    }
    if (!read_exact_key_bytes(fd, cfg->secret_key)) {
      close(fd);
      return false;
    }
    close(fd);
    memcpy(cfg->public_key, cfg->secret_key + 32, 32);
    cfg->has_key = true;
    return true;
  }
  return false;
}

static void close_fds(int fds[VIRKI_OWNER_CONTEXT_COUNT]) {
  for (int i = 0; i < VIRKI_OWNER_CONTEXT_COUNT; i++) {
    if (fds[i] >= 0) {
      close(fds[i]);
      fds[i] = -1;
    }
  }
}

/*
 * Format Canonical JSON ACK Payload
 */
static int format_canonical_ack_json_v2(const virki_owner_request_frame_t *req,
                                        uint64_t seq,
                                        char observed_streams[VIRKI_OWNER_CONTEXT_COUNT][73],
                                        char *out, size_t max_len) {
  return snprintf(out, max_len,
    "{"
    "\"version\":2,"
    "\"status\":\"BUILD_RESULT_AND_CONTEXTS_ACKNOWLEDGED\","
    "\"approvalEnvelopeSha256\":\"%s\","
    "\"approvalKeyId\":\"%s\","
    "\"approvalId\":\"%s\","
    "\"approvalSerial\":\"%s\","
    "\"jobId\":\"%s\","
    "\"role\":\"%s\","
    "\"nonce\":\"%s\","
    "\"ownerIdentity\":\"%s\","
    "\"workerIdentity\":\"%s\","
    "\"sourceCommit\":\"%s\","
    "\"buildPlanSha256\":\"%s\","
    "\"executablePolicySha256\":\"%s\","
    "\"imageId\":\"%s\","
    "\"archiveSha256\":\"%s\","
    "\"archiveBytes\":%" PRIu64 ","
    "\"transcriptSha256\":\"%s\","
    "\"sequenceNumber\":%" PRIu64 ","
    "\"contextDigests\":{"
      "\"source\":\"%s\","
      "\"dockerfile\":\"%s\","
      "\"offline-npm-cacache\":\"%s\","
      "\"offline-prisma-engines\":\"%s\""
    "},"
    "\"contextStreamDigests\":{"
      "\"source\":\"%s\","
      "\"dockerfile\":\"%s\","
      "\"offline-npm-cacache\":\"%s\","
      "\"offline-prisma-engines\":\"%s\""
    "}"
    "}",
    req->approval_envelope_sha256,
    g_cfg.owner_key_id,
    req->approval_id,
    req->approval_serial,
    req->job_id,
    req->role,
    req->nonce,
    "virki-owner-authority-v2",
    "virki-worker-c1",
    req->source_commit,
    req->build_plan_sha256,
    req->executable_policy_sha256,
    req->output_image_id,
    req->archive_sha256,
    req->archive_bytes,
    req->transcript_sha256,
    seq,
    req->expected_tree_digests[0],
    req->expected_tree_digests[1],
    req->expected_tree_digests[2],
    req->expected_tree_digests[3],
    observed_streams[0],
    observed_streams[1],
    observed_streams[2],
    observed_streams[3]
  );
}

/*
 * Process incoming client connection
 */
static void process_client_connection(int client_fd) {
  /* The server handles AF_UNIX peers serially. An authorized but idle peer
   * MUST NOT pin the only owner listener, block an independent abort, or
   * prevent SIGTERM from releasing the exclusive owner ledger flock.
   * Bound both receive and send, and respect the shutdown flag on EINTR. */
  struct timeval io_deadline = { .tv_sec = 2, .tv_usec = 0 };
  if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &io_deadline, sizeof(io_deadline)) != 0 ||
      setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &io_deadline, sizeof(io_deadline)) != 0) {
    return;
  }
  virki_owner_response_frame_t resp = {0};
  memcpy(resp.magic, VIRKI_OWNER_PROTOCOL_MAGIC, sizeof(resp.magic));
  resp.version = VIRKI_OWNER_PROTOCOL_VERSION;

  /* 1. Verify SO_PEERCRED before exposing any ledger or key metadata */
  struct ucred peer;
  socklen_t peer_len = sizeof(peer);
  if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) != 0 ||
      peer_len != sizeof(peer)) {
    resp.status = VIRKI_OWNER_STATUS_ERR_PEERCRED;
    (void)owner_send_response_v21(client_fd, &resp);
    return;
  }

  /* Refuse root */
  if (peer.uid == 0 || peer.gid == 0 || peer.pid <= 1) {
    resp.status = VIRKI_OWNER_STATUS_ERR_PEERCRED;
    (void)owner_send_response_v21(client_fd, &resp);
    return;
  }

  /* Refuse same-UID in strict production mode */
  if (!g_cfg.allow_same_uid_dev && peer.uid == getuid()) {
    resp.status = VIRKI_OWNER_STATUS_ERR_PEERCRED;
    (void)owner_send_response_v21(client_fd, &resp);
    return;
  }

  /* Verify expected daemon UID if configured */
  if (g_cfg.has_expected_daemon_uid && peer.uid != g_cfg.expected_daemon_uid) {
    resp.status = VIRKI_OWNER_STATUS_ERR_PEERCRED;
    (void)owner_send_response_v21(client_fd, &resp);
    return;
  }

  /* V23: socket DAC membership is NOT a peer identity proof. A client
   * with the pinned daemon UID but a foreign primary GID may connect
   * through a supplementary group. When --daemon-gid is explicitly set,
   * require that exact SO_PEERCRED primary GID as well. This deliberately
   * tightens the prior UID-only DEV contract; no signing is enabled. */
  if (g_cfg.has_expected_daemon_gid && peer.gid != g_cfg.expected_daemon_gid) {
    resp.status = VIRKI_OWNER_STATUS_ERR_PEERCRED;
    (void)owner_send_response_v21(client_fd, &resp);
    return;
  }

  /* Populate ledger/key metadata only for authenticated peers */
  resp.epoch = g_ledger.current_epoch;
  resp.sequence_number = g_ledger.sequence_floor;
  snprintf(resp.owner_key_id, sizeof(resp.owner_key_id), "%s", g_cfg.owner_key_id);

  /* 2. Receive Request Frame & Optional SCM_RIGHTS FDs */
  virki_owner_request_frame_t req = {0};
  int fds[VIRKI_OWNER_CONTEXT_COUNT] = {-1, -1, -1, -1};

  size_t extracted_fd_count=0;
  const bool complete_frame=owner_receive_exact_frame_v21(
      client_fd,&req,fds,&extracted_fd_count,2000);
  if (!complete_frame ||
      (req.cmd != VIRKI_OWNER_CMD_SIGN_ACK && extracted_fd_count != 0) ||
      memcmp(req.magic, VIRKI_OWNER_PROTOCOL_MAGIC, sizeof(req.magic)) != 0 ||
      req.version != VIRKI_OWNER_PROTOCOL_VERSION ||
      !memchr(req.nonce, '\0', sizeof(req.nonce)) ||
      !memchr(req.scope_token, '\0', sizeof(req.scope_token)) ||
      !memchr(req.job_id, '\0', sizeof(req.job_id)) ||
      !memchr(req.session_id, '\0', sizeof(req.session_id)) ||
      !memchr(req.role, '\0', sizeof(req.role)) ||
      !memchr(req.source_commit, '\0', sizeof(req.source_commit)) ||
      !memchr(req.build_plan_sha256, '\0', sizeof(req.build_plan_sha256)) ||
      !memchr(req.executable_policy_sha256, '\0', sizeof(req.executable_policy_sha256)) ||
      !memchr(req.output_image_id, '\0', sizeof(req.output_image_id)) ||
      !memchr(req.archive_sha256, '\0', sizeof(req.archive_sha256)) ||
      !memchr(req.transcript_sha256, '\0', sizeof(req.transcript_sha256)) ||
      !memchr(req.approval_key_id, '\0', sizeof(req.approval_key_id)) ||
      !memchr(req.approval_id, '\0', sizeof(req.approval_id)) ||
      !memchr(req.approval_serial, '\0', sizeof(req.approval_serial)) ||
      !memchr(req.approval_envelope_sha256, '\0', sizeof(req.approval_envelope_sha256))) {
    close_fds(fds);
    resp.status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
    (void)owner_send_response_v21(client_fd, &resp);
    return;
  }

  /* 3. Dispatch Command */
  switch (req.cmd) {
    case VIRKI_OWNER_CMD_STATUS: {
      close_fds(fds);
      resp.status = VIRKI_OWNER_STATUS_OK;
      (void)owner_send_response_v21(client_fd, &resp);
      break;
    }

    case VIRKI_OWNER_CMD_SCOPE_BEGIN: {
      close_fds(fds);
      if (req.epoch != g_ledger.current_epoch) {
        resp.status = VIRKI_OWNER_STATUS_ERR_STALE_EPOCH;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }
      if (strlen(req.nonce) != 32 || !is_canonical_lower_hex_v20(req.nonce, 32)) {
        resp.status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }
      /* Generate random scope token */
      uint8_t token_bytes[32];
      randombytes(token_bytes, 32);
      char scope_token[65];
      bytes_to_hex(token_bytes, 32, scope_token);

      uint64_t seq = 0;
      if (!ledger_record_prepare(&g_ledger, scope_token, req.nonce, &seq)) {
        resp.status = VIRKI_OWNER_STATUS_ERR_NONCE_REPLAY;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }

      resp.status = VIRKI_OWNER_STATUS_OK;
      resp.sequence_number = seq;
      snprintf(resp.scope_token, sizeof(resp.scope_token), "%s", scope_token);
      (void)owner_send_response_v21(client_fd, &resp);
      break;
    }

    case VIRKI_OWNER_CMD_SCOPE_ABORT: {
      close_fds(fds);
	  if (req.epoch != g_ledger.current_epoch) {
	    resp.status = VIRKI_OWNER_STATUS_ERR_STALE_EPOCH;
	    (void)owner_send_response_v21(client_fd, &resp);
	    return;
	  }
	  if (strlen(req.nonce)!=32 || !is_canonical_lower_hex_v20(req.nonce,32)) {
	    resp.status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
	    (void)owner_send_response_v21(client_fd, &resp);
	    return;
	  }
      if (strlen(req.scope_token)!=64 || !is_canonical_lower_hex_v20(req.scope_token,64)) {
        resp.status = VIRKI_OWNER_STATUS_ERR_SCOPE_NOT_FOUND;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }
      int state = ledger_scope_state(&g_ledger,req.scope_token,req.nonce);
      if (state != 1) {
        resp.status = state == 2 ? VIRKI_OWNER_STATUS_ERR_SCOPE_ABORTED :
            (state == 0 ? VIRKI_OWNER_STATUS_ERR_SCOPE_NOT_FOUND : VIRKI_OWNER_STATUS_ERR_LEDGER_TAMPER);
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }
      if (!ledger_record_abort(&g_ledger,req.scope_token,req.nonce,1)) {
        resp.status = VIRKI_OWNER_STATUS_ERR_LEDGER_TAMPER;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }
      resp.status = VIRKI_OWNER_STATUS_OK;
      (void)owner_send_response_v21(client_fd, &resp);
      break;
    }

    case VIRKI_OWNER_CMD_SIGN_ACK: {
      /* HARD RELEASE GATE — V16: the v2 frame has no authenticated BuildKit
       * session/source refs, typed OCI descriptor/DAG, selected ignore and
       * filtered FileSync V15 manifest, verified independently by this
       * authority. Scope BEGIN merely reserves a nonce and is NOT an
       * authorization to sign. Therefore *all* signature requests are
       * denied, even with valid keys, sealed FDs and a prepared scope.
       *
       * This cannot be overridden by a CLI/env flag or a caller header.
       * Leave the old signer body unreachable for forensic provenance while
       * redesigning the native protocol and durable verified transaction.
       */
      const bool native_c4_verified_signer_ready = false;
      if (!native_c4_verified_signer_ready) {
        close_fds(fds);
        resp.status = VIRKI_OWNER_STATUS_ERR_SIGNING_DISABLED;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }
      if (!g_cfg.has_key) {
        close_fds(fds);
        resp.status = VIRKI_OWNER_STATUS_ERR_NO_KEY;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }
      if (req.epoch != g_ledger.current_epoch) {
        close_fds(fds);
        resp.status = VIRKI_OWNER_STATUS_ERR_STALE_EPOCH;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }
      if (extracted_fd_count != VIRKI_OWNER_CONTEXT_COUNT) {
        close_fds(fds);
        resp.status = VIRKI_OWNER_STATUS_ERR_FD_INVALID;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }

      /* Validate 4 descriptors */
      struct stat st[VIRKI_OWNER_CONTEXT_COUNT];
      for (int i = 0; i < VIRKI_OWNER_CONTEXT_COUNT; i++) {
        int fd = fds[i];
        int fl = fcntl(fd, F_GETFL);
        if (fl < 0 || (fl & O_ACCMODE) != O_RDONLY) {
          close_fds(fds);
          resp.status = VIRKI_OWNER_STATUS_ERR_FD_INVALID;
          (void)owner_send_response_v21(client_fd, &resp);
          return;
        }
        int seals = fcntl(fd, F_GET_SEALS);
        int req_seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        if (seals < 0 || (seals & req_seals) != req_seals) {
          close_fds(fds);
          resp.status = VIRKI_OWNER_STATUS_ERR_FD_INVALID;
          (void)owner_send_response_v21(client_fd, &resp);
          return;
        }
        if (fstat(fd, &st[i]) != 0 || !S_ISREG(st[i].st_mode)) {
          close_fds(fds);
          resp.status = VIRKI_OWNER_STATUS_ERR_FD_INVALID;
          (void)owner_send_response_v21(client_fd, &resp);
          return;
        }
        if ((uint64_t)st[i].st_size != req.expected_stream_lengths[i]) {
          close_fds(fds);
          resp.status = VIRKI_OWNER_STATUS_ERR_FD_INVALID;
          (void)owner_send_response_v21(client_fd, &resp);
          return;
        }
        /* Check distinct dev / inode across descriptors */
        for (int j = 0; j < i; j++) {
          if (st[i].st_dev == st[j].st_dev && st[i].st_ino == st[j].st_ino) {
            close_fds(fds);
            resp.status = VIRKI_OWNER_STATUS_ERR_FD_INVALID;
            (void)owner_send_response_v21(client_fd, &resp);
            return;
          }
        }
      }

      /* Stream and verify linear SHA-256 for all 4 context descriptors */
      char observed_streams[VIRKI_OWNER_CONTEXT_COUNT][73];
      for (int i = 0; i < VIRKI_OWNER_CONTEXT_COUNT; i++) {
        uint64_t measured_bytes = 0;
        if (!virki_hash_flat_fd(fds[i], observed_streams[i], &measured_bytes)) {
          close_fds(fds);
          resp.status = VIRKI_OWNER_STATUS_ERR_STREAM_MISMATCH;
          (void)owner_send_response_v21(client_fd, &resp);
          return;
        }
        if (strcmp(observed_streams[i], req.expected_stream_digests[i]) != 0) {
          close_fds(fds);
          resp.status = VIRKI_OWNER_STATUS_ERR_STREAM_MISMATCH;
          (void)owner_send_response_v21(client_fd, &resp);
          return;
        }
      }

      /* Context descriptors consumed and verified */
      close_fds(fds);

      /* Validate output image ID format */
      if (strncmp(req.output_image_id, "sha256:", 7) != 0 ||
          strlen(req.output_image_id) != 71 ||
          !is_valid_hex(req.output_image_id + 7, 64)) {
        resp.status = VIRKI_OWNER_STATUS_ERR_PROVENANCE_FAIL;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }

      /* Monotonic sequence for this commitment */
      uint64_t seq = ++g_ledger.sequence_floor;

      /* Format Canonical Signed ACK JSON */
      char ack_json[4096];
      int json_len = format_canonical_ack_json_v2(&req, seq, observed_streams, ack_json, sizeof(ack_json));
      if (json_len <= 0 || json_len >= (int)sizeof(ack_json)) {
        resp.status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }

      /* Compute Ed25519 signature */
      unsigned long long smlen = 0;
      uint8_t sm[sizeof(ack_json) + 64];
      crypto_sign(sm, &smlen, (const unsigned char *)ack_json, (unsigned long long)json_len, g_cfg.secret_key);

      uint8_t sig_raw[64];
      memcpy(sig_raw, sm, 64);
      char sig_b64[128];
      base64_encode(sig_raw, 64, sig_b64, sizeof(sig_b64));

      /* Commit to durable ledger */
      if (!ledger_record_commit(&g_ledger, req.scope_token, req.nonce, req.output_image_id, seq)) {
        resp.status = VIRKI_OWNER_STATUS_ERR_LEDGER_TAMPER;
        (void)owner_send_response_v21(client_fd, &resp);
        return;
      }

      /* Compute SHA-256 of canonical ACK JSON */
      virki_abi_sha256_ctx ack_ctx;
      virki_abi_sha256_init(&ack_ctx);
      virki_abi_sha256_update(&ack_ctx, (const uint8_t *)ack_json, (size_t)json_len);
      uint8_t ack_sha[32];
      virki_abi_sha256_final(&ack_ctx, ack_sha);
      char ack_sha_hex[65];
      bytes_to_hex(ack_sha, 32, ack_sha_hex);

      /* Build Response */
      resp.status = VIRKI_OWNER_STATUS_OK;
      resp.sequence_number = seq;
      snprintf(resp.signature_base64, sizeof(resp.signature_base64), "%s", sig_b64);
      snprintf(resp.canonical_ack_sha256, sizeof(resp.canonical_ack_sha256), "%s", ack_sha_hex);
      resp.ack_json_len = (uint32_t)json_len;
      memcpy(resp.ack_json, ack_json, json_len);
      resp.ack_json[json_len] = '\0';

      (void)owner_send_response_v21(client_fd, &resp);
      break;
    }

    default: {
      close_fds(fds);
      resp.status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
      (void)owner_send_response_v21(client_fd, &resp);
      break;
    }
  }
}

static void print_preview(const virki_owner_config_t *cfg) {
  printf("=== VIRKI INDEPENDENT OWNER AUTHORITY SERVICE INSTALL PREVIEW ===\n");
  printf("Role: Independent Owner Trust Anchor & Fencing Authority\n");
  printf("Target Socket: %s (mode 0660 or 0600)\n", cfg->socket_path);
  printf("Ledger Directory: %s (mode 0700, strict owner UID)\n", cfg->ledger_dir);
  printf("Owner UID: %d (must be distinct from build daemon UID)\n", (int)getuid());
  if (cfg->has_expected_daemon_uid) {
    printf("Expected Daemon UID: %d (separate non-root build service)\n", (int)cfg->expected_daemon_uid);
  } else {
    printf("Expected Daemon UID: NOT CONFIGURED (STRICT MODE REFUSES TO START)\n");
  }
  if (cfg->has_expected_daemon_gid) {
    printf("Expected Daemon GID: %u (group socket mode 0660; SO_PEERCRED UID still pinned)\n",
           (unsigned)cfg->expected_daemon_gid);
  } else {
    printf("Socket mode: 0600 (no cross-UID listener until owner configures daemon group)\n");
  }
  printf("Dev Same-UID Allowed: %s\n", cfg->allow_same_uid_dev ? "YES (DEV-ONLY TEST HARNESS)" : "NO (FAIL CLOSED)");
  printf("Key Custody: %s\n", cfg->has_key ? "VALID KEY LOADED" : "NO KEY SPECIFIED");
  printf("Key ID: %s\n", cfg->owner_key_id);
  printf("=== END INSTALL PREVIEW ===\n");
}

int main(int argc, char **argv) {
  memset(&g_cfg, 0, sizeof(g_cfg));
  g_cfg.key_fd = -1;
  strcpy(g_cfg.owner_key_id, "virki-owner-prod-candidate-key-01");

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--socket") && i + 1 < argc) {
      int n = snprintf(g_cfg.socket_path, sizeof(g_cfg.socket_path), "%s", argv[++i]);
      if (n < 0 || (size_t)n >= sizeof(g_cfg.socket_path)) {
        fputs("Error: --socket path too long\n", stderr);
        return 2;
      }
    } else if (!strcmp(argv[i], "--ledger-dir") && i + 1 < argc) {
      int n = snprintf(g_cfg.ledger_dir, sizeof(g_cfg.ledger_dir), "%s", argv[++i]);
      if (n < 0 || (size_t)n >= sizeof(g_cfg.ledger_dir)) {
        fputs("Error: --ledger-dir path too long\n", stderr);
        return 2;
      }
    } else if (!strcmp(argv[i], "--daemon-uid") && i + 1 < argc) {
      const char *value = argv[++i];
      char *end = NULL;
      errno = 0;
      unsigned long number = strtoul(value, &end, 10);
      if (errno != 0 || !value[0] || !end || *end != '\0' ||
          number == 0 || number > UINT32_MAX || number == (unsigned long)getuid()) {
        fputs("Error: --daemon-uid must pin a different non-root numeric UID\n", stderr);
        return 2;
      }
      g_cfg.expected_daemon_uid = (uid_t)number;
      g_cfg.has_expected_daemon_uid = true;
    } else if (!strcmp(argv[i], "--daemon-gid") && i + 1 < argc) {
      const char *value = argv[++i];
      char *end = NULL;
      errno = 0;
      unsigned long number = strtoul(value, &end, 10);
      if (errno != 0 || !value[0] || !end || *end != '\0' ||
          number == 0 || number > UINT32_MAX) {
        fputs("Error: --daemon-gid must pin a non-root numeric GID\n", stderr);
        return 2;
      }
      g_cfg.expected_daemon_gid = (gid_t)number;
      g_cfg.has_expected_daemon_gid = true;
    } else if (!strcmp(argv[i], "--dev-allow-same-uid")) {
      g_cfg.allow_same_uid_dev = true;
    } else if (!strcmp(argv[i], "--dev-test-v9fs")) {
      g_cfg.test_v9fs_dev = true;
    } else if (!strcmp(argv[i], "--key-fd") && i + 1 < argc) {
      const char *value = argv[++i];
      char *end = NULL;
      errno = 0;
      long fd_num = strtol(value, &end, 10);
      if (errno != 0 || !value[0] || !end || *end != '\0' || fd_num <= 2 || fd_num > INT_MAX) {
        fputs("Error: --key-fd must be a valid descriptor > 2\n", stderr);
        return 2;
      }
      g_cfg.key_fd = (int)fd_num;
    } else if (!strcmp(argv[i], "--key-file") && i + 1 < argc) {
      int n = snprintf(g_cfg.key_file, sizeof(g_cfg.key_file), "%s", argv[++i]);
      if (n < 0 || (size_t)n >= sizeof(g_cfg.key_file)) {
        fputs("Error: --key-file path too long\n", stderr);
        return 2;
      }
    } else if (!strcmp(argv[i], "--key-id") && i + 1 < argc) {
      int n = snprintf(g_cfg.owner_key_id, sizeof(g_cfg.owner_key_id), "%s", argv[++i]);
      if (n < 0 || (size_t)n >= sizeof(g_cfg.owner_key_id)) {
        fputs("Error: --key-id too long\n", stderr);
        return 2;
      }
    } else if (!strcmp(argv[i], "--preview-only")) {
      g_cfg.preview_only = true;
    } else {
      fprintf(stderr, "Unknown or invalid option: %s\n", argv[i]);
      return 2;
    }
  }

  if (g_cfg.preview_only) {
    print_preview(&g_cfg);
    return 0;
  }

  if (g_cfg.socket_path[0] == '\0' || g_cfg.ledger_dir[0] == '\0') {
    fputs("Error: --socket <path> and --ledger-dir <path> are required\n", stderr);
    return 2;
  }

  /* Never start a strict owner on an ANY-UID policy. An open socket in a
   * 0755 traversable directory is not an authorization credential: the
   * daemon UID must be independent and exactly configured. Group access to
   * connect is separately optional and NEVER replaces SO_PEERCRED UID. */
  if (!g_cfg.allow_same_uid_dev &&
      (!g_cfg.has_expected_daemon_uid || getuid() == 0 || geteuid() != getuid())) {
    fputs("Error: strict owner requires --daemon-uid and non-root owner UID\n", stderr);
    return 2;
  }
  if (g_cfg.has_expected_daemon_gid && !g_cfg.has_expected_daemon_uid) {
    fputs("Error: --daemon-gid requires pinned --daemon-uid\n", stderr);
    return 2;
  }
  /* AF_UNIX bind uses current umask; ensure its inode is private from the
   * beginning, not merely chmod'd after a world-accessible creation window. */
  umask(0077);

  /* Load secret key if specified; fail closed if an explicit key source is invalid */
  if ((g_cfg.key_fd >= 0 || g_cfg.key_file[0] != '\0') && !load_signing_key(&g_cfg)) {
    explicit_wipe(g_cfg.secret_key, sizeof(g_cfg.secret_key));
    fputs("Error: failed to load owner signing key from --key-fd/--key-file\n", stderr);
    return 2;
  }

  /* Initialize durable ledger */
  if (!ledger_init(g_cfg.ledger_dir, g_cfg.test_v9fs_dev, &g_ledger)) {
    explicit_wipe(g_cfg.secret_key, sizeof(g_cfg.secret_key));
    fputs("Error: Failed to initialize durable monotonic ledger (check permissions or v9fs flag)\n", stderr);
    return 2;
  }

  /* Setup signal handler */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_signal;
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);

  /* Open socket directory and bind AF_UNIX socket */
  if (strlen(g_cfg.socket_path) >= 1024) {
    fputs("Error: socket path too long\n", stderr);
    return 2;
  }
  char sock_dir[1024];
  memcpy(sock_dir, g_cfg.socket_path, strlen(g_cfg.socket_path) + 1);
  char *last_slash = strrchr(sock_dir, '/');
  if (!last_slash || last_slash[1] == '\0') {
    explicit_wipe(g_cfg.secret_key, sizeof(g_cfg.secret_key));
    fputs("Error: socket path must be absolute with a non-empty filename\n", stderr);
    return 2;
  }
  *last_slash = '\0';
  const char *sock_name = last_slash + 1;

  int sock_dir_fd = open_pinned_directory(sock_dir, g_cfg.test_v9fs_dev);
  if (sock_dir_fd < 0) {
    fputs("Error: socket parent directory is untrusted or unpinned\n", stderr);
    return 2;
  }

  unlinkat(sock_dir_fd, sock_name, 0);

  int server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_sock < 0) {
    close(sock_dir_fd);
    return 2;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  if (strlen(g_cfg.socket_path) >= sizeof(sun.sun_path)) {
    close(server_sock);
    close(sock_dir_fd);
    fputs("Error: socket path exceeds sockaddr_un capacity\n", stderr);
    return 2;
  }
  memcpy(sun.sun_path, g_cfg.socket_path, strlen(g_cfg.socket_path) + 1);

  if (bind(server_sock, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    close(server_sock);
    close(sock_dir_fd);
    fputs("Error: bind failed on owner socket\n", stderr);
    return 2;
  }

  /* Authenticated transport requires inode-level permissions before listen.
   * An explicitly configured daemon group permits cross-UID CONNECT; every
   * connected peer is STILL checked for the exact expected daemon UID. */
  const mode_t socket_mode = g_cfg.has_expected_daemon_gid ? 0660 : 0600;
  if ((g_cfg.has_expected_daemon_gid &&
       fchownat(sock_dir_fd, sock_name, (uid_t)-1,
                g_cfg.expected_daemon_gid, AT_SYMLINK_NOFOLLOW) != 0) ||
      fchmodat(sock_dir_fd, sock_name, socket_mode, 0) != 0) {
    close(server_sock);
    unlinkat(sock_dir_fd, sock_name, 0);
    close(sock_dir_fd);
    fputs("Error: failed to restrict owner socket inode permissions\n", stderr);
    return 2;
  }
  struct stat socket_stat;
  if (fstatat(sock_dir_fd, sock_name, &socket_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
      !S_ISSOCK(socket_stat.st_mode) || socket_stat.st_uid != getuid() ||
      (socket_stat.st_mode & 0777) != socket_mode ||
      (g_cfg.has_expected_daemon_gid &&
       socket_stat.st_gid != g_cfg.expected_daemon_gid)) {
    close(server_sock);
    unlinkat(sock_dir_fd, sock_name, 0);
    close(sock_dir_fd);
    fputs("Error: owner socket inode did not retain pinned UID/GID/mode\n", stderr);
    return 2;
  }

  if (listen(server_sock, 16) != 0) {
    close(server_sock);
    close(sock_dir_fd);
    return 2;
  }

  printf("VIRKI_OWNER_AUTHORITY_READY: epoch=%" PRIu64 " seq=%" PRIu64 " socket=%s\n",
         g_ledger.current_epoch, g_ledger.sequence_floor, g_cfg.socket_path);
  fflush(stdout);

  /* Event loop */
  while (!g_stop) {
    struct pollfd pfd = { .fd = server_sock, .events = POLLIN, .revents = 0 };
    int ret = poll(&pfd, 1, 1000);
    if (ret > 0 && (pfd.revents & POLLIN)) {
      int client = accept4(server_sock, NULL, NULL, SOCK_CLOEXEC);
      if (client >= 0) {
        process_client_connection(client);
        close(client);
      }
    }
  }

  /* Cleanup */
  close(server_sock);
  unlinkat(sock_dir_fd, sock_name, 0);
  close(sock_dir_fd);
  if (g_ledger.ledger_fd >= 0) close(g_ledger.ledger_fd);
  if (g_ledger.dir_fd >= 0) close(g_ledger.dir_fd);

  /* Wipe key from memory */
  explicit_wipe(g_cfg.secret_key, sizeof(g_cfg.secret_key));

  return 0;
}
