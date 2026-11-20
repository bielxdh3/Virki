#ifndef VIRKI_BUILDKIT_CONTEXT_ABI_H
#define VIRKI_BUILDKIT_CONTEXT_ABI_H

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define VIRKI_BUILDKIT_ABI_VERSION_1 1
#define VIRKI_BUILDKIT_ABI_VERSION_2 2
#define VIRKI_BUILDKIT_ABI_VERSION VIRKI_BUILDKIT_ABI_VERSION_2

#define VIRKI_BUILDKIT_TREE_PREFIX_V1 "buildkit-worker-local-context-v1\x00"
#define VIRKI_BUILDKIT_TREE_PREFIX_V1_LEN 33
#define VIRKI_BUILDKIT_TREE_PREFIX_V2 "buildkit-worker-local-context-v2\x00"
#define VIRKI_BUILDKIT_TREE_PREFIX_V2_LEN 33

#define VIRKI_BUILDKIT_TREE_PREFIX VIRKI_BUILDKIT_TREE_PREFIX_V2
#define VIRKI_BUILDKIT_TREE_PREFIX_LEN VIRKI_BUILDKIT_TREE_PREFIX_V2_LEN

typedef struct {
  char name[32];
  char digest[72];             /* "sha256:<64 hex>" */
  uint64_t regular_file_bytes;
  uint64_t entry_count;
} virki_buildkit_local_context_observation_t;

/* Dual-digest context observation: binds v2 tree digest and linear FD stream digest */
typedef struct {
  char name[32];
  char tree_digest[72];        /* "sha256:<64 hex>" (BuildKit v2 canonical tree digest) */
  char stream_digest[72];      /* "sha256:<64 hex>" (Linear stream SHA-256 of sealed FD bytes) */
  uint64_t regular_file_bytes;
  uint64_t stream_bytes;
  uint64_t entry_count;
} virki_context_dual_digest_t;

typedef struct {
  uint32_t version;
  char role[16];               /* "runtime" | "migrator" */
  char session_id[64];
  char vertex_digest[72];      /* "sha256:<hex>" */
  char snapshot_id[64];        /* immutable committed cache snapshot */
  char output_image_id[72];    /* "sha256:<hex>" */
  virki_buildkit_local_context_observation_t observations[4];
} virki_buildkit_consumption_contract_t;

/* --- Internal RFC 6234 SHA-256 for ABI --- */
typedef struct {
  uint32_t state[8];
  uint64_t count;
  uint8_t buffer[64];
} virki_abi_sha256_ctx;

#define ABI_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ABI_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define ABI_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define ABI_SIG0(x) (ABI_ROTR(x, 2) ^ ABI_ROTR(x, 13) ^ ABI_ROTR(x, 22))
#define ABI_SIG1(x) (ABI_ROTR(x, 6) ^ ABI_ROTR(x, 11) ^ ABI_ROTR(x, 25))
#define ABI_sig0(x) (ABI_ROTR(x, 7) ^ ABI_ROTR(x, 18) ^ ((x) >> 3))
#define ABI_sig1(x) (ABI_ROTR(x, 17) ^ ABI_ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t ABI_K256[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline void virki_abi_sha256_init(virki_abi_sha256_ctx *ctx) {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->count = 0;
}

static inline void virki_abi_sha256_transform(uint32_t state[8], const uint8_t *data) {
  uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
  for (unsigned i = 0, j = 0; i < 16; i++, j += 4)
    m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
           ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
  for (unsigned i = 16; i < 64; i++)
    m[i] = ABI_sig1(m[i - 2]) + m[i - 7] + ABI_sig0(m[i - 15]) + m[i - 16];
  a = state[0]; b = state[1]; c = state[2]; d = state[3];
  e = state[4]; f = state[5]; g = state[6]; h = state[7];
  for (unsigned i = 0; i < 64; i++) {
    t1 = h + ABI_SIG1(e) + ABI_CH(e, f, g) + ABI_K256[i] + m[i];
    t2 = ABI_SIG0(a) + ABI_MAJ(a, b, c);
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static inline void virki_abi_sha256_update(virki_abi_sha256_ctx *ctx, const uint8_t *data, size_t len) {
  size_t idx = (size_t)((ctx->count >> 3) & 63);
  ctx->count += (uint64_t)len << 3;
  size_t part_len = 64 - idx;
  size_t i = 0;
  if (len >= part_len) {
    memcpy(&ctx->buffer[idx], data, part_len);
    virki_abi_sha256_transform(ctx->state, ctx->buffer);
    for (i = part_len; i + 63 < len; i += 64)
      virki_abi_sha256_transform(ctx->state, &data[i]);
    idx = 0;
  }
  memcpy(&ctx->buffer[idx], &data[i], len - i);
}

static inline void virki_abi_sha256_final(virki_abi_sha256_ctx *ctx, uint8_t digest[32]) {
  uint8_t final_count[8];
  for (unsigned i = 0; i < 8; i++)
    final_count[i] = (uint8_t)((ctx->count >> ((7 - i) * 8)) & 0xff);
  virki_abi_sha256_update(ctx, (const uint8_t *)"\x80", 1);
  while ((ctx->count & 504) != 448)
    virki_abi_sha256_update(ctx, (const uint8_t *)"\0", 1);
  virki_abi_sha256_update(ctx, final_count, 8);
  for (unsigned i = 0; i < 8; i++) {
    digest[i * 4] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
    digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
    digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
    digest[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xff);
  }
}

static inline void virki_abi_write_uint64(virki_abi_sha256_ctx *ctx, uint64_t v) {
  uint8_t be[8];
  for (int i = 7; i >= 0; i--) {
    be[i] = (uint8_t)(v & 0xff);
    v >>= 8;
  }
  virki_abi_sha256_update(ctx, be, 8);
}

static inline void virki_abi_write_sized(virki_abi_sha256_ctx *ctx, const uint8_t *data, size_t len) {
  virki_abi_write_uint64(ctx, (uint64_t)len);
  virki_abi_sha256_update(ctx, data, len);
}

/*
 * Matches Go localContextModeBits(mode os.FileMode):
 * extracts standard permissions (0777) plus setuid (04000), setgid (02000), sticky (01000).
 */
static inline uint64_t virki_abi_mode_bits(mode_t mode) {
  uint64_t bits = (uint64_t)(mode & 0777);
  if (mode & S_ISUID) bits |= 04000;
  if (mode & S_ISGID) bits |= 02000;
  if (mode & S_ISVTX) bits |= 01000;
  return bits;
}

/* Tree Entry Representation */
enum virki_abi_entry_type {
  VIRKI_ABI_DIR = 1,
  VIRKI_ABI_LINK = 2,
  VIRKI_ABI_REG = 3,
};

typedef struct {
  char rel_path[1024];
  enum virki_abi_entry_type type;
  uint64_t size;
  uint64_t mode;
  char link_target[1024];
  uint8_t file_sha[32];
} virki_abi_entry_t;

static inline int compare_entry_names(const void *a, const void *b) {
  const char *na = *(const char *const *)a;
  const char *nb = *(const char *const *)b;
  return strcmp(na, nb);
}

static inline void free_entry_names(char **names, size_t count) {
  for (size_t i = 0; i < count; i++) {
    free(names[i]);
  }
  free(names);
}

/* Depth-first traversal sorting each directory's basenames lexically, matching Go filepath.WalkDir. */
static inline bool collect_tree_entries(const char *root, const char *sub,
                                        virki_abi_entry_t **entries, size_t *count, size_t *cap) {
  char current_dir[2048];
  int dir_n;
  if (sub && sub[0]) {
    dir_n = snprintf(current_dir, sizeof(current_dir), "%s/%s", root, sub);
  } else {
    dir_n = snprintf(current_dir, sizeof(current_dir), "%s", root);
  }
  if (dir_n < 0 || (size_t)dir_n >= sizeof(current_dir)) return false;

  DIR *d = opendir(current_dir);
  if (!d) return false;

  char **names = NULL;
  size_t name_count = 0;
  size_t name_cap = 0;
  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
    if (name_count >= name_cap) {
      size_t next_cap = (name_cap == 0) ? 16 : (name_cap * 2);
      char **next_names = realloc(names, next_cap * sizeof(char *));
      if (!next_names) {
        free_entry_names(names, name_count);
        closedir(d);
        return false;
      }
      names = next_names;
      name_cap = next_cap;
    }
    size_t dlen = strlen(de->d_name);
    char *copy = malloc(dlen + 1);
    if (!copy) {
      free_entry_names(names, name_count);
      closedir(d);
      return false;
    }
    memcpy(copy, de->d_name, dlen + 1);
    names[name_count++] = copy;
  }
  closedir(d);

  if (name_count > 1) {
    qsort(names, name_count, sizeof(char *), compare_entry_names);
  }

  for (size_t i = 0; i < name_count; i++) {
    char rel[1024];
    int rel_n;
    if (sub && sub[0]) {
      rel_n = snprintf(rel, sizeof(rel), "%s/%s", sub, names[i]);
    } else {
      rel_n = snprintf(rel, sizeof(rel), "%s", names[i]);
    }
    if (rel_n < 0 || (size_t)rel_n >= sizeof(rel)) {
      free_entry_names(names, name_count);
      return false;
    }

    char full[2048];
    int full_n = snprintf(full, sizeof(full), "%s/%s", root, rel);
    if (full_n < 0 || (size_t)full_n >= sizeof(full)) {
      free_entry_names(names, name_count);
      return false;
    }

    struct stat st;
    if (lstat(full, &st) != 0) {
      free_entry_names(names, name_count);
      return false;
    }

    if (*count >= *cap) {
      *cap = (*cap == 0) ? 64 : (*cap * 2);
      virki_abi_entry_t *next_entries = realloc(*entries, *cap * sizeof(virki_abi_entry_t));
      if (!next_entries) {
        free_entry_names(names, name_count);
        return false;
      }
      *entries = next_entries;
    }

    virki_abi_entry_t *e = &(*entries)[*count];
    memset(e, 0, sizeof(*e));
    size_t rel_len = strlen(rel);
    if (rel_len >= sizeof(e->rel_path)) {
      free_entry_names(names, name_count);
      return false;
    }
    memcpy(e->rel_path, rel, rel_len);
    e->rel_path[rel_len] = '\0';
    e->mode = virki_abi_mode_bits(st.st_mode);

    if (S_ISDIR(st.st_mode)) {
      e->type = VIRKI_ABI_DIR;
      (*count)++;
      if (!collect_tree_entries(root, rel, entries, count, cap)) {
        free_entry_names(names, name_count);
        return false;
      }
    } else if (S_ISLNK(st.st_mode)) {
      e->type = VIRKI_ABI_LINK;
      ssize_t len = readlink(full, e->link_target, sizeof(e->link_target));
      if (len < 0 || (size_t)len >= sizeof(e->link_target)) {
        free_entry_names(names, name_count);
        return false;
      }
      e->link_target[len] = '\0';
      (*count)++;
    } else if (S_ISREG(st.st_mode)) {
      e->type = VIRKI_ABI_REG;
      e->size = (uint64_t)st.st_size;

      int fd = open(full, O_RDONLY | O_CLOEXEC);
      if (fd < 0) {
        free_entry_names(names, name_count);
        return false;
      }
      virki_abi_sha256_ctx fctx;
      virki_abi_sha256_init(&fctx);
      uint8_t buf[4096];
      ssize_t n;
      while ((n = read(fd, buf, sizeof(buf))) > 0) {
        virki_abi_sha256_update(&fctx, buf, (size_t)n);
      }
      close(fd);
      if (n < 0) {
        free_entry_names(names, name_count);
        return false;
      }
      virki_abi_sha256_final(&fctx, e->file_sha);
      (*count)++;
    } else {
      /* Unsupported file type */
      free_entry_names(names, name_count);
      return false;
    }
  }
  free_entry_names(names, name_count);
  return true;
}

/*
 * BuildKit local-source canonical observation (v2 format with mode bits).
 * Matches BuildKit v0.34.1 patch session/filesync/localcontext.go observeLocalContext.
 */
static inline bool virki_observe_local_context_v2(const char *root, const char *context_name,
                                                  virki_buildkit_local_context_observation_t *out) {
  if (!root || !context_name || !out) return false;
  memset(out, 0, sizeof(*out));
  snprintf(out->name, sizeof(out->name), "%s", context_name);

  struct stat st;
  if (lstat(root, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
    return false;
  }

  virki_abi_entry_t *entries = NULL;
  size_t count = 0;
  size_t cap = 0;
  if (!collect_tree_entries(root, "", &entries, &count, &cap)) {
    free(entries);
    return false;
  }

  /* Tree hash initialized with v2 prefix */
  virki_abi_sha256_ctx tree_ctx;
  virki_abi_sha256_init(&tree_ctx);
  virki_abi_sha256_update(&tree_ctx, (const uint8_t *)VIRKI_BUILDKIT_TREE_PREFIX_V2, VIRKI_BUILDKIT_TREE_PREFIX_V2_LEN);

  for (size_t i = 0; i < count; i++) {
    const virki_abi_entry_t *e = &entries[i];
    switch (e->type) {
      case VIRKI_ABI_DIR: {
        const uint8_t tag = 'D';
        virki_abi_sha256_update(&tree_ctx, &tag, 1);
        virki_abi_write_sized(&tree_ctx, (const uint8_t *)e->rel_path, strlen(e->rel_path));
        virki_abi_write_uint64(&tree_ctx, e->mode);
        out->entry_count++;
        break;
      }
      case VIRKI_ABI_LINK: {
        const uint8_t tag = 'L';
        virki_abi_sha256_update(&tree_ctx, &tag, 1);
        virki_abi_write_sized(&tree_ctx, (const uint8_t *)e->rel_path, strlen(e->rel_path));
        virki_abi_write_uint64(&tree_ctx, e->mode);
        virki_abi_write_sized(&tree_ctx, (const uint8_t *)e->link_target, strlen(e->link_target));
        out->entry_count++;
        break;
      }
      case VIRKI_ABI_REG: {
        const uint8_t tag = 'F';
        virki_abi_sha256_update(&tree_ctx, &tag, 1);
        virki_abi_write_sized(&tree_ctx, (const uint8_t *)e->rel_path, strlen(e->rel_path));
        virki_abi_write_uint64(&tree_ctx, e->mode);
        virki_abi_write_uint64(&tree_ctx, e->size);
        virki_abi_sha256_update(&tree_ctx, e->file_sha, 32);
        out->regular_file_bytes += e->size;
        out->entry_count++;
        break;
      }
      default:
        free(entries);
        return false;
    }
  }

  free(entries);

  uint8_t final_digest[32];
  virki_abi_sha256_final(&tree_ctx, final_digest);

  static const char hex[] = "0123456789abcdef";
  char hex_buf[65];
  for (size_t i = 0; i < 32; i++) {
    hex_buf[i * 2] = hex[final_digest[i] >> 4];
    hex_buf[i * 2 + 1] = hex[final_digest[i] & 0x0f];
  }
  hex_buf[64] = '\0';
  snprintf(out->digest, sizeof(out->digest), "sha256:%s", hex_buf);

  return true;
}

/* BuildKit v1 canonical observation (omits mode bits; preserved for comparison/legacy) */
static inline bool virki_observe_local_context_v1(const char *root, const char *context_name,
                                                  virki_buildkit_local_context_observation_t *out) {
  if (!root || !context_name || !out) return false;
  memset(out, 0, sizeof(*out));
  snprintf(out->name, sizeof(out->name), "%s", context_name);

  struct stat st;
  if (lstat(root, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
    return false;
  }

  virki_abi_entry_t *entries = NULL;
  size_t count = 0;
  size_t cap = 0;
  if (!collect_tree_entries(root, "", &entries, &count, &cap)) {
    free(entries);
    return false;
  }

  virki_abi_sha256_ctx tree_ctx;
  virki_abi_sha256_init(&tree_ctx);
  virki_abi_sha256_update(&tree_ctx, (const uint8_t *)VIRKI_BUILDKIT_TREE_PREFIX_V1, VIRKI_BUILDKIT_TREE_PREFIX_V1_LEN);

  for (size_t i = 0; i < count; i++) {
    const virki_abi_entry_t *e = &entries[i];
    switch (e->type) {
      case VIRKI_ABI_DIR: {
        const uint8_t tag = 'D';
        virki_abi_sha256_update(&tree_ctx, &tag, 1);
        virki_abi_write_sized(&tree_ctx, (const uint8_t *)e->rel_path, strlen(e->rel_path));
        out->entry_count++;
        break;
      }
      case VIRKI_ABI_LINK: {
        const uint8_t tag = 'L';
        virki_abi_sha256_update(&tree_ctx, &tag, 1);
        virki_abi_write_sized(&tree_ctx, (const uint8_t *)e->rel_path, strlen(e->rel_path));
        virki_abi_write_sized(&tree_ctx, (const uint8_t *)e->link_target, strlen(e->link_target));
        out->entry_count++;
        break;
      }
      case VIRKI_ABI_REG: {
        const uint8_t tag = 'F';
        virki_abi_sha256_update(&tree_ctx, &tag, 1);
        virki_abi_write_sized(&tree_ctx, (const uint8_t *)e->rel_path, strlen(e->rel_path));
        virki_abi_write_uint64(&tree_ctx, e->size);
        virki_abi_sha256_update(&tree_ctx, e->file_sha, 32);
        out->regular_file_bytes += e->size;
        out->entry_count++;
        break;
      }
      default:
        free(entries);
        return false;
    }
  }

  free(entries);

  uint8_t final_digest[32];
  virki_abi_sha256_final(&tree_ctx, final_digest);

  static const char hex[] = "0123456789abcdef";
  char hex_buf[65];
  for (size_t i = 0; i < 32; i++) {
    hex_buf[i * 2] = hex[final_digest[i] >> 4];
    hex_buf[i * 2 + 1] = hex[final_digest[i] & 0x0f];
  }
  hex_buf[64] = '\0';
  snprintf(out->digest, sizeof(out->digest), "sha256:%s", hex_buf);

  return true;
}

/* Default observation function delegates to canonical v2 */
static inline bool virki_observe_local_context(const char *root, const char *context_name,
                                               virki_buildkit_local_context_observation_t *out) {
  return virki_observe_local_context_v2(root, context_name, out);
}

/* Computes linear stream SHA-256 and total bytes from an open descriptor */
static inline bool virki_hash_flat_fd(int fd, char out_sha256[72], uint64_t *out_bytes) {
  if (fd < 0 || !out_sha256) return false;
  if (lseek(fd, 0, SEEK_SET) != 0) return false;

  virki_abi_sha256_ctx ctx;
  virki_abi_sha256_init(&ctx);
  uint8_t buf[4096];
  uint64_t total = 0;
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    virki_abi_sha256_update(&ctx, buf, (size_t)n);
    total += (uint64_t)n;
  }
  if (n < 0) return false;

  uint8_t digest[32];
  virki_abi_sha256_final(&ctx, digest);

  static const char hex[] = "0123456789abcdef";
  strcpy(out_sha256, "sha256:");
  for (size_t i = 0; i < 32; i++) {
    out_sha256[7 + i * 2] = hex[digest[i] >> 4];
    out_sha256[7 + i * 2 + 1] = hex[digest[i] & 0x0f];
  }
  out_sha256[71] = '\0';

  if (out_bytes) *out_bytes = total;
  return true;
}

/* Computes both canonical v2 tree digest and linear FD stream digest */
static inline bool virki_compute_context_dual_digest(const char *root, int fd,
                                                     const char *context_name,
                                                     virki_context_dual_digest_t *out) {
  if (!root || !context_name || !out) return false;
  memset(out, 0, sizeof(*out));
  snprintf(out->name, sizeof(out->name), "%s", context_name);

  virki_buildkit_local_context_observation_t tree_obs;
  if (!virki_observe_local_context_v2(root, context_name, &tree_obs)) {
    return false;
  }
  memcpy(out->tree_digest, tree_obs.digest, sizeof(out->tree_digest));
  out->regular_file_bytes = tree_obs.regular_file_bytes;
  out->entry_count = tree_obs.entry_count;

  if (fd >= 0) {
    if (!virki_hash_flat_fd(fd, out->stream_digest, &out->stream_bytes)) {
      return false;
    }
  }

  return true;
}

#endif
