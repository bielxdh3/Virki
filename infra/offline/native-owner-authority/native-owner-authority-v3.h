/*
 * VROA_V3 DEV candidate verifier.
 *
 * This protocol verifies a pinned Ed25519 owner approval, four sealed
 * context streams and a sealed BuildKit evidence bundle. A test-only build
 * may sign a CANDIDATE_VERIFIED receipt with an ephemeral key. Production
 * builds always return SIGNING_DISABLED after verification; SIGN_ACK remains
 * hard-disabled in every build.
 */
#ifndef VIRKI_NATIVE_OWNER_AUTHORITY_V3_H
#define VIRKI_NATIVE_OWNER_AUTHORITY_V3_H

static bool v3_read_exact_at(int fd, void *buffer, size_t length, off_t offset) {
  size_t done = 0;
  while (done < length) {
    const ssize_t n = pread(fd, (unsigned char *)buffer + done,
                            length - done, offset + (off_t)done);
    if (n > 0) done += (size_t)n;
    else if (n < 0 && errno == EINTR) continue;
    else return false;
  }
  return true;
}

static bool v3_hash_fd_range(int fd, off_t offset, uint64_t length,
                             char out_hex[65]) {
  if (fd < 0 || offset < 0 || !out_hex) return false;
  virki_abi_sha256_ctx ctx;
  virki_abi_sha256_init(&ctx);
  uint8_t buffer[16384];
  uint64_t done = 0;
  while (done < length) {
    const size_t want = (length - done > sizeof(buffer))
        ? sizeof(buffer) : (size_t)(length - done);
    const ssize_t n = pread(fd, buffer, want, offset + (off_t)done);
    if (n > 0) {
      virki_abi_sha256_update(&ctx, buffer, (size_t)n);
      done += (uint64_t)n;
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else {
      explicit_wipe(buffer, sizeof(buffer));
      return false;
    }
  }
  uint8_t digest[32];
  virki_abi_sha256_final(&ctx, digest);
  bytes_to_hex(digest, sizeof(digest), out_hex);
  explicit_wipe(buffer, sizeof(buffer));
  explicit_wipe(digest, sizeof(digest));
  return true;
}

static bool v3_string_valid(const char *value, size_t capacity,
                            bool allow_empty) {
  if (!value || capacity == 0) return false;
  const char *end = memchr(value, '\0', capacity);
  if (!end || (!allow_empty && end == value)) return false;
  for (const char *p = end + 1; p < value + capacity; p++) {
    if (*p != '\0') return false;
  }
  for (const char *p = value; p < end; p++) {
    const unsigned char ch = (unsigned char)*p;
    if (ch < 0x21 || ch > 0x7e) return false;
  }
  return true;
}

#ifdef VIRKI_OWNER_TEST_BUILD
static bool v3_json_safe_string(const char *value, size_t capacity) {
  if (!value || capacity == 0) return false;
  const char *end = memchr(value, '\0', capacity);
  if (!end || end == value) return false;
  for (const char *p = value; p < end; p++) {
    const unsigned char ch = (unsigned char)*p;
    if (ch < 0x21 || ch > 0x7e || ch == '"' || ch == '\\') return false;
  }
  return true;
}
#endif

static bool v3_digest_valid(const char *value, bool allow_empty) {
  if (!value) return false;
  if (allow_empty && value[0] == '\0') return true;
  return strlen(value) == 64 && is_canonical_lower_hex_v20(value, 64);
}

static bool v3_image_id_valid(const char *value) {
  return value && strlen(value) == 71 && strncmp(value, "sha256:", 7) == 0 &&
      is_canonical_lower_hex_v20(value + 7, 64);
}

static bool v3_read_exact_key_bytes(int fd, uint8_t *out, size_t length) {
  size_t done = 0;
  while (done < length) {
    const ssize_t n = read(fd, out + done, length - done);
    if (n > 0) done += (size_t)n;
    else if (n < 0 && errno == EINTR) continue;
    else return false;
  }
  return true;
}

static bool load_approval_public_key(virki_owner_config_t *cfg) {
  if (!cfg || cfg->approval_public_key_file[0] == '\0' ||
      !v3_string_valid(cfg->approval_key_id, sizeof(cfg->approval_key_id), false) ||
      !v3_digest_valid(cfg->approval_pin_sha256, false)) return false;
  const int fd = open(cfg->approval_public_key_file,
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  struct stat st;
  bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
      st.st_size == 32 && st.st_uid == getuid() &&
      (st.st_mode & 0777) == 0400 && st.st_nlink == 1 &&
      v3_read_exact_key_bytes(fd, cfg->approval_public_key, 32);
  close(fd);
  if (!ok) {
    explicit_wipe(cfg->approval_public_key, sizeof(cfg->approval_public_key));
    return false;
  }
  static const uint8_t spki_prefix[12] = {
    0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00
  };
  uint8_t spki[44];
  memcpy(spki, spki_prefix, sizeof(spki_prefix));
  memcpy(spki + sizeof(spki_prefix), cfg->approval_public_key, 32);
  virki_abi_sha256_ctx hash;
  virki_abi_sha256_init(&hash);
  virki_abi_sha256_update(&hash, spki, sizeof(spki));
  uint8_t digest[32];
  virki_abi_sha256_final(&hash, digest);
  char pin[65];
  bytes_to_hex(digest, sizeof(digest), pin);
  explicit_wipe(spki, sizeof(spki));
  explicit_wipe(digest, sizeof(digest));
  if (strcmp(pin, cfg->approval_pin_sha256) != 0) {
    explicit_wipe(cfg->approval_public_key, sizeof(cfg->approval_public_key));
    return false;
  }
  cfg->has_approval_key = true;
  return true;
}

static bool v3_verify_owner_signature(
    const virki_owner_approval_envelope_v3_t *approval) {
  if (!approval || !g_cfg.has_approval_key) return false;
  const size_t body_len = offsetof(virki_owner_approval_envelope_v3_t, signature);
  static const uint8_t domain[] = VIRKI_OWNER_V3_APPROVAL_DOMAIN;
  const size_t message_len = sizeof(domain) + body_len;
  if (message_len > SIZE_MAX - crypto_sign_BYTES) return false;
  const size_t signed_len = crypto_sign_BYTES + message_len;
  uint8_t *signed_message = malloc(signed_len);
  /* TweetNaCl's crypto_sign_open uses its output buffer as scratch for the
   * entire signed message before replacing it with the opened message. Its
   * required output capacity is therefore signed_len, not message_len. */
  uint8_t *opened_message = malloc(signed_len);
  if (!signed_message || !opened_message) {
    free(signed_message); free(opened_message);
    return false;
  }
  memcpy(signed_message, approval->signature, crypto_sign_BYTES);
  memcpy(signed_message + crypto_sign_BYTES, domain, sizeof(domain));
  memcpy(signed_message + crypto_sign_BYTES + sizeof(domain), approval, body_len);
  unsigned long long opened_len = 0;
  const int result = crypto_sign_open(opened_message, &opened_len,
      signed_message, (unsigned long long)signed_len,
      g_cfg.approval_public_key);
  const bool valid = result == 0 && opened_len == message_len &&
      memcmp(opened_message, domain, sizeof(domain)) == 0 &&
      memcmp(opened_message + sizeof(domain), approval, body_len) == 0;
  explicit_wipe(signed_message, signed_len);
  explicit_wipe(opened_message, signed_len);
  free(signed_message); free(opened_message);
  return valid;
}

static bool v3_approval_shape_valid(
    const virki_owner_approval_envelope_v3_t *approval,
    const virki_owner_request_frame_t *req, const struct ucred *peer,
    const char envelope_sha256[65]) {
  if (!approval || !req || !peer || !envelope_sha256 ||
      memcmp(approval->magic, "VROA_AP3", 8) != 0 || approval->version != 3 ||
      approval->epoch != g_ledger.current_epoch ||
      approval->expires_unix <= (uint64_t)time(NULL) ||
      approval->expires_unix > (uint64_t)time(NULL) + 3600 ||
      approval->context_count != VIRKI_OWNER_CONTEXT_COUNT ||
      !v3_string_valid(approval->key_id, sizeof(approval->key_id), false) ||
      !v3_string_valid(approval->public_key_pin_sha256, sizeof(approval->public_key_pin_sha256), false) ||
      !v3_string_valid(approval->approval_id, sizeof(approval->approval_id), false) ||
      !v3_string_valid(approval->approval_serial, sizeof(approval->approval_serial), false) ||
      !v3_string_valid(approval->job_id, sizeof(approval->job_id), false) ||
      !v3_string_valid(approval->role, sizeof(approval->role), false) ||
      !v3_string_valid(approval->nonce, sizeof(approval->nonce), false) ||
      !v3_string_valid(approval->source_commit, sizeof(approval->source_commit), false) ||
      !v3_string_valid(approval->build_plan_sha256, sizeof(approval->build_plan_sha256), false) ||
      !v3_string_valid(approval->executable_policy_sha256, sizeof(approval->executable_policy_sha256), false) ||
      !v3_string_valid(approval->exporter_intent_sha256, sizeof(approval->exporter_intent_sha256), false) ||
      !v3_string_valid(approval->output_image_id, sizeof(approval->output_image_id), false) ||
      !v3_string_valid(approval->file_sync_manifest_sha256, sizeof(approval->file_sync_manifest_sha256), false) ||
      !v3_string_valid(approval->ignore_policy_sha256, sizeof(approval->ignore_policy_sha256), false) ||
      !v3_string_valid(approval->worker_id, sizeof(approval->worker_id), false) ||
      !v3_string_valid(approval->dockerfile_sha256, sizeof(approval->dockerfile_sha256), true) ||
      !v3_string_valid(approval->ignore_path, sizeof(approval->ignore_path), true) ||
      !v3_string_valid(approval->ignore_sha256, sizeof(approval->ignore_sha256), true) ||
      !v3_string_valid(approval->ignore_source, sizeof(approval->ignore_source), false) ||
      strcmp(approval->key_id, g_cfg.approval_key_id) != 0 ||
      strcmp(approval->public_key_pin_sha256, g_cfg.approval_pin_sha256) != 0 ||
      !v3_string_valid(approval->approval_id, sizeof(approval->approval_id), false) ||
      !v3_string_valid(approval->approval_serial, sizeof(approval->approval_serial), false) ||
      !v3_string_valid(approval->job_id, sizeof(approval->job_id), false) ||
      !v3_string_valid(approval->role, sizeof(approval->role), false) ||
      (strcmp(approval->role, "runtime") != 0 && strcmp(approval->role, "migrator") != 0) ||
      !v3_string_valid(approval->nonce, sizeof(approval->nonce), false) ||
      strlen(approval->nonce) != 32 || !is_canonical_lower_hex_v20(approval->nonce, 32) ||
      !v3_string_valid(approval->source_commit, sizeof(approval->source_commit), false) ||
      strlen(approval->source_commit) != 40 || !is_canonical_lower_hex_v20(approval->source_commit, 40) ||
      !v3_digest_valid(approval->build_plan_sha256, false) ||
      !v3_digest_valid(approval->executable_policy_sha256, false) ||
      !v3_digest_valid(approval->exporter_intent_sha256, false) ||
      !v3_image_id_valid(approval->output_image_id) ||
      !v3_digest_valid(approval->file_sync_manifest_sha256, false) ||
      !v3_digest_valid(approval->ignore_policy_sha256, false) ||
      !v3_string_valid(approval->worker_id, sizeof(approval->worker_id), false) ||
      approval->worker_uid == 0 || approval->worker_gid == 0 ||
      approval->worker_uid == 65534 || approval->worker_gid == 65534 ||
      approval->worker_uid == getuid() || approval->worker_gid == getgid() ||
      approval->worker_uid == peer->uid || approval->worker_gid == peer->gid ||
      !v3_digest_valid(approval->dockerfile_sha256, true) ||
      !v3_string_valid(approval->ignore_path, sizeof(approval->ignore_path), true) ||
      !v3_digest_valid(approval->ignore_sha256, true) ||
      approval->ignore_present > 1 ||
      !v3_string_valid(approval->ignore_source, sizeof(approval->ignore_source), false) ||
      !v3_digest_valid(envelope_sha256, false)) return false;

  if (approval->ignore_present == 0) {
    if (approval->ignore_path[0] != '\0' || approval->ignore_sha256[0] != '\0' ||
        strcmp(approval->ignore_source, "none") != 0) return false;
  } else if (approval->ignore_path[0] == '\0' ||
             !v3_digest_valid(approval->ignore_sha256, false) ||
             (strcmp(approval->ignore_source, "preferred") != 0 &&
              strcmp(approval->ignore_source, "root") != 0)) return false;

  for (size_t i = 0; i < VIRKI_OWNER_CONTEXT_COUNT; i++) {
    const virki_owner_v3_context_claim_t *ctx = &approval->contexts[i];
    if (!v3_string_valid(ctx->name, sizeof(ctx->name), false) ||
        strcmp(ctx->name, VIRKI_OWNER_CONTEXT_NAMES[i]) != 0 ||
        !v3_string_valid(ctx->session_id, sizeof(ctx->session_id), false) ||
        !v3_string_valid(ctx->identity, sizeof(ctx->identity), false) ||
        !v3_image_id_valid(ctx->tree_digest) ||
        !v3_image_id_valid(ctx->stream_digest) ||
        ctx->stream_length == 0 || ctx->stream_length > VIRKI_OWNER_MAX_PAYLOAD_BYTES) return false;
  }

  if (req->epoch != approval->epoch ||
      strcmp(req->session_id, approval->worker_id) != 0 ||
      strcmp(req->job_id, approval->job_id) != 0 ||
      strcmp(req->role, approval->role) != 0 ||
      strcmp(req->nonce, approval->nonce) != 0 ||
      strcmp(req->source_commit, approval->source_commit) != 0 ||
      strcmp(req->build_plan_sha256, approval->build_plan_sha256) != 0 ||
      strcmp(req->executable_policy_sha256, approval->executable_policy_sha256) != 0 ||
      strcmp(req->output_image_id, approval->output_image_id) != 0 ||
      strcmp(req->archive_sha256, approval->file_sync_manifest_sha256) != 0 ||
      strcmp(req->approval_key_id, approval->key_id) != 0 ||
      strcmp(req->approval_id, approval->approval_id) != 0 ||
      strcmp(req->approval_serial, approval->approval_serial) != 0 ||
      strcmp(req->approval_envelope_sha256, envelope_sha256) != 0) return false;
  uint64_t total_bytes = 0;
  for (size_t i = 0; i < VIRKI_OWNER_CONTEXT_COUNT; i++) {
    const virki_owner_v3_context_claim_t *ctx = &approval->contexts[i];
    if (strcmp(req->expected_tree_digests[i], ctx->tree_digest) != 0 ||
        strcmp(req->expected_stream_digests[i], ctx->stream_digest) != 0 ||
        req->expected_stream_lengths[i] != ctx->stream_length ||
        total_bytes > UINT64_MAX - ctx->stream_length) return false;
    total_bytes += ctx->stream_length;
  }
  return req->archive_bytes == total_bytes;
}

static bool v3_validate_sealed_payload_fd(int fd, uint64_t min_bytes,
    uint64_t max_bytes, uint64_t expected_bytes, struct stat *out_stat,
    char out_digest[73]) {
  if (fd < 0 || !out_stat || !out_digest) return false;
  const int flags = fcntl(fd, F_GETFL);
  const int seals = fcntl(fd, F_GET_SEALS);
  const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || seals < 0 ||
      (seals & required) != required || fstat(fd, out_stat) != 0 ||
      !S_ISREG(out_stat->st_mode) || out_stat->st_size < 0 ||
      (uint64_t)out_stat->st_size < min_bytes ||
      (uint64_t)out_stat->st_size > max_bytes ||
      (expected_bytes != UINT64_MAX && (uint64_t)out_stat->st_size != expected_bytes)) return false;
  char prefixed[73];
  uint64_t measured = 0;
  if (!virki_hash_flat_fd(fd, prefixed, &measured) ||
      measured != (uint64_t)out_stat->st_size || strncmp(prefixed, "sha256:", 7) != 0) return false;
  memcpy(out_digest, prefixed, sizeof(prefixed));
  return true;
}

static bool v3_verify_approval_fd(int fd, const virki_owner_request_frame_t *req,
    const struct ucred *peer, virki_owner_approval_envelope_v3_t *out_approval,
    char out_sha256[65], struct stat *out_stat) {
  char prefixed[73];
  if (!v3_validate_sealed_payload_fd(fd,
      sizeof(virki_owner_approval_envelope_v3_t),
      sizeof(virki_owner_approval_envelope_v3_t),
      sizeof(virki_owner_approval_envelope_v3_t), out_stat, prefixed) ||
      !v3_read_exact_at(fd, out_approval, sizeof(*out_approval), 0)) {
    fprintf(stderr, "VROA_V3: approval FD validation failed\n");
    return false;
  }
  memcpy(out_sha256, prefixed + 7, 65);
  if (!v3_approval_shape_valid(out_approval, req, peer, out_sha256)) {
    fprintf(stderr, "VROA_V3: approval claims/request mismatch\n");
    return false;
  }
  if (!v3_verify_owner_signature(out_approval)) {
    fprintf(stderr, "VROA_V3: owner Ed25519 signature verification failed\n");
    return false;
  }
  return true;
}

static const char *v3_json_skip_ws(const char *p, const char *end) {
  while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
  return p;
}

static const char *v3_json_skip_string(const char *p, const char *end) {
  if (!p || p >= end || *p != '"') return NULL;
  p++;
  while (p < end) {
    const unsigned char ch = (unsigned char)*p++;
    if (ch < 0x20) return NULL;
    if (ch == '"') return p;
    if (ch == '\\') {
      if (p >= end) return NULL;
      const char esc = *p++;
      if (esc == 'u') {
        for (int i = 0; i < 4; i++) {
          if (p >= end) return NULL;
          const unsigned char hc = (unsigned char)*p;
          if (!((hc >= '0' && hc <= '9') || (hc >= 'a' && hc <= 'f') || (hc >= 'A' && hc <= 'F'))) return NULL;
          p++;
        }
      } else if (esc != '"' && esc != '\\' && esc != '/' && esc != 'b' &&
                 esc != 'f' && esc != 'n' && esc != 'r' && esc != 't') {
        return NULL;
      }
    }
  }
  return NULL;
}

static const char *v3_json_skip_value(const char *p, const char *end, int depth) {
  if (!p || depth > 64) return NULL;
  p = v3_json_skip_ws(p, end);
  if (p >= end) return NULL;
  if (*p == '"') return v3_json_skip_string(p, end);
  if (*p == '{') {
    p = v3_json_skip_ws(p + 1, end);
    if (p < end && *p == '}') return p + 1;
    while (p < end) {
      p = v3_json_skip_ws(p, end);
      p = v3_json_skip_string(p, end);
      if (!p) return NULL;
      p = v3_json_skip_ws(p, end);
      if (p >= end || *p != ':') return NULL;
      p = v3_json_skip_value(p + 1, end, depth + 1);
      if (!p) return NULL;
      p = v3_json_skip_ws(p, end);
      if (p >= end) return NULL;
      if (*p == '}') return p + 1;
      if (*p != ',') return NULL;
      p++;
    }
    return NULL;
  }
  if (*p == '[') {
    p = v3_json_skip_ws(p + 1, end);
    if (p < end && *p == ']') return p + 1;
    while (p < end) {
      p = v3_json_skip_value(p, end, depth + 1);
      if (!p) return NULL;
      p = v3_json_skip_ws(p, end);
      if (p >= end) return NULL;
      if (*p == ']') return p + 1;
      if (*p != ',') return NULL;
      p++;
    }
    return NULL;
  }
  if (end - p >= 4 && memcmp(p, "true", 4) == 0) return p + 4;
  if (end - p >= 5 && memcmp(p, "false", 5) == 0) return p + 5;
  if (end - p >= 4 && memcmp(p, "null", 4) == 0) return p + 4;
  if (*p == '-' || (*p >= '0' && *p <= '9')) {
    if (*p == '-') p++;
    if (p >= end || *p < '0' || *p > '9') return NULL;
    if (*p == '0') p++;
    else while (p < end && *p >= '0' && *p <= '9') p++;
    if (p < end && *p == '.') {
      p++;
      if (p >= end || *p < '0' || *p > '9') return NULL;
      while (p < end && *p >= '0' && *p <= '9') p++;
    }
    if (p < end && (*p == 'e' || *p == 'E')) {
      p++;
      if (p < end && (*p == '+' || *p == '-')) p++;
      if (p >= end || *p < '0' || *p > '9') return NULL;
      while (p < end && *p >= '0' && *p <= '9') p++;
    }
    return p;
  }
  return NULL;
}

static bool v3_json_string_equals(const char *vs, const char *ve, const char *expected) {
  if (!vs || !ve || !expected || ve - vs < 2 || *vs != '"' || *(ve - 1) != '"') return false;
  const size_t elen = strlen(expected);
  if ((size_t)(ve - vs - 2) != elen) return false;
  if (memchr(vs + 1, '\\', elen) != NULL) return false;
  return memcmp(vs + 1, expected, elen) == 0;
}

static bool v3_json_parse_uint64(const char *vs, const char *ve, uint64_t *out) {
  if (!vs || !ve || vs >= ve || *vs < '0' || *vs > '9') return false;
  uint64_t val = 0;
  for (const char *p = vs; p < ve; p++) {
    if (*p < '0' || *p > '9') return false;
    const uint64_t digit = (uint64_t)(*p - '0');
    if (val > (UINT64_MAX - digit) / 10) return false;
    val = val * 10 + digit;
  }
  if (out) *out = val;
  return true;
}

static bool v3_json_uint64_equals(const char *vs, const char *ve, uint64_t expected) {
  uint64_t val = 0;
  return v3_json_parse_uint64(vs, ve, &val) && val == expected;
}

static bool v3_json_find_field(const char *obj_start, const char *obj_end,
    const char *key, const char **val_start, const char **val_end) {
  if (!obj_start || !obj_end || obj_start >= obj_end || *obj_start != '{') return false;
  const char *p = v3_json_skip_ws(obj_start + 1, obj_end);
  if (p < obj_end && *p == '}') return false;
  bool found = false;
  while (p < obj_end) {
    p = v3_json_skip_ws(p, obj_end);
    const char *ks = p;
    const char *ke = v3_json_skip_string(ks, obj_end);
    if (!ke) return false;
    p = v3_json_skip_ws(ke, obj_end);
    if (p >= obj_end || *p != ':') return false;
    const char *vs = v3_json_skip_ws(p + 1, obj_end);
    const char *ve = v3_json_skip_value(vs, obj_end, 1);
    if (!ve) return false;
    if (v3_json_string_equals(ks, ke, key)) {
      if (found) return false;
      *val_start = vs;
      *val_end = ve;
      found = true;
    }
    p = v3_json_skip_ws(ve, obj_end);
    if (p >= obj_end) return false;
    if (*p == '}') return found;
    if (*p != ',') return false;
    p++;
  }
  return false;
}

typedef struct { const char *s; const char *e; } v3_json_span;

static bool v3_json_field(v3_json_span obj, const char *key, v3_json_span *value) {
  return v3_json_find_field(obj.s, obj.e, key, &value->s, &value->e);
}

static bool v3_json_same_span(v3_json_span a, v3_json_span b) {
  return a.e - a.s == b.e - b.s && memcmp(a.s, b.s, (size_t)(a.e - a.s)) == 0;
}

static int v3_json_string_order(v3_json_span a, v3_json_span b) {
  const size_t na = (size_t)(a.e - a.s - 2), nb = (size_t)(b.e - b.s - 2);
  const int order = memcmp(a.s + 1, b.s + 1, na < nb ? na : nb);
  return order != 0 ? order : (na > nb) - (na < nb);
}

static bool v3_json_same_field(v3_json_span a, const char *ak, v3_json_span b, const char *bk) {
  v3_json_span x, y;
  return v3_json_field(a, ak, &x) && v3_json_field(b, bk, &y) && v3_json_same_span(x, y);
}

static bool v3_json_field_uint(v3_json_span obj, const char *key, uint64_t *out) {
  v3_json_span value;
  return v3_json_field(obj, key, &value) && v3_json_parse_uint64(value.s, value.e, out);
}

static bool v3_json_plain_nonempty(v3_json_span value) {
  return value.e - value.s > 2 && *value.s == '"' && *(value.e - 1) == '"' &&
      memchr(value.s + 1, '\\', (size_t)(value.e - value.s - 2)) == NULL;
}

static bool v3_json_digest(v3_json_span value) {
  if (value.e - value.s != 73 || memcmp(value.s, "\"sha256:", 8) != 0 || *(value.e - 1) != '"') return false;
  for (const char *p = value.s + 8; p < value.e - 1; p++) {
    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return false;
  }
  return true;
}

/* The enclosing JSON is already syntax-checked; walk its array values in order. */
static bool v3_json_array_item(const char **cursor, const char *end, v3_json_span *item) {
  const char *p = v3_json_skip_ws(*cursor, end);
  if (p >= end || *p == ']') return false;
  item->s = p;
  item->e = v3_json_skip_value(p, end, 1);
  if (!item->e) return false;
  p = v3_json_skip_ws(item->e, end);
  if (p >= end || (*p != ',' && *p != ']')) return false;
  *cursor = *p == ',' ? p + 1 : p;
  return true;
}

static int v3_json_digest_cmp(const void *a, const void *b) {
  return memcmp(((const v3_json_span *)a)->s, ((const v3_json_span *)b)->s, 73);
}

static bool v3_json_validate_path(v3_json_span path, v3_json_span record,
    v3_json_span root_vertex, uint64_t root_output) {
  v3_json_span source_vertex, edges;
  uint64_t source_output;
  if (*path.s != '{' ||
      !v3_json_same_field(path, "name", record, "name") ||
      !v3_json_same_field(path, "generation", record, "generation") ||
      !v3_json_same_field(path, "contextIdentity", record, "contextIdentity") ||
      !v3_json_same_field(path, "snapshotId", record, "snapshotId") ||
      !v3_json_same_field(path, "treeDigest", record, "treeDigest") ||
      !v3_json_same_field(path, "sourceVertexDigest", record, "vertexDigest") ||
      !v3_json_same_field(path, "sourceOutputIndex", record, "vertexOutputIndex") ||
      !v3_json_field(path, "sourceVertexDigest", &source_vertex) ||
      !v3_json_field_uint(path, "sourceOutputIndex", &source_output) ||
      !v3_json_field(path, "edges", &edges)) return false;
  if (edges.e - edges.s == 4 && memcmp(edges.s, "null", 4) == 0) {
    return v3_json_same_span(root_vertex, source_vertex) && root_output == source_output;
  }
  if (*edges.s != '[') return false;
  /* Each edge contains a full child digest, so this bounds allocation by payload size. */
  const size_t capacity = (size_t)(edges.e - edges.s) / 73 + 1;
  v3_json_span *visited = malloc(capacity * sizeof(*visited));
  if (!visited) return false;
  size_t count = 1;
  visited[0] = root_vertex;
  v3_json_span parent = root_vertex, edge;
  uint64_t output = root_output;
  bool valid = true;
  const char *cursor = edges.s + 1;
  while (v3_json_array_item(&cursor, edges.e, &edge)) {
    v3_json_span edge_parent, child;
    uint64_t parent_output, input_index, child_output;
    if (*edge.s != '{' || count >= capacity ||
        !v3_json_field(edge, "parentVertexDigest", &edge_parent) || !v3_json_same_span(edge_parent, parent) ||
        !v3_json_field_uint(edge, "parentOutputIndex", &parent_output) || parent_output != output ||
        !v3_json_field_uint(edge, "parentInputIndex", &input_index) || input_index > INT64_MAX ||
        !v3_json_field(edge, "childVertexDigest", &child) || !v3_json_digest(child) ||
        !v3_json_field_uint(edge, "childOutputIndex", &child_output) || child_output > INT64_MAX) {
      valid = false;
      break;
    }
    visited[count++] = child;
    parent = child;
    output = child_output;
  }
  valid = valid && v3_json_skip_ws(cursor, edges.e) == edges.e - 1 &&
      v3_json_same_span(parent, source_vertex) && output == source_output;
  if (valid) {
    qsort(visited, count, sizeof(*visited), v3_json_digest_cmp);
    for (size_t i = 1; i < count; i++) {
      if (v3_json_same_span(visited[i - 1], visited[i])) { valid = false; break; }
    }
  }
  free(visited);
  return valid;
}

static bool v3_json_validate_roots(v3_json_span roots, const char *worker_id,
    const v3_json_span records[VIRKI_OWNER_CONTEXT_COUNT]) {
  if (*roots.s != '[') return false;
  size_t root_count = 0;
  const char *cursor = roots.s + 1;
  v3_json_span root;
  v3_json_span previous_ref = {0}, previous_vertex = {0};
  uint64_t previous_output = 0;
  while (v3_json_array_item(&cursor, roots.e, &root)) {
    v3_json_span worker, ref, vertex, paths, path;
    uint64_t output;
    if (*root.s != '{' ||
        !v3_json_field(root, "workerId", &worker) || !v3_json_string_equals(worker.s, worker.e, worker_id) ||
        !v3_json_field(root, "refId", &ref) || !v3_json_plain_nonempty(ref) ||
        !v3_json_field(root, "vertexDigest", &vertex) || !v3_json_digest(vertex) ||
        !v3_json_field_uint(root, "outputIndex", &output) || output > INT64_MAX ||
        !v3_json_field(root, "contextPaths", &paths) || *paths.s != '[') return false;
    if (root_count != 0) {
      const int ref_order = v3_json_string_order(previous_ref, ref);
      const int vertex_order = v3_json_string_order(previous_vertex, vertex);
      if (ref_order > 0 || (ref_order == 0 && (vertex_order > 0 ||
          (vertex_order == 0 && previous_output >= output)))) return false;
    }
    previous_ref = ref;
    previous_vertex = vertex;
    previous_output = output;
    const char *path_cursor = paths.s + 1;
    size_t path_count = 0;
    while (v3_json_array_item(&path_cursor, paths.e, &path)) {
      if (path_count >= VIRKI_OWNER_CONTEXT_COUNT ||
          !v3_json_validate_path(path, records[path_count], vertex, output)) return false;
      path_count++;
    }
    if (path_count != VIRKI_OWNER_CONTEXT_COUNT || v3_json_skip_ws(path_cursor, paths.e) != paths.e - 1) return false;
    root_count++;
  }
  return root_count > 0 && v3_json_skip_ws(cursor, roots.e) == roots.e - 1;
}

static bool v3_json_verify_proof_digest(const char *obj_start, const char *obj_end,
    const char *domain, size_t domain_len, const char expected_hex[65]) {
  const char *vs = NULL, *ve = NULL;
  if (!v3_json_find_field(obj_start, obj_end, "proofDigest", &vs, &ve)) return false;
  char expected_prefixed[73];
  snprintf(expected_prefixed, sizeof(expected_prefixed), "sha256:%s", expected_hex);
  if (!v3_json_string_equals(vs, ve, expected_prefixed)) return false;
  virki_abi_sha256_ctx ctx;
  virki_abi_sha256_init(&ctx);
  virki_abi_sha256_update(&ctx, (const uint8_t *)domain, domain_len);
  /* Replace "sha256:<64 hex>" with "" to match Go's ProofDigest="" before json.Marshal. */
  virki_abi_sha256_update(&ctx, (const uint8_t *)obj_start, (size_t)((vs + 1) - obj_start));
  virki_abi_sha256_update(&ctx, (const uint8_t *)(ve - 1), (size_t)(obj_end - (ve - 1)));
  uint8_t digest[32];
  virki_abi_sha256_final(&ctx, digest);
  char computed[65];
  bytes_to_hex(digest, sizeof(digest), computed);
  explicit_wipe(digest, sizeof(digest));
  return strcmp(computed, expected_hex) == 0;
}

#include "native-owner-oci-dag-v3.h"

static bool v3_validate_evidence_payload(const char *payload, size_t len, int oci_fd, uint64_t oci_bytes,
    const virki_owner_candidate_evidence_v3_t *header,
    const virki_owner_approval_envelope_v3_t *approval) {
  if (!payload || len == 0 || memchr(payload, '\0', len) != NULL) return false;
  const char *end = payload + len;
  const char *p = v3_json_skip_ws(payload, end);
  if (p >= end || *p != '{') return false;
  const char *obj_end = v3_json_skip_value(p, end, 0);
  if (!obj_end || v3_json_skip_ws(obj_end, end) != end) return false;

  const char *vs = NULL, *ve = NULL;
  if (!v3_json_find_field(p, obj_end, "schemaVersion", &vs, &ve) || !v3_json_uint64_equals(vs, ve, 2) ||
      !v3_json_find_field(p, obj_end, "epoch", &vs, &ve) || !v3_json_uint64_equals(vs, ve, approval->epoch)) return false;
  /* Validate required "binding" object. */
  const char *bind_s = NULL, *bind_e = NULL;
  if (!v3_json_find_field(p, obj_end, "binding", &bind_s, &bind_e) || *bind_s != '{') return false;
  if (!v3_json_find_field(bind_s, bind_e, "approvalId", &vs, &ve) ||
      !v3_json_string_equals(vs, ve, approval->approval_id)) return false;
  const char *exp_s = NULL, *exp_e = NULL;
  if (!v3_json_find_field(bind_s, bind_e, "exporter", &exp_s, &exp_e) || *exp_s != '{') return false;
  char exp_digest[73];
  snprintf(exp_digest, sizeof(exp_digest), "sha256:%s", approval->exporter_intent_sha256);
  if (!v3_json_find_field(exp_s, exp_e, "attributesDigest", &vs, &ve) ||
      !v3_json_string_equals(vs, ve, exp_digest)) return false;
  if (!v3_json_find_field(exp_s, exp_e, "schemaVersion", &vs, &ve) || !v3_json_uint64_equals(vs, ve, 2) ||
      !v3_json_find_field(exp_s, exp_e, "id", &vs, &ve) || !v3_json_uint64_equals(vs, ve, 0) ||
      !v3_json_find_field(exp_s, exp_e, "type", &vs, &ve) || !v3_json_string_equals(vs, ve, "image") ||
      !v3_json_find_field(exp_s, exp_e, "destination", &vs, &ve) ||
      !v3_json_plain_nonempty((v3_json_span){vs, ve}) || v3_json_string_equals(vs, ve, "*")) return false;
  if (!v3_json_find_field(bind_s, bind_e, "jobId", &vs, &ve) ||
      !v3_json_string_equals(vs, ve, approval->job_id) ||
      !v3_json_find_field(bind_s, bind_e, "role", &vs, &ve) ||
      !v3_json_string_equals(vs, ve, approval->role) ||
      !v3_json_find_field(bind_s, bind_e, "nonce", &vs, &ve) ||
      !v3_json_string_equals(vs, ve, approval->nonce)) return false;

  /* Validate all 4 canonical contexts inside "contexts" array. */
  const char *ctxs_s = NULL, *ctxs_e = NULL;
  if (!v3_json_find_field(p, obj_end, "contexts", &ctxs_s, &ctxs_e) || *ctxs_s != '[') return false;
  bool seen_ctx[VIRKI_OWNER_CONTEXT_COUNT] = {false, false, false, false};
  v3_json_span records[VIRKI_OWNER_CONTEXT_COUNT];
  size_t ctx_count = 0;
  const char *cp = v3_json_skip_ws(ctxs_s + 1, ctxs_e);
  if (cp >= ctxs_e || *cp == ']') return false;
  while (cp < ctxs_e) {
    const char *item_s = v3_json_skip_ws(cp, ctxs_e);
    const char *item_e = v3_json_skip_value(item_s, ctxs_e, 1);
    if (!item_e || *item_s != '{') return false;
    if (!v3_json_find_field(item_s, item_e, "name", &vs, &ve)) return false;
    ssize_t idx = -1;
    for (size_t k = 0; k < VIRKI_OWNER_CONTEXT_COUNT; k++) {
      if (v3_json_string_equals(vs, ve, VIRKI_OWNER_CONTEXT_NAMES[k])) { idx = (ssize_t)k; break; }
    }
    if (idx < 0 || seen_ctx[idx]) return false;
    seen_ctx[idx] = true;
    records[idx] = (v3_json_span){item_s, item_e};
    uint64_t vertex_output;
    if (!v3_json_find_field(item_s, item_e, "workerId", &vs, &ve) ||
        !v3_json_string_equals(vs, ve, approval->worker_id) ||
        !v3_json_find_field(item_s, item_e, "sessionId", &vs, &ve) ||
        !v3_json_string_equals(vs, ve, approval->contexts[idx].session_id) ||
        !v3_json_find_field(item_s, item_e, "contextIdentity", &vs, &ve) ||
        !v3_json_string_equals(vs, ve, approval->contexts[idx].identity) ||
        !v3_json_find_field(item_s, item_e, "generation", &vs, &ve) ||
        !v3_json_string_equals(vs, ve, approval->nonce) ||
        !v3_json_find_field(item_s, item_e, "snapshotId", &vs, &ve) ||
        !v3_json_plain_nonempty((v3_json_span){vs, ve}) ||
        !v3_json_find_field(item_s, item_e, "vertexDigest", &vs, &ve) || !v3_json_digest((v3_json_span){vs, ve}) ||
        !v3_json_field_uint(records[idx], "vertexOutputIndex", &vertex_output) || vertex_output > INT64_MAX ||
        !v3_json_find_field(item_s, item_e, "treeDigestSchema", &vs, &ve) ||
        !v3_json_string_equals(vs, ve, "buildkit-worker-local-context-v2") ||
        !v3_json_find_field(item_s, item_e, "treeDigest", &vs, &ve) ||
        !v3_json_string_equals(vs, ve, approval->contexts[idx].tree_digest) ||
        !v3_json_find_field(item_s, item_e, "streamDigest", &vs, &ve) ||
        !v3_json_string_equals(vs, ve, approval->contexts[idx].stream_digest) ||
        !v3_json_find_field(item_s, item_e, "streamLength", &vs, &ve) ||
        !v3_json_uint64_equals(vs, ve, approval->contexts[idx].stream_length)) return false;
    ctx_count++;
    cp = v3_json_skip_ws(item_e, ctxs_e);
    if (cp >= ctxs_e) return false;
    if (*cp == ']') break;
    if (*cp != ',') return false;
    cp++;
  }
  if (ctx_count != VIRKI_OWNER_CONTEXT_COUNT) return false;

  /* Validate "output" object: workerId, image, causality proof, and ociDag proof. */
  const char *out_s = NULL, *out_e = NULL;
  if (!v3_json_find_field(p, obj_end, "output", &out_s, &out_e) || *out_s != '{') return false;
  if (!v3_json_find_field(out_s, out_e, "workerId", &vs, &ve) ||
      !v3_json_string_equals(vs, ve, approval->worker_id)) return false;
  const char *img_s = NULL, *img_e = NULL;
  uint64_t img_size = 0;
  if (!v3_json_find_field(out_s, out_e, "image", &img_s, &img_e) || *img_s != '{' ||
      !v3_json_find_field(img_s, img_e, "digest", &vs, &ve) ||
      !v3_json_string_equals(vs, ve, approval->output_image_id) ||
      !v3_json_find_field(img_s, img_e, "size", &vs, &ve) ||
      !v3_json_parse_uint64(vs, ve, &img_size) || img_size == 0 || img_size > INT64_MAX ||
      !v3_json_find_field(img_s, img_e, "mediaType", &vs, &ve) ||
      !(v3_json_string_equals(vs, ve, "application/vnd.oci.image.manifest.v1+json") ||
        v3_json_string_equals(vs, ve, "application/vnd.oci.image.index.v1+json") ||
        v3_json_string_equals(vs, ve, "application/vnd.docker.distribution.manifest.v2+json") ||
        v3_json_string_equals(vs, ve, "application/vnd.docker.distribution.manifest.list.v2+json"))) return false;

  const char *cau_s = NULL, *cau_e = NULL;
  if (!v3_json_find_field(out_s, out_e, "causality", &cau_s, &cau_e) || *cau_s != '{' ||
      !v3_json_find_field(cau_s, cau_e, "schemaVersion", &vs, &ve) ||
      !v3_json_uint64_equals(vs, ve, 3) ||
      !v3_json_verify_proof_digest(cau_s, cau_e, "virki-c1-export-causality-v3\0", 29,
          header->causality_proof_sha256)) return false;
  const char *roots_s = NULL, *roots_e = NULL;
  if (!v3_json_find_field(cau_s, cau_e, "roots", &roots_s, &roots_e) ||
      !v3_json_same_field((v3_json_span){cau_s, cau_e}, "exporter", (v3_json_span){bind_s, bind_e}, "exporter") ||
      !v3_json_validate_roots((v3_json_span){roots_s, roots_e}, approval->worker_id, records)) return false;

  const char *oci_s = NULL, *oci_e = NULL;
  if (!v3_json_find_field(out_s, out_e, "ociDag", &oci_s, &oci_e) || *oci_s != '{' ||
      !v3_json_find_field(oci_s, oci_e, "schemaVersion", &vs, &ve) ||
      !v3_json_uint64_equals(vs, ve, 2) ||
      !v3_json_verify_proof_digest(oci_s, oci_e, "virki-c1-oci-dag-v2\0", 20,
          header->oci_dag_sha256)) return false;
  const char *root_s = NULL, *root_e = NULL;
  if (!v3_json_find_field(oci_s, oci_e, "root", &root_s, &root_e) || *root_s != '{' ||
      !v3_json_find_field(root_s, root_e, "digest", &vs, &ve) ||
      !v3_json_string_equals(vs, ve, approval->output_image_id) ||
      !v3_json_same_field((v3_json_span){root_s, root_e}, "size", (v3_json_span){img_s, img_e}, "size") ||
      !v3_json_same_field((v3_json_span){root_s, root_e}, "mediaType", (v3_json_span){img_s, img_e}, "mediaType")) return false;
  const char *nodes_s = NULL, *nodes_e = NULL;
  if (!v3_json_find_field(oci_s, oci_e, "nodes", &nodes_s, &nodes_e) || *nodes_s != '[') return false;
  const char *node_cursor = nodes_s + 1;
  v3_json_span node;
  size_t root_nodes = 0;
  while (v3_json_array_item(&node_cursor, nodes_e, &node)) {
    v3_json_span digest, media, role;
    uint64_t size;
    if (*node.s != '{' || !v3_json_field(node, "digest", &digest) || !v3_json_digest(digest) ||
        !v3_json_field(node, "mediaType", &media) || !v3_json_plain_nonempty(media) ||
        !v3_json_field_uint(node, "size", &size) || size > INT64_MAX) return false;
    if (v3_json_field(node, "role", &role) && v3_json_string_equals(role.s, role.e, "root")) {
      if (++root_nodes != 1 || !v3_json_string_equals(digest.s, digest.e, approval->output_image_id) ||
          !v3_json_same_field(node, "mediaType", (v3_json_span){root_s, root_e}, "mediaType") || size != img_size) return false;
    }
  }
  if (root_nodes != 1 || v3_json_skip_ws(node_cursor, nodes_e) != nodes_e - 1) return false;
  if (!v3_verify_oci_archive(oci_fd, oci_bytes, (v3_json_span){root_s, root_e}, (v3_json_span){nodes_s, nodes_e})) return false;

  /* Validate optional "frontendProof". */
  const char *fe_s = NULL, *fe_e = NULL;
  const bool has_fe = v3_json_find_field(p, obj_end, "frontendProof", &fe_s, &fe_e);
  if (header->frontend_proof_sha256[0] == '\0') {
    if (has_fe && !(fe_e - fe_s == 4 && memcmp(fe_s, "null", 4) == 0)) return false;
  } else {
    if (!has_fe || *fe_s != '{' ||
        !v3_json_verify_proof_digest(fe_s, fe_e, "virki-c1-frontend-proof-v1\0", 27,
            header->frontend_proof_sha256)) return false;
  }
  return true;
}

static bool v3_validate_evidence_fd(int fd, int oci_fd, uint64_t oci_bytes,
    const virki_owner_request_frame_t *req,
    const virki_owner_approval_envelope_v3_t *approval,
    const char approval_sha256[65], char evidence_sha256[65],
    struct stat *out_stat) {
  char prefixed[73];
  if (!v3_validate_sealed_payload_fd(fd, sizeof(virki_owner_candidate_evidence_v3_t),
      VIRKI_OWNER_V3_EVIDENCE_MAX_BYTES, UINT64_MAX, out_stat, prefixed) ||
      strcmp(req->transcript_sha256, prefixed + 7) != 0) return false;
  virki_owner_candidate_evidence_v3_t header;
  if (!v3_read_exact_at(fd, &header, sizeof(header), 0) ||
      memcmp(header.magic, "VROA_EV3", 8) != 0 || header.version != 3 ||
      !v3_string_valid(header.approval_envelope_sha256, sizeof(header.approval_envelope_sha256), false) ||
      !v3_string_valid(header.job_id, sizeof(header.job_id), false) ||
      !v3_string_valid(header.role, sizeof(header.role), false) ||
      !v3_string_valid(header.nonce, sizeof(header.nonce), false) ||
      !v3_string_valid(header.worker_id, sizeof(header.worker_id), false) ||
      !v3_string_valid(header.output_image_id, sizeof(header.output_image_id), false) ||
      !v3_string_valid(header.exporter_intent_sha256, sizeof(header.exporter_intent_sha256), false) ||
      !v3_string_valid(header.file_sync_manifest_sha256, sizeof(header.file_sync_manifest_sha256), false) ||
      !v3_string_valid(header.causality_proof_sha256, sizeof(header.causality_proof_sha256), false) ||
      !v3_string_valid(header.oci_dag_sha256, sizeof(header.oci_dag_sha256), false) ||
      !v3_string_valid(header.frontend_proof_sha256, sizeof(header.frontend_proof_sha256), true) ||
      !v3_string_valid(header.evidence_payload_sha256, sizeof(header.evidence_payload_sha256), false) ||
      strcmp(header.approval_envelope_sha256, approval_sha256) != 0 ||
      strcmp(header.job_id, approval->job_id) != 0 ||
      strcmp(header.role, approval->role) != 0 ||
      strcmp(header.nonce, approval->nonce) != 0 ||
      strcmp(header.worker_id, approval->worker_id) != 0 ||
      strcmp(header.output_image_id, approval->output_image_id) != 0 ||
      strcmp(header.exporter_intent_sha256, approval->exporter_intent_sha256) != 0 ||
      strcmp(header.file_sync_manifest_sha256, approval->file_sync_manifest_sha256) != 0 ||
      header.deploy_authorized != 0 || header.worker_receipt_pair_admitted != 0 ||
      !v3_digest_valid(header.causality_proof_sha256, false) ||
      !v3_digest_valid(header.oci_dag_sha256, false) ||
      !v3_digest_valid(header.frontend_proof_sha256, true) ||
      !v3_digest_valid(header.evidence_payload_sha256, false) ||
      header.evidence_payload_bytes == 0 ||
      (uint64_t)header.evidence_payload_bytes != (uint64_t)out_stat->st_size - sizeof(header)) return false;
  for (size_t i = 0; i < VIRKI_OWNER_CONTEXT_COUNT; i++) {
    if (!v3_string_valid(header.context_tree_digests[i], sizeof(header.context_tree_digests[i]), false) ||
        !v3_string_valid(header.context_stream_digests[i], sizeof(header.context_stream_digests[i]), false) ||
        strcmp(header.context_tree_digests[i], approval->contexts[i].tree_digest) != 0 ||
        strcmp(header.context_stream_digests[i], approval->contexts[i].stream_digest) != 0 ||
        header.context_stream_lengths[i] != approval->contexts[i].stream_length ||
        strcmp(req->expected_tree_digests[i], header.context_tree_digests[i]) != 0 ||
        strcmp(req->expected_stream_digests[i], header.context_stream_digests[i]) != 0 ||
        req->expected_stream_lengths[i] != header.context_stream_lengths[i]) return false;
  }
  char payload_sha[65];
  if (!v3_hash_fd_range(fd, (off_t)sizeof(header), header.evidence_payload_bytes, payload_sha) ||
      strcmp(payload_sha, header.evidence_payload_sha256) != 0) return false;
  char *payload_buf = malloc(header.evidence_payload_bytes);
  if (!payload_buf) return false;
  const bool read_ok = v3_read_exact_at(fd, payload_buf, header.evidence_payload_bytes, (off_t)sizeof(header));
  const bool semantic_ok = read_ok && v3_validate_evidence_payload(
      payload_buf, header.evidence_payload_bytes, oci_fd, oci_bytes, &header, approval);
  explicit_wipe(payload_buf, header.evidence_payload_bytes);
  free(payload_buf);
  if (!semantic_ok) return false;
  memcpy(evidence_sha256, prefixed + 7, 65);
  return true;
}

static bool v3_stream_read(int fd, uint64_t length, uint64_t *offset, void *out, size_t size) {
  if (*offset > length || (uint64_t)size > length - *offset ||
      !v3_read_exact_at(fd, out, size, (off_t)*offset)) return false;
  *offset += (uint64_t)size;
  return true;
}

static bool v3_stream_uint(int fd, uint64_t length, uint64_t *offset, uint64_t *value) {
  uint8_t bytes[8];
  if (!v3_stream_read(fd, length, offset, bytes, sizeof(bytes))) return false;
  *value = 0;
  for (size_t i = 0; i < sizeof(bytes); i++) *value = (*value << 8) | bytes[i];
  return true;
}

static bool v3_stream_hash_bytes(int fd, uint64_t length, uint64_t *offset,
    uint64_t size, virki_abi_sha256_ctx *hash, bool text) {
  uint8_t buf[16384];
  if (*offset > length || size > length - *offset) return false;
  while (size > 0) {
    const size_t chunk = size > sizeof(buf) ? sizeof(buf) : (size_t)size;
    if (!v3_stream_read(fd, length, offset, buf, chunk) || (text && memchr(buf, '\0', chunk))) {
      explicit_wipe(buf, sizeof(buf));
      return false;
    }
    virki_abi_sha256_update(hash, buf, chunk);
    size -= chunk;
  }
  explicit_wipe(buf, sizeof(buf));
  return true;
}

/* A stream/tree pair can be internally hash-consistent without representing
 * any directory walk BuildKit could have performed. Verify path grammar,
 * witnessed parent directories and the Go filepath.WalkDir depth-first,
 * byte-sorted basename order while consuming only bounded stack memory.
 * A malformed stream must never become C4's canonical provenance evidence. */
typedef struct {
  char previous[1024];
  size_t previous_len;
  bool previous_directory;
  char ancestor_path[1024];
  uint16_t ancestor_lengths[1024];
  size_t depth;
} v3_walk_state;

static bool v3_walk_path_follows(const v3_walk_state *walk, const char *path, size_t length) {
  size_t previous_at = 0, current_at = 0;
  while (previous_at < walk->previous_len && current_at < length) {
    const size_t previous_start = previous_at, current_start = current_at;
    while (previous_at < walk->previous_len && walk->previous[previous_at] != '/') previous_at++;
    while (current_at < length && path[current_at] != '/') current_at++;
    const size_t previous_size = previous_at - previous_start, current_size = current_at - current_start;
    const size_t smaller = previous_size < current_size ? previous_size : current_size;
    const int order = memcmp(walk->previous + previous_start, path + current_start, smaller);
    if (order != 0) return order < 0;
    if (previous_size != current_size) return previous_size < current_size;
    if (current_at == length) return false; /* duplicate or prefix regression */
    if (previous_at == walk->previous_len) return walk->previous_directory;
    previous_at++;
    current_at++;
  }
  return false;
}

/* The Node C1 provenance parser uses a fatal UTF-8 decoder before accepting
 * filenames. Mirror that grammar in C4, including overlong/surrogate/too-high
 * scalar rejection; never allow a forged sealed stream to bypass the stricter
 * producer-to-approver contract through arbitrary raw pathname octets. */
static bool v3_walk_valid_utf8(const uint8_t *bytes, size_t length) {
  /* Node's fatal TextDecoder otherwise strips an initial UTF-8 BOM and may
   * validate a different pathname than the raw bytes signed by C4. Admit no
   * such aliases on either side of the provenance boundary. */
  if (length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf) return false;
  size_t utf16_units = 0;
  for (size_t i = 0; i < length;) {
    const uint8_t lead = bytes[i];
    if (lead < 0x80) {
      if (++utf16_units > 512) return false;
      i++;
      continue;
    }
    size_t count;
    uint8_t second_min = 0x80, second_max = 0xbf;
    if (lead >= 0xc2 && lead <= 0xdf) count = 1;
    else if (lead >= 0xe0 && lead <= 0xef) {
      count = 2;
      if (lead == 0xe0) second_min = 0xa0;
      else if (lead == 0xed) second_max = 0x9f;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
      count = 3;
      if (lead == 0xf0) second_min = 0x90;
      else if (lead == 0xf4) second_max = 0x8f;
    } else return false;
    if (count >= length - i || bytes[i + 1] < second_min || bytes[i + 1] > second_max)
      return false;
    for (size_t j = 2; j <= count; j++) {
      if (bytes[i + j] < 0x80 || bytes[i + j] > 0xbf) return false;
    }
    /* Node validateRelPath caps JS UTF-16 string length at 512, not
     * UTF-8 octet count. Supplementary code points occupy two units. */
    utf16_units += count == 3 ? 2 : 1;
    if (utf16_units > 512) return false;
    i += count + 1;
  }
  return true;
}

static bool v3_walk_accept_path(v3_walk_state *walk, const char *path, size_t length, uint8_t kind) {
  if (!walk || !path || length == 0 || length >= sizeof(walk->previous) ||
      path[0] == '/' || path[length - 1] == '/' ||
      !v3_walk_valid_utf8((const uint8_t *)path, length)) return false;
  size_t segment_start = 0, parent_length = 0;
  for (size_t i = 0; i <= length; i++) {
    const char c = i == length ? '/' : path[i];
    const uint8_t octet = (uint8_t)c;
    /* Match the upstream C1->C4 Node canonical path admission. Hash agreement
     * alone must never let the native signer accept control characters or
     * wildcard names rejected by the non-authorizing provenance contract. */
    if (octet < 32 || octet == 127 || c == '\\' || c == '*' || c == '?' ||
        c == '[' || c == ']') return false;
    if (c != '/') continue;
    const size_t segment_length = i - segment_start;
    if (segment_length == 0 ||
        (segment_length == 1 && path[segment_start] == '.') ||
        (segment_length == 2 && path[segment_start] == '.' && path[segment_start + 1] == '.')) return false;
    if (i < length) parent_length = i;
    segment_start = i + 1;
  }
  while (walk->depth != 0) {
    const size_t ancestor_length = walk->ancestor_lengths[walk->depth - 1];
    if (ancestor_length == parent_length &&
        memcmp(walk->ancestor_path, path, ancestor_length) == 0) break;
    walk->depth--;
  }
  if (parent_length != 0 && walk->depth == 0) return false;
  if (walk->previous_len != 0 && !v3_walk_path_follows(walk, path, length)) return false;
  if (kind == 'D') {
    if (walk->depth >= sizeof(walk->ancestor_lengths) / sizeof(walk->ancestor_lengths[0])) return false;
    memcpy(walk->ancestor_path, path, length);
    walk->ancestor_lengths[walk->depth++] = (uint16_t)length;
  }
  memcpy(walk->previous, path, length);
  walk->previous_len = length;
  walk->previous_directory = kind == 'D';
  return true;
}

/* Recompute the canonical tree hash from the sealed linear stream, without
 * trusting a separately supplied tree digest or arbitrary stream ordering. */
static bool v3_verify_context_stream_tree(int fd, uint64_t length,
    const char *name, const char *expected_tree) {
  static const char prefix[] = "virki-context-stream-v1\0";
  uint8_t actual_prefix[sizeof(prefix) - 1];
  char actual_name[32];
  uint64_t offset = 0, name_len;
  if (!v3_stream_read(fd, length, &offset, actual_prefix, sizeof(actual_prefix)) ||
      memcmp(actual_prefix, prefix, sizeof(actual_prefix)) != 0 ||
      !v3_stream_uint(fd, length, &offset, &name_len) || name_len != strlen(name) || name_len >= sizeof(actual_name) ||
      !v3_stream_read(fd, length, &offset, actual_name, (size_t)name_len) ||
      memcmp(actual_name, name, (size_t)name_len) != 0) return false;

  virki_abi_sha256_ctx tree;
  virki_abi_sha256_init(&tree);
  virki_abi_sha256_update(&tree, (const uint8_t *)VIRKI_BUILDKIT_TREE_PREFIX_V2, VIRKI_BUILDKIT_TREE_PREFIX_V2_LEN);
  v3_walk_state walk = {0};
  while (offset < length) {
    uint8_t kind;
    uint64_t path_len, mode, size;
    if (!v3_stream_read(fd, length, &offset, &kind, 1) || (kind != 'D' && kind != 'L' && kind != 'F') ||
        !v3_stream_uint(fd, length, &offset, &path_len) || path_len == 0 || path_len >= 1024) return false;
    char path[1024];
    if (!v3_stream_read(fd, length, &offset, path, (size_t)path_len) ||
        !v3_walk_accept_path(&walk, path, (size_t)path_len, kind)) return false;
    virki_abi_sha256_update(&tree, &kind, 1);
    virki_abi_write_uint64(&tree, path_len);
    virki_abi_sha256_update(&tree, (const uint8_t *)path, (size_t)path_len);
    if (!v3_stream_uint(fd, length, &offset, &mode) || mode > 07777) return false;
    virki_abi_write_uint64(&tree, mode);
    if (kind == 'D') continue;
    if (!v3_stream_uint(fd, length, &offset, &size)) return false;
    virki_abi_write_uint64(&tree, size);
    if (kind == 'L') {
      if (size == 0 || !v3_stream_hash_bytes(fd, length, &offset, size, &tree, true)) return false;
    } else {
      virki_abi_sha256_ctx content;
      uint8_t content_digest[32];
      virki_abi_sha256_init(&content);
      if (!v3_stream_hash_bytes(fd, length, &offset, size, &content, false)) return false;
      virki_abi_sha256_final(&content, content_digest);
      virki_abi_sha256_update(&tree, content_digest, sizeof(content_digest));
      explicit_wipe(content_digest, sizeof(content_digest));
    }
  }
  uint8_t digest[32];
  char hex[65];
  virki_abi_sha256_final(&tree, digest);
  bytes_to_hex(digest, sizeof(digest), hex);
  explicit_wipe(digest, sizeof(digest));
  return strncmp(expected_tree, "sha256:", 7) == 0 && strcmp(expected_tree + 7, hex) == 0;
}

static int v3_validate_context_fds(const int fds[VIRKI_OWNER_MAX_FD_COUNT],
    const virki_owner_request_frame_t *req, struct stat stats[6],
    char observed[VIRKI_OWNER_CONTEXT_COUNT][65]) {
  for (size_t i = 0; i < VIRKI_OWNER_CONTEXT_COUNT; i++) {
    char prefixed[73];
    if (!v3_validate_sealed_payload_fd(fds[i], 1, VIRKI_OWNER_MAX_PAYLOAD_BYTES,
        req->expected_stream_lengths[i], &stats[i], prefixed)) return VIRKI_OWNER_STATUS_ERR_FD_INVALID;
    if (strcmp(prefixed, req->expected_stream_digests[i]) != 0) return VIRKI_OWNER_STATUS_ERR_STREAM_MISMATCH;
    if (!v3_verify_context_stream_tree(fds[i], req->expected_stream_lengths[i],
        VIRKI_OWNER_CONTEXT_NAMES[i], req->expected_tree_digests[i])) return VIRKI_OWNER_STATUS_ERR_TREE_MISMATCH;
    memcpy(observed[i], prefixed + 7, 65);
    for (size_t j = 0; j < i; j++) {
      if (stats[i].st_dev == stats[j].st_dev && stats[i].st_ino == stats[j].st_ino)
        return VIRKI_OWNER_STATUS_ERR_FD_INVALID;
    }
  }
  return VIRKI_OWNER_STATUS_OK;
}

static int v3_process_command(int client_fd, const virki_owner_request_frame_t *req,
    int fds[VIRKI_OWNER_MAX_FD_COUNT], size_t fd_count,
    virki_owner_response_frame_t *resp, const struct ucred *peer) {
  if (!req || !resp || !peer) {
    close_fds(fds);
    return VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
  }
  if (req->cmd == VIRKI_OWNER_CMD_V3_BEGIN) {
    if (fd_count != 1 || req->scope_token[0] != '\0' || req->transcript_sha256[0] != '\0' ||
        req->epoch != g_ledger.current_epoch || !g_cfg.has_approval_key) {
      close_fds(fds);
      resp->status = req->epoch != g_ledger.current_epoch
          ? VIRKI_OWNER_STATUS_ERR_STALE_EPOCH
          : (!g_cfg.has_approval_key ? VIRKI_OWNER_STATUS_ERR_NO_KEY : VIRKI_OWNER_STATUS_ERR_BAD_FRAME);
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    virki_owner_approval_envelope_v3_t approval;
    char approval_sha[65];
    struct stat approval_stat;
    const bool valid = v3_verify_approval_fd(fds[0], req, peer,
        &approval, approval_sha, &approval_stat);
    close_fds(fds);
    if (!valid) {
      resp->status = VIRKI_OWNER_STATUS_ERR_PROVENANCE_FAIL;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    uint8_t token_bytes[32];
    randombytes(token_bytes, sizeof(token_bytes));
    char token[65];
    bytes_to_hex(token_bytes, sizeof(token_bytes), token);
    explicit_wipe(token_bytes, sizeof(token_bytes));
    uint64_t seq = 0;
    if (!ledger_record_prepare_v3(&g_ledger, token, approval.nonce, approval_sha, &seq)) {
      resp->status = g_ledger.faulted ? VIRKI_OWNER_STATUS_ERR_LEDGER_TAMPER :
          VIRKI_OWNER_STATUS_ERR_NONCE_REPLAY;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    resp->status = VIRKI_OWNER_STATUS_OK;
    resp->sequence_number = seq;
    snprintf(resp->scope_token, sizeof(resp->scope_token), "%s", token);
    (void)owner_send_response_v21(client_fd, resp);
    return VIRKI_OWNER_STATUS_OK;
  }

  if (req->cmd == VIRKI_OWNER_CMD_V3_ABORT) {
    close_fds(fds);
    if (fd_count != 0 || req->epoch != g_ledger.current_epoch ||
        strlen(req->nonce) != 32 || !is_canonical_lower_hex_v20(req->nonce, 32) ||
        strlen(req->scope_token) != 64 || !is_canonical_lower_hex_v20(req->scope_token, 64)) {
      resp->status = req->epoch != g_ledger.current_epoch
          ? VIRKI_OWNER_STATUS_ERR_STALE_EPOCH : VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    const int state = ledger_v3_scope_state(&g_ledger, req->scope_token, req->nonce, NULL);
    if (state != 1) {
      resp->status = state == 2 ? VIRKI_OWNER_STATUS_ERR_SCOPE_ABORTED :
          (state == 0 ? VIRKI_OWNER_STATUS_ERR_SCOPE_NOT_FOUND : VIRKI_OWNER_STATUS_ERR_LEDGER_TAMPER);
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    if (!ledger_record_abort_v3(&g_ledger, req->scope_token, req->nonce, 1)) {
      resp->status = VIRKI_OWNER_STATUS_ERR_LEDGER_TAMPER;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    resp->status = VIRKI_OWNER_STATUS_OK;
    (void)owner_send_response_v21(client_fd, resp);
    return VIRKI_OWNER_STATUS_OK;
  }

  if (req->cmd == VIRKI_OWNER_CMD_V3_VERIFY_CANDIDATE) {
    if (fd_count != 7 || req->epoch != g_ledger.current_epoch ||
        strlen(req->scope_token) != 64 || !is_canonical_lower_hex_v20(req->scope_token, 64) ||
        strlen(req->nonce) != 32 || !is_canonical_lower_hex_v20(req->nonce, 32) ||
        !v3_digest_valid(req->transcript_sha256, false) || !g_cfg.has_approval_key) {
      close_fds(fds);
      resp->status = req->epoch != g_ledger.current_epoch ? VIRKI_OWNER_STATUS_ERR_STALE_EPOCH :
          (!g_cfg.has_approval_key ? VIRKI_OWNER_STATUS_ERR_NO_KEY : VIRKI_OWNER_STATUS_ERR_BAD_FRAME);
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    char prepared_approval_sha[65];
    const int scope_state = ledger_v3_scope_state(&g_ledger, req->scope_token, req->nonce, prepared_approval_sha);
    if (scope_state != 1) {
      close_fds(fds);
      resp->status = scope_state == 2 ? VIRKI_OWNER_STATUS_ERR_SCOPE_ABORTED :
          (scope_state == 0 ? VIRKI_OWNER_STATUS_ERR_SCOPE_NOT_FOUND : VIRKI_OWNER_STATUS_ERR_LEDGER_TAMPER);
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    virki_owner_approval_envelope_v3_t approval;
    char approval_sha[65];
    struct stat approval_stat;
    if (!v3_verify_approval_fd(fds[4], req, peer, &approval, approval_sha, &approval_stat) ||
        strcmp(approval_sha, prepared_approval_sha) != 0) {
      close_fds(fds);
      resp->status = VIRKI_OWNER_STATUS_ERR_PROVENANCE_FAIL;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    struct stat context_stats[6];
    char observed[VIRKI_OWNER_CONTEXT_COUNT][65];
    const int context_status = v3_validate_context_fds(fds, req, context_stats, observed);
    if (context_status != VIRKI_OWNER_STATUS_OK) {
      close_fds(fds);
      resp->status = (uint32_t)context_status;
      (void)owner_send_response_v21(client_fd, resp);
      return context_status;
    }
    for (size_t i = 0; i < VIRKI_OWNER_CONTEXT_COUNT; i++) {
      if ((context_stats[i].st_dev == approval_stat.st_dev && context_stats[i].st_ino == approval_stat.st_ino)) {
        close_fds(fds);
        resp->status = VIRKI_OWNER_STATUS_ERR_FD_INVALID;
        (void)owner_send_response_v21(client_fd, resp);
        return (int)resp->status;
      }
    }
    char evidence_sha[65];
    struct stat evidence_stat;
    struct stat oci_stat;
    char oci_digest[73];
    if (!v3_validate_sealed_payload_fd(fds[6], 1, VIRKI_OWNER_V3_OCI_MAX_BYTES, UINT64_MAX, &oci_stat, oci_digest)) {
      close_fds(fds);
      resp->status = VIRKI_OWNER_STATUS_ERR_FD_INVALID;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    if (!v3_validate_evidence_fd(fds[5], fds[6], (uint64_t)oci_stat.st_size, req, &approval, approval_sha,
        evidence_sha, &evidence_stat)) {
      close_fds(fds);
      resp->status = VIRKI_OWNER_STATUS_ERR_PROVENANCE_FAIL;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    for (size_t i = 0; i < VIRKI_OWNER_CONTEXT_COUNT + 2; i++) {
      const struct stat *left = i < VIRKI_OWNER_CONTEXT_COUNT ? &context_stats[i] : (i == VIRKI_OWNER_CONTEXT_COUNT ? &approval_stat : &evidence_stat);
      if ((i != VIRKI_OWNER_CONTEXT_COUNT + 1 && left->st_dev == evidence_stat.st_dev && left->st_ino == evidence_stat.st_ino) ||
          (left->st_dev == oci_stat.st_dev && left->st_ino == oci_stat.st_ino)) {
        close_fds(fds);
        resp->status = VIRKI_OWNER_STATUS_ERR_FD_INVALID;
        (void)owner_send_response_v21(client_fd, resp);
        return (int)resp->status;
      }
    }
    close_fds(fds);

#ifndef VIRKI_OWNER_TEST_BUILD
    /* Production verifies the owner envelope, actual context streams and
     * evidence digest, then denies because no independently provisioned C4
     * receipt signer is admitted by this DEV-only package. */
    resp->status = VIRKI_OWNER_STATUS_ERR_SIGNING_DISABLED;
    (void)owner_send_response_v21(client_fd, resp);
    return (int)resp->status;
#else
    if (!g_cfg.has_key) {
      resp->status = VIRKI_OWNER_STATUS_ERR_NO_KEY;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    if (g_ledger.sequence_floor == UINT64_MAX ||
        !v3_json_safe_string(g_cfg.owner_key_id, sizeof(g_cfg.owner_key_id)) ||
        !v3_json_safe_string(approval.key_id, sizeof(approval.key_id)) ||
        !v3_json_safe_string(approval.approval_id, sizeof(approval.approval_id)) ||
        !v3_json_safe_string(approval.approval_serial, sizeof(approval.approval_serial)) ||
        !v3_json_safe_string(approval.job_id, sizeof(approval.job_id)) ||
        !v3_json_safe_string(approval.worker_id, sizeof(approval.worker_id))) {
      resp->status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    const uint64_t expected_seq = g_ledger.sequence_floor + 1;
    char ack_json[4096];
    const int json_len = snprintf(ack_json, sizeof(ack_json),
      "{\"version\":3,\"status\":\"CANDIDATE_VERIFIED\","
      "\"ownerKeyId\":\"%s\",\"approvalKeyId\":\"%s\","
      "\"approvalId\":\"%s\",\"approvalSerial\":\"%s\","
      "\"scopeToken\":\"%s\","
      "\"approvalEnvelopeSha256\":\"%s\",\"evidenceSha256\":\"%s\","
      "\"jobId\":\"%s\",\"role\":\"%s\",\"nonce\":\"%s\","
      "\"sourceCommit\":\"%s\",\"buildPlanSha256\":\"%s\","
      "\"executablePolicySha256\":\"%s\",\"exporterIntentSha256\":\"%s\","
      "\"fileSyncManifestSha256\":\"%s\","
      "\"workerId\":\"%s\",\"outputImageId\":\"%s\","
      "\"contextTreeDigests\":[\"%s\",\"%s\",\"%s\",\"%s\"],"
      "\"contextStreamDigests\":[\"%s\",\"%s\",\"%s\",\"%s\"],"
      "\"contextStreamLengths\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],"
      "\"sequenceNumber\":%" PRIu64 ",\"epoch\":%" PRIu64 ","
      "\"deployAuthorized\":false,\"workerReceiptPairAdmitted\":false,"
      "\"releaseSignature\":false}",
      g_cfg.owner_key_id, approval.key_id,
      approval.approval_id, approval.approval_serial,
      req->scope_token,
      approval_sha, evidence_sha,
      approval.job_id, approval.role, approval.nonce,
      approval.source_commit, approval.build_plan_sha256,
      approval.executable_policy_sha256, approval.exporter_intent_sha256,
      approval.file_sync_manifest_sha256,
      approval.worker_id, approval.output_image_id,
      approval.contexts[0].tree_digest, approval.contexts[1].tree_digest,
      approval.contexts[2].tree_digest, approval.contexts[3].tree_digest,
      observed[0], observed[1], observed[2], observed[3],
      approval.contexts[0].stream_length, approval.contexts[1].stream_length,
      approval.contexts[2].stream_length, approval.contexts[3].stream_length,
      expected_seq, g_ledger.current_epoch);
    if (json_len <= 0 || json_len >= (int)sizeof(ack_json)) {
      resp->status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    uint64_t seq = 0;
    if (!ledger_record_candidate_verified(&g_ledger, req->scope_token,
        req->nonce, evidence_sha, &seq) || seq != expected_seq) {
      resp->status = VIRKI_OWNER_STATUS_ERR_LEDGER_TAMPER;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    const size_t domain_len = sizeof("VIRKI_C4_CANDIDATE_RECEIPT_V3");
    uint8_t signed_payload[sizeof(ack_json) + 64 + sizeof("VIRKI_C4_CANDIDATE_RECEIPT_V3")];
    unsigned long long signed_len = 0;
    uint8_t message[sizeof("VIRKI_C4_CANDIDATE_RECEIPT_V3") + sizeof(ack_json)];
    memcpy(message, "VIRKI_C4_CANDIDATE_RECEIPT_V3", domain_len);
    memcpy(message + domain_len, ack_json, (size_t)json_len);
    crypto_sign(signed_payload, &signed_len, message,
        (unsigned long long)(domain_len + (size_t)json_len), g_cfg.secret_key);
    char signature_b64[128];
    base64_encode(signed_payload, 64, signature_b64, sizeof(signature_b64));
    virki_abi_sha256_ctx ack_ctx;
    virki_abi_sha256_init(&ack_ctx);
    virki_abi_sha256_update(&ack_ctx, (const uint8_t *)ack_json, (size_t)json_len);
    uint8_t ack_sha[32];
    virki_abi_sha256_final(&ack_ctx, ack_sha);
    char ack_sha_hex[65];
    bytes_to_hex(ack_sha, sizeof(ack_sha), ack_sha_hex);
    resp->status = VIRKI_OWNER_STATUS_OK;
    resp->sequence_number = seq;
    snprintf(resp->owner_key_id, sizeof(resp->owner_key_id), "%s", g_cfg.owner_key_id);
    snprintf(resp->signature_base64, sizeof(resp->signature_base64), "%s", signature_b64);
    snprintf(resp->canonical_ack_sha256, sizeof(resp->canonical_ack_sha256), "%s", ack_sha_hex);
    resp->ack_json_len = (uint32_t)json_len;
    memcpy(resp->ack_json, ack_json, (size_t)json_len);
    resp->ack_json[json_len] = '\0';
    explicit_wipe(signed_payload, sizeof(signed_payload));
    explicit_wipe(message, sizeof(message));
    (void)owner_send_response_v21(client_fd, resp);
    return VIRKI_OWNER_STATUS_OK;
#endif
  }

  close_fds(fds);
  resp->status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
  (void)owner_send_response_v21(client_fd, resp);
  return (int)resp->status;
}

static void process_v3_command(int client_fd, const virki_owner_request_frame_t *req,
    int fds[VIRKI_OWNER_MAX_FD_COUNT], size_t fd_count,
    virki_owner_response_frame_t *resp, const struct ucred *peer) {
  if (!req || !resp || !peer) {
    close_fds(fds);
    if (resp) resp->status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
    if (resp) (void)owner_send_response_v21(client_fd, resp);
    return;
  }
  if (req->cmd == VIRKI_OWNER_CMD_V3_BEGIN && fd_count != 1) {
    close_fds(fds); resp->status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
    (void)owner_send_response_v21(client_fd, resp); return;
  }
  if (req->cmd == VIRKI_OWNER_CMD_V3_VERIFY_CANDIDATE && fd_count != 7) {
    close_fds(fds); resp->status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
    (void)owner_send_response_v21(client_fd, resp); return;
  }
  if (req->cmd == VIRKI_OWNER_CMD_V3_ABORT && fd_count != 0) {
    close_fds(fds); resp->status = VIRKI_OWNER_STATUS_ERR_BAD_FRAME;
    (void)owner_send_response_v21(client_fd, resp); return;
  }
  (void)v3_process_command(client_fd, req, fds, fd_count, resp, peer);
}

#endif
