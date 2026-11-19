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

static bool v3_validate_evidence_fd(int fd,
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
  memcpy(evidence_sha256, prefixed + 7, 65);
  return true;
}

static int v3_validate_context_fds(const int fds[VIRKI_OWNER_MAX_FD_COUNT],
    const virki_owner_request_frame_t *req, struct stat stats[6],
    char observed[VIRKI_OWNER_CONTEXT_COUNT][65]) {
  for (size_t i = 0; i < VIRKI_OWNER_CONTEXT_COUNT; i++) {
    char prefixed[73];
    if (!v3_validate_sealed_payload_fd(fds[i], 1, VIRKI_OWNER_MAX_PAYLOAD_BYTES,
        req->expected_stream_lengths[i], &stats[i], prefixed)) return VIRKI_OWNER_STATUS_ERR_FD_INVALID;
    if (strcmp(prefixed, req->expected_stream_digests[i]) != 0) return VIRKI_OWNER_STATUS_ERR_STREAM_MISMATCH;
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
    if (fd_count != 6 || req->epoch != g_ledger.current_epoch ||
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
    if (!v3_validate_evidence_fd(fds[5], req, &approval, approval_sha,
        evidence_sha, &evidence_stat)) {
      close_fds(fds);
      resp->status = VIRKI_OWNER_STATUS_ERR_PROVENANCE_FAIL;
      (void)owner_send_response_v21(client_fd, resp);
      return (int)resp->status;
    }
    for (size_t i = 0; i < VIRKI_OWNER_CONTEXT_COUNT + 1; i++) {
      const struct stat *left = i < VIRKI_OWNER_CONTEXT_COUNT ? &context_stats[i] : &approval_stat;
      if (left->st_dev == evidence_stat.st_dev && left->st_ino == evidence_stat.st_ino) {
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
  if (req->cmd == VIRKI_OWNER_CMD_V3_VERIFY_CANDIDATE && fd_count != 6) {
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
