/*
 * DEV-only C4 v20 ledger recovery verifier.
 *
 * Checks the *transaction history*, not merely individual record shapes.
 * A valid-looking orphan ABORT/COMMIT, duplicated reservation, sequence gap
 * or epoch rollback must not result in a recovered READY owner process.
 * Deliberately does not authorize SIGN_ACK, which remains hard disabled.
 *
 * Included exactly once after ledger_record_shape_valid in the native owner
 * translation unit; this header is not a reusable external authorization API.
 */
#ifndef VIRKI_OWNER_LEDGER_REPLAY_V20_H
#define VIRKI_OWNER_LEDGER_REPLAY_V20_H

typedef struct {
  char scope_token[65];
  char nonce[33];
  uint64_t epoch;
  uint64_t prepare_seq;
  bool terminal;
} ledger_replay_scope_v20_t;

static unsigned char ledger_replay_hex_fold_v20(unsigned char ch) {
  return (ch >= 'A' && ch <= 'F') ? (unsigned char)(ch - 'A' + 'a') : ch;
}

static bool ledger_replay_hex_equal_v20(const char *a, const char *b) {
  for (; *a && *b; a++,b++) {
    if (ledger_replay_hex_fold_v20((unsigned char)*a) !=
        ledger_replay_hex_fold_v20((unsigned char)*b)) return false;
  }
  return *a == *b;
}

static uint64_t ledger_replay_hash_v20(const char *s) {
  uint64_t h = UINT64_C(14695981039346656037);
  for (; *s; s++) {
    h ^= ledger_replay_hex_fold_v20((unsigned char)*s);
    h *= UINT64_C(1099511628211);
  }
  return h;
}

/* Hash table values are the original scope index PLUS ONE (0 = empty).
 * Separate tables enforce scope-token uniqueness and nonce uniqueness.
 * Bounded open addressing avoids quadratic startup on a large history. */
static size_t ledger_replay_find_v20(const size_t *slots, size_t capacity,
    const ledger_replay_scope_v20_t *scopes, const char *value, bool nonce) {
  size_t offset = (size_t)(ledger_replay_hash_v20(value) & (capacity - 1));
  for (size_t scanned = 0; scanned < capacity; scanned++) {
    const size_t stored = slots[offset];
    if (stored == 0) return SIZE_MAX;
    const char *candidate = nonce ? scopes[stored-1].nonce : scopes[stored-1].scope_token;
    if (ledger_replay_hex_equal_v20(candidate, value)) return stored-1;
    offset = (offset+1) & (capacity-1);
  }
  return SIZE_MAX;
}

static bool ledger_replay_insert_v20(size_t *slots, size_t capacity,
    const char *value, size_t scope_index) {
  size_t offset = (size_t)(ledger_replay_hash_v20(value) & (capacity-1));
  for (size_t scanned = 0; scanned < capacity; scanned++) {
    if (slots[offset] == 0) {
      slots[offset] = scope_index+1;
      return true;
    }
    offset = (offset+1) & (capacity-1);
  }
  return false;
}

/* Existing V2 files may have zero records (header-only). Limit parsing and
 * memory allocation explicitly; a giant or hostile ledger must fail closed
 * rather than exhaust owner process memory before installing its socket. */
#define VIRKI_OWNER_REPLAY_MAX_LEDGER_V20 (32U * 1024U * 1024U)

static bool ledger_replay_verify_v20(int fd, off_t body_bytes,
    uint64_t *out_epoch, uint64_t *out_sequence) {
  if (fd < 0 || !out_epoch || !out_sequence || body_bytes < 0 ||
      (uint64_t)body_bytes > VIRKI_OWNER_REPLAY_MAX_LEDGER_V20 ||
      body_bytes % (off_t)sizeof(ledger_record_t) != 0) return false;
  size_t count = (size_t)(body_bytes / (off_t)sizeof(ledger_record_t));
  if (count == 0) {
    /* Crash after the first durable MAGIC/header fsync but before initial
     * epoch bump: recover the SAME virgin bootstrap sequence 1001.
     * This marker is never a READY epoch by itself. */
    *out_epoch = 0;
    *out_sequence = 1000;
    return true;
  }
  size_t capacity = 1;
  while (capacity < count*2+1) {
    if (capacity > SIZE_MAX/2) return false;
    capacity <<= 1;
  }
  ledger_replay_scope_v20_t *scopes =
      calloc(count ? count : 1, sizeof(*scopes));
  size_t *scope_slots = calloc(capacity, sizeof(*scope_slots));
  size_t *nonce_slots = calloc(capacity, sizeof(*nonce_slots));
  if (!scopes || !scope_slots || !nonce_slots) {
    free(scopes); free(scope_slots); free(nonce_slots);
    return false;
  }

  bool valid = true;
  size_t seen_scopes = 0;
  uint64_t epoch = 0;
  uint64_t sequence = 0;
  for (size_t i = 0; i < count && valid; i++) {
    ledger_record_t rec;
    const off_t offset = (off_t)strlen(VIRKI_LEDGER_MAGIC) +
        (off_t)i * (off_t)sizeof(rec);
    if (pread(fd, &rec, sizeof(rec), offset) != (ssize_t)sizeof(rec) ||
        !ledger_record_shape_valid(&rec)) {
      valid = false; break;
    }
    if (strcmp(rec.scope_token, "EPOCH_ADVANCE") == 0) {
      if ((epoch == 0 && (rec.epoch != 1 || rec.seq != 1001)) ||
          (epoch != 0 && (epoch == UINT64_MAX ||
             sequence == UINT64_MAX || rec.epoch != epoch+1 ||
             rec.seq != sequence+1))) {
        valid = false; break;
      }
      epoch = rec.epoch;
      sequence = rec.seq;
      continue;
    }

    if (epoch == 0 || rec.epoch != epoch) {
      valid = false; break;
    }
    if (rec.type == REC_TYPE_PREPARE) {
      if (sequence == UINT64_MAX || rec.seq != sequence+1 ||
          ledger_replay_find_v20(scope_slots,capacity,scopes,rec.scope_token,false) != SIZE_MAX ||
          ledger_replay_find_v20(nonce_slots,capacity,scopes,rec.nonce,true) != SIZE_MAX ||
          seen_scopes >= count) {
        valid = false; break;
      }
      ledger_replay_scope_v20_t *scope = &scopes[seen_scopes];
      memcpy(scope->scope_token,rec.scope_token,sizeof(scope->scope_token));
      memcpy(scope->nonce,rec.nonce,sizeof(scope->nonce));
      scope->epoch = rec.epoch;
      scope->prepare_seq = rec.seq;
      if (!ledger_replay_insert_v20(scope_slots,capacity,scope->scope_token,seen_scopes) ||
          !ledger_replay_insert_v20(nonce_slots,capacity,scope->nonce,seen_scopes)) {
        valid = false; break;
      }
      seen_scopes++;
      sequence = rec.seq;
      continue;
    }

    const size_t index = ledger_replay_find_v20(scope_slots,capacity,scopes,rec.scope_token,false);
    if (index == SIZE_MAX || scopes[index].terminal || scopes[index].epoch != epoch) {
      valid = false; break;
    }
    if (rec.type == REC_TYPE_ABORTED) {
      /* ABORT consumes a NEW durable sequence; its historical record has
       * an empty nonce, but must be preceded by this live prepared scope. */
      if (sequence == UINT64_MAX || rec.seq != sequence+1) {
        valid = false; break;
      }
      scopes[index].terminal = true;
      sequence = rec.seq;
    } else if (rec.type == REC_TYPE_COMMITTED) {
      /* The original 0e22b29 SIGN_ACK writer allocated a NEW sequence for
       * COMMIT, not the PREPARE sequence. Preserve only this proven legacy
       * transition: live prepared scope, same epoch/nonce, next sequence.
       * V20 cannot produce a new COMMIT because SIGN_ACK stays OFF. */
      if (sequence == UINT64_MAX || rec.seq != sequence+1 ||
          strcmp(rec.nonce,scopes[index].nonce) != 0) {
        valid = false; break;
      }
      scopes[index].terminal = true;
      sequence = rec.seq;
    } else {
      valid = false;
    }
  }

  free(nonce_slots);
  free(scope_slots);
  free(scopes);
  if (!valid) return false;
  *out_epoch = epoch;
  *out_sequence = sequence;
  return true;
}

/* A bounded replay parser must not allow the live writer to produce a file
 * it cannot recover on its very next restart. Failure to reserve room for
 * a new durable record is a fail-closed availability stop, not permission
 * to skip validation or wrap the sequence. */
static bool ledger_can_append_v20(int fd, size_t required_records) {
  struct stat st;
  if (fd < 0 || required_records == 0 || required_records > 2 ||
      fstat(fd, &st) != 0) return false;
  const off_t magic = (off_t)strlen(VIRKI_LEDGER_MAGIC);
  if (!S_ISREG(st.st_mode) || st.st_size < magic) return false;
  const off_t body = st.st_size - magic;
  if (body < 0 || body % (off_t)sizeof(ledger_record_t) != 0 ||
      (uint64_t)body > (uint64_t)VIRKI_OWNER_REPLAY_MAX_LEDGER_V20 -
                           required_records * sizeof(ledger_record_t)) return false;
  return true;
}

#endif
