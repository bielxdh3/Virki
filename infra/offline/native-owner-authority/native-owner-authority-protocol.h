#ifndef VIRKI_NATIVE_OWNER_AUTHORITY_PROTOCOL_H
#define VIRKI_NATIVE_OWNER_AUTHORITY_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define VIRKI_OWNER_PROTOCOL_VERSION 2
#define VIRKI_OWNER_PROTOCOL_MAGIC "VROA_V2\0"
#define VIRKI_OWNER_CONTEXT_COUNT 4
#define VIRKI_OWNER_MAX_PAYLOAD_BYTES (64 * 1024 * 1024) /* 64 MB max context size */

/* Standard context names in canonical order */
static const char *const VIRKI_OWNER_CONTEXT_NAMES[VIRKI_OWNER_CONTEXT_COUNT] = {
  "source",
  "dockerfile",
  "offline-npm-cacache",
  "offline-prisma-engines"
};

/* Request commands */
enum virki_owner_cmd {
  VIRKI_OWNER_CMD_STATUS       = 0x01,
  VIRKI_OWNER_CMD_SCOPE_BEGIN  = 0x02,
  VIRKI_OWNER_CMD_SIGN_ACK     = 0x03,
  VIRKI_OWNER_CMD_SCOPE_ABORT  = 0x04,
};

/* Response status codes */
enum virki_owner_status {
  VIRKI_OWNER_STATUS_OK                  = 0,
  VIRKI_OWNER_STATUS_ERR_PEERCRED        = 10,
  VIRKI_OWNER_STATUS_ERR_BAD_FRAME       = 11,
  VIRKI_OWNER_STATUS_ERR_FD_INVALID      = 12,
  VIRKI_OWNER_STATUS_ERR_STREAM_MISMATCH = 13,
  VIRKI_OWNER_STATUS_ERR_TREE_MISMATCH   = 14,
  VIRKI_OWNER_STATUS_ERR_NONCE_REPLAY    = 15,
  VIRKI_OWNER_STATUS_ERR_STALE_EPOCH     = 16,
  VIRKI_OWNER_STATUS_ERR_NO_KEY          = 17,
  VIRKI_OWNER_STATUS_ERR_LEDGER_TAMPER   = 18,
  VIRKI_OWNER_STATUS_ERR_PROVENANCE_FAIL = 19,
  VIRKI_OWNER_STATUS_ERR_SCOPE_NOT_FOUND = 20,
  VIRKI_OWNER_STATUS_ERR_SCOPE_ABORTED   = 21,
  VIRKI_OWNER_STATUS_ERR_SIGNING_DISABLED = 22, /* DEV: no physical independent C4 receipt */
};

/* Wire Request Frame */
typedef struct {
  char magic[8];                 /* "VROA_V2\0" */
  uint32_t version;              /* 2 */
  uint32_t cmd;                  /* enum virki_owner_cmd */
  uint64_t epoch;                /* expected monotonic epoch */
  char scope_token[65];          /* hex scope token (64 hex chars + \0) */
  char session_id[65];           /* session ID */
  char job_id[65];               /* job ID */
  char role[16];                 /* "runtime" | "migrator" */
  char nonce[33];                /* 32 hex chars + \0 */
  char source_commit[41];        /* 40 hex chars git commit */
  char build_plan_sha256[65];    /* 64 hex chars */
  char executable_policy_sha256[65]; /* 64 hex chars */
  char output_image_id[73];      /* "sha256:<64 hex>" */
  char expected_tree_digests[VIRKI_OWNER_CONTEXT_COUNT][73];   /* "sha256:<64 hex>" */
  char expected_stream_digests[VIRKI_OWNER_CONTEXT_COUNT][73]; /* "sha256:<64 hex>" */
  uint64_t expected_stream_lengths[VIRKI_OWNER_CONTEXT_COUNT];
  char archive_sha256[65];       /* 64 hex chars */
  uint64_t archive_bytes;
  char transcript_sha256[65];    /* 64 hex chars */
  char approval_key_id[65];
  char approval_id[65];
  char approval_serial[65];
  char approval_envelope_sha256[65];
} __attribute__((packed)) virki_owner_request_frame_t;

/* Wire Response Frame */
typedef struct {
  char magic[8];                 /* "VROA_V2\0" */
  uint32_t version;              /* 2 */
  uint32_t status;               /* enum virki_owner_status */
  uint64_t epoch;                /* current active epoch */
  uint64_t sequence_number;      /* monotonic sequence number */
  char scope_token[65];          /* issued scope token (on SCOPE_BEGIN) */
  char owner_key_id[65];         /* owner signing key ID */
  char signature_base64[128];    /* Ed25519 signature base64 */
  char canonical_ack_sha256[65]; /* SHA-256 of canonical signed ACK JSON */
  uint32_t ack_json_len;         /* length of canonical ACK JSON payload */
  char ack_json[4096];           /* canonical ACK JSON payload */
} __attribute__((packed)) virki_owner_response_frame_t;

#endif
