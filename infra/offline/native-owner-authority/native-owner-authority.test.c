#define _GNU_SOURCE
#include "native-owner-authority-protocol.h"
#include "buildkit-context-abi.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

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
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) abort();
    while (offset < length) {
      size_t to_read = (length - offset > 256) ? 256 : (size_t)(length - offset);
      ssize_t n = read(fd, ptr + offset, to_read);
      if (n > 0) offset += (unsigned long long)n;
      else { close(fd); abort(); }
    }
    close(fd);
    break;
  }
}

#include "tweetnacl.h"
#include "tweetnacl.c"

_Static_assert(sizeof(virki_owner_v3_context_claim_t) == 316,
    "VROA_V3 context claim ABI drift");
_Static_assert(sizeof(virki_owner_approval_envelope_v3_t) == 2669,
    "VROA_V3 approval envelope ABI drift");
_Static_assert(sizeof(virki_owner_candidate_evidence_v3_t) == 1347,
    "VROA_V3 evidence header ABI drift");

static void test_key_generation_and_signing_verification(void) {
  uint8_t pk[32];
  uint8_t sk[64];
  assert(crypto_sign_keypair(pk, sk) == 0);

  const char message[] = "{\"approvalId\":\"app-test-01\",\"nonce\":\"11223344556677889900aabbccddeeff\"}";
  unsigned long long smlen = 0;
  uint8_t sm[sizeof(message) + 64];
  assert(crypto_sign(sm, &smlen, (const unsigned char *)message, strlen(message), sk) == 0);
  assert(smlen == strlen(message) + 64);

  // Verification with authentic public key succeeds
  unsigned long long mlen = 0;
  uint8_t m[sizeof(message) + 64];
  assert(crypto_sign_open(m, &mlen, sm, smlen, pk) == 0);
  assert(mlen == strlen(message));
  assert(memcmp(m, message, mlen) == 0);

  // Verification with tampered message fails closed
  sm[64] ^= 0x01;
  assert(crypto_sign_open(m, &mlen, sm, smlen, pk) != 0);

  // Verification with wrong public key fails closed
  uint8_t wrong_pk[32];
  uint8_t wrong_sk[64];
  assert(crypto_sign_keypair(wrong_pk, wrong_sk) == 0);
  sm[64] ^= 0x01; // restore valid signature
  assert(crypto_sign_open(m, &mlen, sm, smlen, wrong_pk) != 0);

  printf("PASS: test_key_generation_and_signing_verification\n");
}

static void test_protocol_frame_sizes_and_alignment(void) {
  virki_owner_request_frame_t req;
  virki_owner_response_frame_t resp;

  memset(&req, 0, sizeof(req));
  memset(&resp, 0, sizeof(resp));

  assert(sizeof(req.magic) == 8);
  assert(sizeof(resp.magic) == 8);
  assert(VIRKI_OWNER_CONTEXT_COUNT == 4);

  printf("PASS: test_protocol_frame_sizes_and_alignment (req=%zu bytes, resp=%zu bytes)\n",
         sizeof(req), sizeof(resp));
}

static void hash_dfs_dir_entry(virki_abi_sha256_ctx *ctx, const char *rel, uint64_t mode) {
  const uint8_t tag = 'D';
  virki_abi_sha256_update(ctx, &tag, 1);
  virki_abi_write_sized(ctx, (const uint8_t *)rel, strlen(rel));
  virki_abi_write_uint64(ctx, mode);
}

static void hash_dfs_file_entry(virki_abi_sha256_ctx *ctx, const char *rel, uint64_t mode, const uint8_t *content, size_t len) {
  const uint8_t tag = 'F';
  virki_abi_sha256_update(ctx, &tag, 1);
  virki_abi_write_sized(ctx, (const uint8_t *)rel, strlen(rel));
  virki_abi_write_uint64(ctx, mode);
  virki_abi_write_uint64(ctx, (uint64_t)len);
  virki_abi_sha256_ctx fctx;
  virki_abi_sha256_init(&fctx);
  virki_abi_sha256_update(&fctx, content, len);
  uint8_t fsha[32];
  virki_abi_sha256_final(&fctx, fsha);
  virki_abi_sha256_update(ctx, fsha, 32);
}

static void test_nested_depth_first_traversal_matches_go(void) {
  char tmpl[] = "/tmp/virki-abi-dfs-XXXXXX";
  char *root = mkdtemp(tmpl);
  assert(root != NULL);

  char dir_a[256], file_ax[256], file_ab[256];
  snprintf(dir_a, sizeof(dir_a), "%s/a", root);
  snprintf(file_ax, sizeof(file_ax), "%s/a/x", root);
  snprintf(file_ab, sizeof(file_ab), "%s/a-b", root);
  assert(mkdir(dir_a, 0755) == 0);
  assert(chmod(dir_a, 0755) == 0);

  const uint8_t data_x[] = "x-data";
  const uint8_t data_ab[] = "ab-data";
  int fd = open(file_ax, O_WRONLY | O_CREAT | O_EXCL, 0644);
  assert(fd >= 0);
  assert(write(fd, data_x, sizeof(data_x) - 1) == (ssize_t)(sizeof(data_x) - 1));
  close(fd);
  assert(chmod(file_ax, 0644) == 0);

  fd = open(file_ab, O_WRONLY | O_CREAT | O_EXCL, 0644);
  assert(fd >= 0);
  assert(write(fd, data_ab, sizeof(data_ab) - 1) == (ssize_t)(sizeof(data_ab) - 1));
  close(fd);
  assert(chmod(file_ab, 0644) == 0);

  virki_buildkit_local_context_observation_t obs;
  assert(virki_observe_local_context_v2(root, "source", &obs));

  /* Expected order from Go filepath.WalkDir: "a" -> "a/x" -> "a-b". */
  virki_abi_sha256_ctx expected_ctx;
  virki_abi_sha256_init(&expected_ctx);
  virki_abi_sha256_update(&expected_ctx, (const uint8_t *)VIRKI_BUILDKIT_TREE_PREFIX_V2, VIRKI_BUILDKIT_TREE_PREFIX_V2_LEN);
  hash_dfs_dir_entry(&expected_ctx, "a", 0755);
  hash_dfs_file_entry(&expected_ctx, "a/x", 0644, data_x, sizeof(data_x) - 1);
  hash_dfs_file_entry(&expected_ctx, "a-b", 0644, data_ab, sizeof(data_ab) - 1);
  uint8_t expected_sha[32];
  virki_abi_sha256_final(&expected_ctx, expected_sha);
  char expected_digest[73];
  snprintf(expected_digest, sizeof(expected_digest), "sha256:");
  for (int i = 0; i < 32; i++) {
    snprintf(expected_digest + 7 + (size_t)i * 2, 3, "%02x", expected_sha[i]);
  }
  assert(strcmp(obs.digest, expected_digest) == 0);

  unlink(file_ax);
  unlink(file_ab);
  rmdir(dir_a);
  rmdir(root);
  printf("PASS: test_nested_depth_first_traversal_matches_go\n");
}

static void test_truncated_symlink_target_rejected(void) {
  char tmpl[] = "/tmp/virki-abi-sym-XXXXXX";
  char *root = mkdtemp(tmpl);
  assert(root != NULL);

  char long_target[1042];
  memset(long_target, 'x', sizeof(long_target) - 1);
  long_target[sizeof(long_target) - 1] = '\0';

  char link_path[256];
  snprintf(link_path, sizeof(link_path), "%s/longlink", root);
  assert(symlink(long_target, link_path) == 0);

  virki_buildkit_local_context_observation_t obs;
  assert(!virki_observe_local_context_v2(root, "source", &obs));

  unlink(link_path);
  rmdir(root);
  printf("PASS: test_truncated_symlink_target_rejected\n");
}

int main(void) {
  printf("=== Running Owner Authority Unit Tests ===\n");
  test_key_generation_and_signing_verification();
  test_protocol_frame_sizes_and_alignment();
  test_nested_depth_first_traversal_matches_go();
  test_truncated_symlink_target_rejected();
  printf("=== All Owner Authority Unit Tests PASSED ===\n");
  return 0;
}
