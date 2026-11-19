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

int main(void) {
  printf("=== Running Owner Authority Unit Tests ===\n");
  test_key_generation_and_signing_verification();
  test_protocol_frame_sizes_and_alignment();
  printf("=== All Owner Authority Unit Tests PASSED ===\n");
  return 0;
}
