/* Exercises the actual V3 native stream verifier, not a copied model. */
#define main virki_owner_main_not_called_by_stream_test
#include "native-owner-authority.c"
#undef main

typedef struct { char kind; const char *path; uint64_t mode; const char *content; } stream_entry_fixture;

static void fixture_write_u64(uint8_t **cursor, uint64_t value) {
  for (int i = 7; i >= 0; i--) { (*cursor)[i] = (uint8_t)(value & 0xff); value >>= 8; }
  *cursor += 8;
}

static void fixture_write_bytes(uint8_t **cursor, const char *text, size_t size) {
  memcpy(*cursor, text, size);
  *cursor += size;
}

static void fixture_write_sized(uint8_t **cursor, const char *text, size_t size) {
  fixture_write_u64(cursor, size);
  fixture_write_bytes(cursor, text, size);
}

static bool fixture_native_accepts(const stream_entry_fixture *entries, size_t count) {
  uint8_t buffer[4096], *cursor = buffer;
  static const char prefix[] = "virki-context-stream-v1\0";
  fixture_write_bytes(&cursor, prefix, sizeof(prefix) - 1);
  fixture_write_sized(&cursor, "source", 6);
  virki_abi_sha256_ctx tree;
  virki_abi_sha256_init(&tree);
  virki_abi_sha256_update(&tree, (const uint8_t *)VIRKI_BUILDKIT_TREE_PREFIX_V2, VIRKI_BUILDKIT_TREE_PREFIX_V2_LEN);
  for (size_t i = 0; i < count; ++i) {
    const stream_entry_fixture *e = &entries[i];
    const size_t path_len = strlen(e->path);
    fixture_write_bytes(&cursor, &e->kind, 1);
    fixture_write_sized(&cursor, e->path, path_len);
    fixture_write_u64(&cursor, e->mode);
    virki_abi_sha256_update(&tree, (const uint8_t *)&e->kind, 1);
    virki_abi_write_sized(&tree, (const uint8_t *)e->path, path_len);
    virki_abi_write_uint64(&tree, e->mode);
    if (e->kind == 'F' || e->kind == 'L') {
      const size_t size = strlen(e->content);
      fixture_write_u64(&cursor, size);
      fixture_write_bytes(&cursor, e->content, size);
      virki_abi_write_uint64(&tree, size);
      if (e->kind == 'F') {
        virki_abi_sha256_ctx file;
        virki_abi_sha256_init(&file);
        virki_abi_sha256_update(&file, (const uint8_t *)e->content, size);
        uint8_t file_sha[32];
        virki_abi_sha256_final(&file, file_sha);
        virki_abi_sha256_update(&tree, file_sha, sizeof(file_sha));
      } else {
        virki_abi_sha256_update(&tree, (const uint8_t *)e->content, size);
      }
    }
  }
  uint8_t tree_sha[32];
  char digest_hex[65], digest[73];
  virki_abi_sha256_final(&tree, tree_sha);
  bytes_to_hex(tree_sha, sizeof(tree_sha), digest_hex);
  snprintf(digest, sizeof(digest), "sha256:%s", digest_hex);
  char path[] = "/tmp/virki-c4-v3-stream-XXXXXX";
  const int fd = mkstemp(path);
  if (fd < 0) abort();
  if (unlink(path) != 0) abort();
  const size_t total = (size_t)(cursor - buffer);
  if (write(fd, buffer, total) != (ssize_t)total) abort();
  const bool accepted = v3_verify_context_stream_tree(fd, total, "source", digest);
  close(fd);
  return accepted;
}

int main(void) {
  static const stream_entry_fixture valid[] = {
    {'D', "a", 0755, NULL}, {'F', "a/x", 0644, "x"},
    {'F', "a-b", 0644, "y"}, {'L', "z-link", 0777, "a/x"},
  };
  if (!fixture_native_accepts(valid, 4)) return 2;
  static const stream_entry_fixture missing_parent[] = {{'F', "missing/file", 0644, "x"}};
  static const stream_entry_fixture reversed[] = {{'F', "z", 0644, "z"}, {'F', "a", 0644, "a"}};
  static const stream_entry_fixture forged_traversal[] = {{'F', "../outside", 0644, "x"}};
  static const stream_entry_fixture repeated[] = {{'F', "same", 0644, "x"}, {'F', "same", 0644, "y"}};
  /* Node's C1->C4 canonical context parser rejects wildcard/ASCII control
   * names; C4 must not authorize the same hash-consistent divergent stream. */
  static const stream_entry_fixture wildcard[] = {{'F', "payload[1]*.txt", 0644, "x"}};
  static const stream_entry_fixture control[] = {{'F', "audit\nrecord", 0644, "x"}};
  static const stream_entry_fixture valid_utf8[] = {{'F', "dados-\xc3\xa1.txt", 0644, "x"}};
  static const stream_entry_fixture invalid_utf8[] = {{'F', "payload-\xff", 0644, "x"}};
  static const stream_entry_fixture invalid_surrogate[] = {{'F', "payload-\xed\xa0\x80", 0644, "x"}};
  /* TextDecoder's default BOM handling drops EF BB BF at the beginning of
   * each pathname. Node then rejects the resulting '.' / '..' segments;
   * native C4 must not sign a stream that fails the C1 contract. */
  static const stream_entry_fixture bom_dot[] = {{'F', "\xef\xbb\xbf.", 0644, "x"}};
  static const stream_entry_fixture bom_dotdot[] = {{'F', "\xef\xbb\xbf..", 0644, "x"}};
  if (fixture_native_accepts(missing_parent, 1)) { puts("FAIL: missing parent accepted"); return 3; }
  if (fixture_native_accepts(reversed, 2)) { puts("FAIL: unsorted entries accepted"); return 4; }
  if (fixture_native_accepts(forged_traversal, 1)) { puts("FAIL: traversal path accepted"); return 5; }
  if (fixture_native_accepts(repeated, 2)) { puts("FAIL: duplicate path accepted"); return 6; }
  if (fixture_native_accepts(wildcard, 1)) { puts("FAIL: wildcard name accepted"); return 7; }
  if (fixture_native_accepts(control, 1)) { puts("FAIL: control-character name accepted"); return 8; }
  if (!fixture_native_accepts(valid_utf8, 1)) { puts("FAIL: valid UTF-8 name rejected"); return 9; }
  if (fixture_native_accepts(invalid_utf8, 1)) { puts("FAIL: invalid UTF-8 name accepted"); return 10; }
  if (fixture_native_accepts(invalid_surrogate, 1)) { puts("FAIL: UTF-8 encoded surrogate accepted"); return 11; }
  if (fixture_native_accepts(bom_dot, 1)) { puts("FAIL: leading UTF-8 BOM hides a dot segment from Node"); return 13; }
  if (fixture_native_accepts(bom_dotdot, 1)) { puts("FAIL: leading UTF-8 BOM hides a parent segment from Node"); return 14; }
  char too_long[514];
  memset(too_long, 'x', sizeof(too_long) - 1);
  too_long[sizeof(too_long) - 1] = '\0';
  const stream_entry_fixture long_path[] = {{'F', too_long, 0644, "x"}};
  if (fixture_native_accepts(long_path, 1)) { puts("FAIL: path over 512 UTF-16 code units accepted"); return 12; }
  puts("C4_NATIVE_CANONICAL_WALK_STREAM_PASS");
  return 0;
}
