/*
 * DEV-only white-box boundary arithmetic test.
 * Includes the native C translation unit with renamed main to inspect the
 * static ledger_can_append_v20 helper. This does NOT inspect a VALID 32MiB
 * ledger history; it proves append-budget math on sparse disposable files.
 */
#define main virki_owner_main_imported_for_v20_test
#include "native-owner-authority.c"
#undef main

int main(void) {
  char template_name[] = "/tmp/virki-owner-v20-cap-XXXXXX";
  int fd = mkstemp(template_name);
  if (fd < 0) return 11;
  if (unlink(template_name) != 0) return 12;
  size_t magic = strlen(VIRKI_LEDGER_MAGIC);
  if (write(fd, VIRKI_LEDGER_MAGIC, magic) != (ssize_t)magic) return 13;

  const size_t maximum_records =
      VIRKI_OWNER_REPLAY_MAX_LEDGER_V20 / sizeof(ledger_record_t);
  if (maximum_records < 3) return 14;
  off_t body = (off_t)(maximum_records-2) * (off_t)sizeof(ledger_record_t);
  if (ftruncate(fd, (off_t)magic + body) != 0) return 15;
  if (!ledger_can_append_v20(fd, 2)) return 16;
  if (!ledger_can_append_v20(fd, 1)) return 17;

  /* One free record is enough for the next RESTART epoch bump but must NOT
   * be consumed by a new runtime reservation or tombstone. */
  body += (off_t)sizeof(ledger_record_t);
  if (ftruncate(fd, (off_t)magic + body) != 0) return 18;
  if (ledger_can_append_v20(fd, 2)) return 19;
  if (!ledger_can_append_v20(fd, 1)) return 20;

  /* No capacity left; both runtime and restart must fail CLOSED. */
  body += (off_t)sizeof(ledger_record_t);
  if (ftruncate(fd, (off_t)magic + body) != 0) return 21;
  if (ledger_can_append_v20(fd, 2)) return 22;
  if (ledger_can_append_v20(fd, 1)) return 23;
  close(fd);
  puts("V20_REPLAY_APPEND_BUDGET_BOUNDARY_PASS");
  return 0;
}
