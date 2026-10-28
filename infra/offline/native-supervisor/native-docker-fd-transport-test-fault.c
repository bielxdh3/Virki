/*
 * Opt-in standalone test-only source-I/O fault injection. Linked only by
 * explicit VDT_DISPOSABLE_TEST_SOURCE_FAULT in the disposable fixture build.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
ssize_t vdt_disposable_test_pread(int fd, void *buf, size_t count, off_t offset) {
  (void)fd;
  static int delayed = 0;
  if (offset == 0 && !delayed) {
    const char *delay = getenv("VIRKI_TEST_DELAY_SOURCE_PREAD_MS");
    if (delay) {
      delayed = 1;
      char *end = NULL;
      long ms = strtol(delay, &end, 10);
      if (end && *end == 0 && ms > 0 && ms <= 5000) {
        struct timespec ts = {.tv_sec = ms / 1000,
                              .tv_nsec = (ms % 1000) * 1000000L};
        while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
      }
    }
  }
  return pread(fd, buf, count, offset);
}
ssize_t vdt_disposable_test_pwrite(int fd, const void *buf, size_t count,
                                  off_t offset) {
  static int delayed = 0;
  if (offset == 0 && !delayed) {
    const char *delay = getenv("VIRKI_TEST_DELAY_STAGE_PWRITE_MS");
    if (delay) {
      delayed = 1;
      char *end = NULL;
      long ms = strtol(delay, &end, 10);
      if (end && *end == 0 && ms > 0 && ms <= 5000) {
        struct timespec ts = {.tv_sec = ms / 1000,
                              .tv_nsec = (ms % 1000) * 1000000L};
        while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
      }
    }
  }
  return pwrite(fd, buf, count, offset);
}
