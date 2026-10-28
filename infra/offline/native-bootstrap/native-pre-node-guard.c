/*
 * DEV-ONLY native pre-Node byte/ELF guard. NOT an installation, release
 * authority, deployment mechanism, Node verifier graph entry or signer.
 *
 * Production has FIXED owner-provisioned paths and refuses WSL. The fixture
 * build is a distinct compiler opt-in with only /root/ disposable paths.
 * The two owner-controlled SHA256 pins are NOT signatures or provenance.
 * No keys are generated; trust depends on real, independent root provisioning.
 *
 * We do not execute dynamically linked ELF: a pinned executable FD does not
 * pin PT_INTERP's loader or later DT_NEEDED objects. Actual stock Node often
 * has PT_INTERP and will correctly be refused, rather than fake a proof.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/close_range.h>
#include <linux/capability.h>
#include <linux/if_alg.h>
#include <linux/memfd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef VIRKI_TEST_ONLY_ROOT_FIXTURE
#define VIRKI_PIN_PATH "/etc/virki/offline-native-guard/owner-pin.txt"
#define VIRKI_OWNER_PATH "/etc/virki/offline-bootstrap/bootstrap-policy.json"
#define VIRKI_NODE_PATH "/usr/bin/node"
#define VIRKI_LAUNCHER_PATH "/usr/local/lib/virki/offline-bootstrap/native-pre-node-guard"
#endif

#define GUARD_MAGIC "VIRKI_DEV_NATIVE_GUARD_PIN_V1\n"
#define GUARD_MAX_NODE (128ULL * 1024 * 1024)

static bool hex64(const char *s) {
  if (!s || strlen(s) != 64) return false;
  for (size_t i = 0; i < 64; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
      return false;
  return true;
}
static bool same(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
    a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
    a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
    a->st_size == b->st_size &&
    a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
    a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
    a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
    a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
/* No symlinks, writable ancestors or non-root ownership at any path level. */
static bool anchored_path(const char *filename, bool directory) {
  if (!filename || filename[0] != '/' || strstr(filename, "//") ||
      strstr(filename, "/./") || strstr(filename, "/../") ||
      strlen(filename) >= 4096) return false;
  char current[4096];
  size_t n = strlen(filename);
  memcpy(current, filename, n + 1);
  for (;;) {
    struct stat st;
    if (lstat(current, &st) || st.st_uid != 0 || st.st_gid != 0 ||
        (st.st_mode & 0022) != 0 || S_ISLNK(st.st_mode)) return false;
    bool at_target = strlen(current) == n;
    if (at_target ? (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))
                  : !S_ISDIR(st.st_mode)) return false;
    if (strcmp(current, "/") == 0) return true;
    char *end = strrchr(current, '/');
    if (!end) return false;
    if (end == current) current[1] = 0;
    else *end = 0;
  }
}
static int owner_fd(const char *filename, mode_t expected, size_t max) {
  if (!anchored_path(filename, false)) return -1;
  struct stat before, opened;
  if (lstat(filename, &before) || before.st_nlink != 1 ||
      before.st_size <= 0 || (uint64_t)before.st_size > max ||
      (expected && (before.st_mode & 07777) != expected)) return -1;
  int fd = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) return -1;
  if (fstat(fd, &opened) || !same(&before, &opened)) {
    close(fd);
    return -1;
  }
  return fd;
}
static bool exact_fd(int fd, const char *filename, const struct stat *before) {
  struct stat now, named;
  return fstat(fd, &now) == 0 && lstat(filename, &named) == 0 &&
    same(before, &now) && same(before, &named) &&
    anchored_path(filename, false);
}
static bool bytes_sha(int fd, const char *filename, char result[65],
                      int copy_fd, size_t maximum) {
  struct stat before;
  if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_size <= 0 ||
      (uint64_t)before.st_size > maximum) return false;
  /* Kernel SHA256 avoids dynamically linked crypto providers in this
   * statically linked pre-Node binary; never dlopen user-space modules. */
  int hash_socket = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (hash_socket < 0) return false;
  struct sockaddr_alg algorithm = { .salg_family = AF_ALG };
  memcpy(algorithm.salg_type, "hash", 5);
  memcpy(algorithm.salg_name, "sha256", 7);
  if (bind(hash_socket, (struct sockaddr *)&algorithm, sizeof algorithm)) {
    close(hash_socket);
    return false;
  }
  int operation = accept4(hash_socket, NULL, NULL, SOCK_CLOEXEC);
  close(hash_socket);
  if (operation < 0) return false;
  bool good = true;
  unsigned char buf[16384], hash[32];
  for (off_t offset = 0; good && offset < before.st_size;) {
    size_t want = (uint64_t)(before.st_size - offset) > sizeof buf
      ? sizeof buf : (size_t)(before.st_size - offset);
    ssize_t got = pread(fd, buf, want, offset);
    if (got <= 0) {
      good = false; break;
    }
    if (copy_fd >= 0) {
      for (ssize_t used = 0; used < got;) {
        ssize_t wrote = pwrite(copy_fd, buf + used, (size_t)(got - used),
                               offset + used);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) { good = false; break; }
        used += wrote;
      }
    }
    for (ssize_t used = 0; good && used < got;) {
      int flags = offset + got == before.st_size ? 0 : MSG_MORE;
      ssize_t sent = send(operation, buf + used, (size_t)(got - used),
                          flags | MSG_NOSIGNAL);
      if (sent < 0 && errno == EINTR) continue;
      if (sent <= 0) { good = false; break; }
      used += sent;
    }
    offset += got;
  }
  if (good) good = read(operation, hash, sizeof hash) == (ssize_t)sizeof hash &&
    exact_fd(fd, filename, &before);
  close(operation);
  if (!good) return false;
  static const char alphabet[] = "0123456789abcdef";
  for (size_t i = 0; i < sizeof hash; i++) {
    result[i * 2] = alphabet[hash[i] >> 4];
    result[i * 2 + 1] = alphabet[hash[i] & 15];
  }
  result[64] = 0;
  return true;
}
static bool no_dynamic_loader(int fd, off_t size) {
  Elf64_Ehdr elf;
  if (size < (off_t)sizeof elf ||
      pread(fd, &elf, sizeof elf, 0) != (ssize_t)sizeof elf ||
      memcmp(elf.e_ident, ELFMAG, SELFMAG) ||
      elf.e_ident[EI_CLASS] != ELFCLASS64 ||
      elf.e_ident[EI_DATA] != ELFDATA2LSB ||
      elf.e_machine != EM_X86_64 || elf.e_type != ET_EXEC ||
      elf.e_version != EV_CURRENT ||
      elf.e_phentsize != sizeof(Elf64_Phdr) ||
      elf.e_phnum == 0 || elf.e_phnum > 64 ||
      elf.e_phoff > (uint64_t)size ||
      (uint64_t)elf.e_phnum * sizeof(Elf64_Phdr) >
        (uint64_t)size - elf.e_phoff) return false;
  bool code = false;
  for (unsigned i = 0; i < elf.e_phnum; i++) {
    Elf64_Phdr ph;
    off_t where = (off_t)(elf.e_phoff + i * sizeof ph);
    if (pread(fd, &ph, sizeof ph, where) != (ssize_t)sizeof ph ||
        ph.p_type == PT_INTERP || ph.p_type == PT_DYNAMIC ||
        (ph.p_type == PT_GNU_STACK && (ph.p_flags & PF_X)) ||
        (ph.p_type == PT_LOAD && (ph.p_flags & (PF_W | PF_X)) == (PF_W | PF_X)))
      return false;
    if (ph.p_type == PT_LOAD) {
      if (ph.p_offset > (uint64_t)size ||
          ph.p_filesz > (uint64_t)size - ph.p_offset) return false;
      if (ph.p_flags & PF_X) code = true;
    }
  }
  return code;
}
static bool pins(int fd, char owner[65], char node[65], char launcher[65]) {
  struct stat st;
  if (fstat(fd, &st) || st.st_size !=
      (off_t)(sizeof(GUARD_MAGIC) - 1 + 17 + 64 + 1 + 12 + 64 + 1 + 16 + 64 + 1))
    return false;
  char text[320] = {0};
  ssize_t got = pread(fd, text, sizeof text - 1, 0);
  if (got != st.st_size) return false;
  size_t magic = sizeof(GUARD_MAGIC) - 1;
  if (memcmp(text, GUARD_MAGIC, magic) ||
      memcmp(text + magic, "bootstrap_sha256=", 17) ||
      memcmp(text + magic + 17 + 64, "\nnode_sha256=", 13))
    return false;
  memcpy(owner, text + magic + 17, 64); owner[64] = 0;
  memcpy(node, text + magic + 17 + 64 + 13, 64); node[64] = 0;
  size_t tail = magic + 17 + 64 + 13 + 64;
  if (memcmp(text + tail, "\nlauncher_sha256=", 17)) return false;
  memcpy(launcher, text + tail + 17, 64); launcher[64] = 0;
  return text[tail + 17 + 64] == '\n' &&
    text[tail + 17 + 64 + 1] == 0 &&
    hex64(owner) && hex64(node) && hex64(launcher);
}
extern char **environ;
static bool safe_environment(void) {
  for (char **at = environ; at && *at; at++) {
    if (strcmp(*at, "PATH=/usr/bin:/bin") != 0 &&
        strcmp(*at, "HOME=/nonexistent") != 0) return false;
  }
  return true;
}
/* Root is not an assurance of an untainted capability state. In particular,
 * SECBIT_NO_SETUID_FIXUP prevents setuid(65534) from removing capabilities.
 * Reject hostile inherited securebits/ambient rather than trying to repair a
 * caller-controlled security execution context. */
static bool untainted_capability_context(void) {
  if (prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != 0) return false;
  bool found = false;
  for (unsigned cap = 0; cap < 1024; cap++) {
    errno = 0;
    long bound = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if (bound == -1) return found && errno == EINVAL;
    /* capget v3 represents exactly 64 capability bits. A future kernel
     * supporting bit 64+ must not silently escape the P/E/I audit. */
    if (cap >= 64) return false;
    if (bound != 0 && bound != 1) return false;
    found = true;
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0)
      return false;
  }
  return false; /* Future kernel supporting more than 1024 caps: refuse. */
}
static bool verified_empty_capabilities(void) {
  struct __user_cap_header_struct header = {
    .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0
  };
  struct __user_cap_data_struct bits[2] = {{0}, {0}};
  if (syscall(SYS_capget, &header, bits) ||
      bits[0].effective || bits[0].permitted || bits[0].inheritable ||
      bits[1].effective || bits[1].permitted || bits[1].inheritable)
    return false;
  bool found = false;
  for (unsigned cap = 0; cap < 1024; cap++) {
    errno = 0;
    long bounding = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if (bounding == -1) return found && errno == EINVAL;
    if (cap >= 64) return false;
    if (bounding != 0 ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0)
      return false;
    found = true;
  }
  return false;
}
static bool drop_child_capabilities(pid_t recorded_parent) {
  if (prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != 0 ||
      prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
    return false;
  /* Bounding bits can only be dropped reliably BEFORE losing CAP_SETPCAP. */
  bool found = false;
  for (unsigned cap = 0; cap < 1024; cap++) {
    errno = 0;
    long bounding = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if (bounding == -1) {
      if (errno != EINVAL || !found) return false;
      break;
    }
    if (cap >= 64) return false;
    if (bounding != 0 && bounding != 1) return false;
    found = true;
    if (bounding == 1 &&
        prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) return false;
    if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != 0) return false;
  }
  if (!found || setgroups(0, NULL) ||
      setresgid(65534, 65534, 65534) ||
      setresuid(65534, 65534, 65534))
    return false;
  struct __user_cap_header_struct header = {
    .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0
  };
  struct __user_cap_data_struct empty[2] = {{0}, {0}};
  if (syscall(SYS_capset, &header, empty) ||
      prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
      prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != 0 ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
      getuid() != 65534 || geteuid() != 65534 ||
      getgid() != 65534 || getegid() != 65534 ||
      getgroups(0, NULL) != 0 || !verified_empty_capabilities())
    return false;
  /* A uid/gid transition clears PDEATHSIG. Arm it only AFTER that change,
   * and compare parent identity after arming to close the fork/SIGKILL race. */
  if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0 ||
      getppid() != recorded_parent)
    return false;
  int signal_number = 0;
  if (prctl(PR_GET_PDEATHSIG, &signal_number, 0, 0, 0) != 0 ||
      signal_number != SIGKILL || signal(SIGALRM, SIG_DFL) == SIG_ERR ||
      alarm(3) != 0)
    return false;
  return syscall(SYS_close_range, 3U, UINT_MAX, CLOSE_RANGE_CLOEXEC) == 0 &&
    verified_empty_capabilities();
}
static bool system_allowed(void) {
  struct utsname u;
  if (uname(&u) || strcmp(u.sysname, "Linux") != 0 ||
      strcmp(u.machine, "x86_64") != 0) return false;
#ifndef VIRKI_TEST_ONLY_ROOT_FIXTURE
  if (strcasestr(u.release, "microsoft") || strcasestr(u.release, "wsl"))
    return false;
#else
  /* Separate nonauthorizing binary: only private /root paths are permitted. */
  static const char prefix[] = "/root/virki-pre-node-guard-fixture-";
  if (strncmp(VIRKI_LAUNCHER_PATH, prefix, sizeof(prefix) - 1) ||
      strncmp(VIRKI_PIN_PATH, prefix, sizeof(prefix) - 1) ||
      strncmp(VIRKI_OWNER_PATH, prefix, sizeof(prefix) - 1) ||
      strncmp(VIRKI_NODE_PATH, prefix, sizeof(prefix) - 1))
    return false;
#endif
  return getuid() == 0 && geteuid() == 0 && getgid() == 0 &&
    getegid() == 0 && getauxval(AT_BASE) == 0 &&
    untainted_capability_context();
}
static int refuse(void) {
  fputs("DEV_ONLY_PRENODE_REFUSED; no Docker, ledger, CAS or deploy authority.\n", stderr);
  return 2;
}
int main(int argc, char **argv) {
  if (argc != 1 || !argv || !safe_environment() || !system_allowed())
    return refuse();
  int self = owner_fd(VIRKI_LAUNCHER_PATH, 0, 4 * 1024 * 1024);
  if (self < 0) return refuse();
  struct stat installed, running;
  bool matched = fstat(self, &installed) == 0 &&
    stat("/proc/self/exe", &running) == 0 && same(&installed, &running);
  if (!matched) { close(self); return refuse(); }
  int policy = owner_fd(VIRKI_PIN_PATH, 0600, 4096);
  int owner = owner_fd(VIRKI_OWNER_PATH, 0600, 16384);
  int node = owner_fd(VIRKI_NODE_PATH, 0, GUARD_MAX_NODE);
  if (policy < 0 || owner < 0 || node < 0) {
    close(self);
    if (policy >= 0) close(policy);
    if (owner >= 0) close(owner);
    if (node >= 0) close(node);
    return refuse();
  }
  char expected_owner[65], expected_node[65], expected_launcher[65];
  char observed_owner[65], observed_node[65], observed_launcher[65];
  bool good = pins(policy, expected_owner, expected_node, expected_launcher) &&
    bytes_sha(self, VIRKI_LAUNCHER_PATH, observed_launcher, -1, 4 * 1024 * 1024) &&
    strcmp(expected_launcher, observed_launcher) == 0 &&
    bytes_sha(owner, VIRKI_OWNER_PATH, observed_owner, -1, 16384) &&
    strcmp(expected_owner, observed_owner) == 0;
  close(self);
  struct stat before;
  if (!good || fstat(node, &before) || !no_dynamic_loader(node, before.st_size))
    good = false;
  int sealed = -1;
  if (good) {
    sealed = (int)syscall(SYS_memfd_create, "virki-dev-only-pinned-elf",
                          MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (sealed < 0 || fchmod(sealed, 0555) ||
        !bytes_sha(node, VIRKI_NODE_PATH, observed_node, sealed, GUARD_MAX_NODE) ||
        strcmp(expected_node, observed_node) != 0 ||
        !no_dynamic_loader(sealed, before.st_size) ||
        fcntl(sealed, F_ADD_SEALS,
              F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) ||
        fcntl(sealed, F_GET_SEALS) !=
          (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL))
      good = false;
  }
  close(policy); close(owner); close(node);
  if (!good) { if (sealed >= 0) close(sealed); return refuse(); }
  /* NO script, verifier, module graph, Docker or release command. The only
   * allowed child operation is the pinned static binary's --version probe. */
  pid_t recorded_parent = getpid();
  pid_t child = fork();
  if (child == 0) {
    char *const args[] = { "node", "--version", NULL };
    char *const env[] = { "PATH=/usr/bin:/bin", "HOME=/nonexistent", NULL };
    if (!drop_child_capabilities(recorded_parent))
      _exit(126);
    syscall(SYS_execveat, sealed, "", args, env, AT_EMPTY_PATH);
    _exit(126);
  }
  close(sealed);
  if (child < 1) return refuse();
  int status = 0;
  bool reaped = false;
  for (int i = 0; i < 200; i++) {
    pid_t done = waitpid(child, &status, WNOHANG);
    if (done == child) { reaped = true; break; }
    if (done != 0) break;
    struct timespec nap = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
    nanosleep(&nap, NULL);
  }
  if (!reaped) {
    kill(child, SIGKILL);
    for (int i = 0; i < 50; i++) {
      pid_t done = waitpid(child, &status, WNOHANG);
      if (done == child) { reaped = true; break; }
      if (done != 0) break;
      struct timespec nap = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
      nanosleep(&nap, NULL);
    }
    return refuse(); /* A D-state child cannot be asserted reaped. */
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return refuse();
  puts("DEV_ONLY_STATIC_BYTE_PROBE_NO_RELEASE_AUTHORITY");
  return 0;
}
