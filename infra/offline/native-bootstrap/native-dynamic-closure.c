/*
 * DEV-ONLY native Node22 ELF closure byte inspector, not an installer,
 * verifier launcher, signature validator or execution authorizer.
 *
 * Root-owned inventory bytes are NOT proof of owner consent or signer trust.
 * The genuine native owner must separately provision and independently sign
 * a trusted inventory, reviewed linker + DSO layout and protected namespace.
 * This diagnostic never executes the measured executable/interpreter/DSOs.
 *
 * The Linux kernel resolves PT_INTERP and ld-linux later resolves DT_NEEDED
 * by PATHNAMES, not by the FDs verified here. Thus hashes, inode snapshots,
 * even a sealed executable memfd do not provide an immutable dynamic closure
 * at execveat. No dynamic execveat exists in this file by design.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <linux/memfd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifndef VIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE
#define VIRKI_CLOSURE_INVENTORY "/etc/virki/offline-native-guard/operator-elf-closure.txt"
#endif
#define NODE_EXE "/usr/bin/node"
#define MAX_FILES 64
#define MAX_INVENTORY 32768
#define MAX_BYTES (128ULL * 1024 * 1024)
#define MAGIC "VIRKI_DEV_ELF_CLOSURE_V1\n"
struct entry {
  char path[320];
  char name[130];
  char digest[65];
  bool visited;
};
static struct entry files[MAX_FILES];
static int held_snapshots[MAX_FILES];
static size_t total;
static char interpreter[320];

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
static bool protected_path(const char *name) {
  if (!name || name[0] != '/' || strstr(name, "//") ||
      strstr(name, "/./") || strstr(name, "/../") ||
      strlen(name) > 300) return false;
  char cur[320];
  strcpy(cur, name);
  size_t full = strlen(name);
  while (true) {
    struct stat st;
    if (lstat(cur, &st) || st.st_uid != 0 || st.st_gid != 0 ||
        (st.st_mode & 0022) || S_ISLNK(st.st_mode)) return false;
    if (strlen(cur) == full) {
      if (!S_ISREG(st.st_mode) || st.st_nlink != 1) return false;
    } else if (!S_ISDIR(st.st_mode)) return false;
    if (!strcmp(cur, "/")) return true;
    char *slash = strrchr(cur, '/');
    if (!slash) return false;
    if (slash == cur) cur[1] = 0;
    else *slash = 0;
  }
}
static int secure_open(const char *filename, size_t max, int mode) {
  if (!protected_path(filename)) return -1;
  struct stat before, after;
  if (lstat(filename, &before) || before.st_size <= 0 ||
      (uint64_t)before.st_size > max ||
      (mode >= 0 && (before.st_mode & 07777) != (unsigned)mode)) return -1;
  int fd = open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) return -1;
  if (fstat(fd, &after) || !same(&before, &after)) { close(fd); return -1; }
  return fd;
}
static bool unchanged(int fd, const char *filename, const struct stat *before) {
  struct stat fdstat, diskstat;
  return fstat(fd, &fdstat) == 0 && lstat(filename, &diskstat) == 0 &&
    same(before, &fdstat) && same(before, &diskstat) &&
    protected_path(filename);
}
static int verified_snapshot(int fd, const char *filename, const char *hex) {
  struct stat first;
  if (fstat(fd, &first) || first.st_size <= 0 ||
      (uint64_t)first.st_size > MAX_BYTES) return -1;
  int copy = (int)syscall(SYS_memfd_create, "virki-dev-elf-measured-no-exec",
                          MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (copy < 0) return -1;
  if (fchmod(copy, 0500)) { close(copy); return -1; }
  int sock = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (sock < 0) { close(copy); return -1; }
  struct sockaddr_alg alg = {.salg_family = AF_ALG};
  memcpy(alg.salg_type, "hash", 5);
  memcpy(alg.salg_name, "sha256", 7);
  if (bind(sock, (struct sockaddr *)&alg, sizeof alg)) {
    close(sock); close(copy); return -1;
  }
  int op = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
  close(sock);
  if (op < 0) { close(copy); return -1; }
  unsigned char buf[16384], out[32];
  bool good = true;
  for (off_t off = 0; good && off < first.st_size;) {
    size_t wanted = (uint64_t)(first.st_size - off) > sizeof buf ?
      sizeof buf : (size_t)(first.st_size - off);
    ssize_t got = pread(fd, buf, wanted, off);
    if (got <= 0) { good = false; break; }
    for (ssize_t written = 0; good && written < got;) {
      ssize_t n = pwrite(copy, buf + written, (size_t)(got - written),
                         off + written);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) good = false;
      else written += n;
    }
    for (ssize_t sent = 0; good && sent < got;) {
      int flags = off + got == first.st_size ? 0 : MSG_MORE;
      ssize_t n = send(op, buf + sent, (size_t)(got - sent), flags | MSG_NOSIGNAL);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) good = false;
      else sent += n;
    }
    off += got;
  }
  good = good && read(op, out, sizeof out) == sizeof out &&
    unchanged(fd, filename, &first);
  close(op);
  static const char alphabet[] = "0123456789abcdef";
  if (!good) { close(copy); return -1; }
  for (size_t i = 0; i < sizeof out; i++)
    if (hex[i * 2] != alphabet[out[i] >> 4] ||
        hex[i * 2 + 1] != alphabet[out[i] & 15]) {
      close(copy); return -1;
    }
  const int seals = F_SEAL_WRITE | F_SEAL_GROW |
    F_SEAL_SHRINK | F_SEAL_SEAL;
  struct stat sealed;
  if (hex[64] || fsync(copy) || fcntl(copy, F_ADD_SEALS, seals) ||
      fcntl(copy, F_GET_SEALS) != seals ||
      fstat(copy, &sealed) || !S_ISREG(sealed.st_mode) ||
      sealed.st_size != first.st_size ||
      !unchanged(fd, filename, &first)) {
    close(copy); return -1;
  }
  return copy;
}
static bool clean_name(const char *value) {
  if (!value || !*value || strlen(value) > 128 ||
      !strcmp(value, ".") || !strcmp(value, "..")) return false;
  for (const char *c = value; *c; c++)
    if (!((*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') ||
          (*c >= '0' && *c <= '9') || *c == '.' || *c == '_' ||
          *c == '-' || *c == '+')) return false;
  return true;
}
static bool interp_alias_is_owner_held(const char *filename) {
  /* The glibc interpreter may be a root-owned symlink, unlike regular
   * manifest entries. Inspect the exact known loader alias and ensure it is
   * NOT in a writable directory. This still cannot bind a later kernel
   * PT_INTERP lookup to this read-only observation. */
  if (strcmp(filename, "/lib64/ld-linux-x86-64.so.2")) return false;
  struct stat parent, parent_target, link;
  char parent_link[40] = {0};
  ssize_t length = readlink("/lib64", parent_link, sizeof parent_link - 1);
  return length == 9 && !strcmp(parent_link, "usr/lib64") &&
    lstat("/lib64", &parent) == 0 && S_ISLNK(parent.st_mode) &&
    parent.st_uid == 0 && parent.st_gid == 0 &&
    lstat("/usr/lib64", &parent_target) == 0 &&
    S_ISDIR(parent_target.st_mode) && parent_target.st_uid == 0 &&
    parent_target.st_gid == 0 && (parent_target.st_mode & 0022) == 0 &&
    lstat(filename, &link) == 0 &&
    S_ISLNK(link.st_mode) && link.st_uid == 0 &&
    link.st_gid == 0;
}
static bool inventory(void) {
  int fd = secure_open(VIRKI_CLOSURE_INVENTORY, MAX_INVENTORY, 0600);
  if (fd < 0) return false;
  struct stat before;
  bool good = fstat(fd, &before) == 0;
  static char buffer[MAX_INVENTORY + 1];
  if (good) good = pread(fd, buffer, (size_t)before.st_size, 0) == before.st_size &&
    unchanged(fd, VIRKI_CLOSURE_INVENTORY, &before);
  close(fd);
  if (!good || before.st_size >= MAX_INVENTORY) return false;
  buffer[before.st_size] = 0;
  size_t m = sizeof MAGIC - 1;
  if (strncmp(buffer, MAGIC, m)) return false;
  char *rest = buffer + m;
  while (*rest) {
    if (total >= MAX_FILES) return false;
    char *newline = strchr(rest, '\n');
    if (!newline) return false;
    *newline = 0;
    char *first_space = strchr(rest, ' ');
    char *space = strrchr(rest, ' ');
    if (!first_space || !space || first_space == space) return false;
    *space = 0;
    *first_space = 0;
    const char *alias = rest;
    const char *name = first_space + 1;
    const char *sha = space + 1;
    if (!clean_name(alias) || strlen(sha) != 64 ||
        strlen(name) >= sizeof files[0].path || name[0] != '/' ||
        strchr(name, ' ')) return false;
    for (size_t i = 0; i < 64; i++)
      if (!((sha[i] >= '0' && sha[i] <= '9') ||
            (sha[i] >= 'a' && sha[i] <= 'f'))) return false;
    char *resolved = realpath(name, NULL);
    bool canonical = resolved && !strcmp(resolved, name);
    free(resolved);
    if (!canonical || !protected_path(name)) return false;
    for (size_t i = 0; i < total; i++) {
      if (!strcmp(files[i].path, name) || !strcmp(files[i].name, alias))
        return false;
    }
    strcpy(files[total].path, name);
    strcpy(files[total].name, alias);
    strcpy(files[total].digest, sha);
    total++;
    rest = newline + 1;
  }
  return total >= 3 && !strcmp(files[0].path, NODE_EXE) &&
    !strcmp(files[0].name, "node");
}
static int find_lib(const char *name) {
  for (size_t i = 1; i < total; i++)
    if (!strcmp(files[i].name, name)) return (int)i;
  return -1;
}
static bool vaddr_offset(uint64_t virtual_addr, uint64_t bytes,
                         const Elf64_Phdr *ph, size_t count, uint64_t *out) {
  for (size_t i = 0; i < count; i++) {
    if (ph[i].p_type != PT_LOAD || virtual_addr < ph[i].p_vaddr) continue;
    uint64_t offset = virtual_addr - ph[i].p_vaddr;
    if (offset <= ph[i].p_filesz && bytes <= ph[i].p_filesz - offset) {
      *out = ph[i].p_offset + offset;
      return true;
    }
  }
  return false;
}
static bool inspect_elf(size_t index) {
  int fd = secure_open(files[index].path, MAX_BYTES, -1);
  if (fd < 0) return false;
  bool good = false;
#ifdef VIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE
  int stage = 0;
#endif
  char *strings = NULL;
  struct stat st;
  Elf64_Ehdr h;
  Elf64_Phdr ph[128];
  if (fstat(fd, &st)) goto finish;
  held_snapshots[index] = verified_snapshot(fd, files[index].path,
                                             files[index].digest);
  if (held_snapshots[index] < 0 ||
      st.st_size < (off_t)sizeof h ||
      pread(held_snapshots[index], &h, sizeof h, 0) != sizeof h ||
      memcmp(h.e_ident, ELFMAG, SELFMAG) ||
      h.e_ident[EI_CLASS] != ELFCLASS64 ||
      h.e_ident[EI_DATA] != ELFDATA2LSB ||
      h.e_machine != EM_X86_64 || h.e_version != EV_CURRENT ||
      (h.e_type != ET_DYN && h.e_type != ET_EXEC) ||
      h.e_phnum == 0 || h.e_phnum > 128 ||
      h.e_phentsize != sizeof(Elf64_Phdr) ||
      h.e_phoff > (uint64_t)st.st_size ||
      (uint64_t)h.e_phnum * sizeof(Elf64_Phdr) > (uint64_t)st.st_size - h.e_phoff ||
      pread(held_snapshots[index], ph, h.e_phnum * sizeof(Elf64_Phdr),
            (off_t)h.e_phoff) !=
        (ssize_t)(h.e_phnum * sizeof(Elf64_Phdr))) goto finish;
#ifdef VIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE
  stage = 1;
#endif
  uint64_t interp_off = 0, interp_len = 0, dyn_off = 0, dyn_len = 0;
  size_t n_interp = 0;
  for (unsigned i = 0; i < h.e_phnum; i++) {
    if (ph[i].p_offset > (uint64_t)st.st_size ||
        ph[i].p_filesz > (uint64_t)st.st_size - ph[i].p_offset ||
        (ph[i].p_type == PT_LOAD &&
          (ph[i].p_flags & (PF_W | PF_X)) == (PF_W | PF_X)) ||
        (ph[i].p_type == PT_GNU_STACK && (ph[i].p_flags & PF_X))) goto finish;
    if (ph[i].p_type == PT_INTERP) {
      if (++n_interp > 1) goto finish;
      interp_off = ph[i].p_offset; interp_len = ph[i].p_filesz;
    }
    if (ph[i].p_type == PT_DYNAMIC) {
      if (dyn_len) goto finish;
      dyn_off = ph[i].p_offset; dyn_len = ph[i].p_filesz;
    }
  }
  if (index == 0 && n_interp != 1) goto finish;
  if (n_interp) {
    if (interp_len < 2 || interp_len >= sizeof interpreter)
      goto finish;
    char raw[320];
    if (pread(held_snapshots[index], raw, interp_len, (off_t)interp_off) !=
          (ssize_t)interp_len ||
        raw[interp_len - 1] != 0 || strlen(raw) != interp_len - 1 ||
        raw[0] != '/' || strstr(raw, "..") || strstr(raw, "//") ||
        !interp_alias_is_owner_held(raw)) goto finish;
    char *resolved = realpath(raw, NULL);
    if (!resolved) goto finish;
    bool matches = strlen(resolved) < sizeof interpreter &&
      strcmp(resolved, files[1].path) == 0;
    if (matches) strcpy(interpreter, resolved);
    free(resolved);
    if (!matches) goto finish;
    files[1].visited = true; /* pinned loader checked as an ELF below. */
  } /* Some glibc DSOs (e.g. libc.so.6) include a PT_INTERP themselves. */
  if (!dyn_len || dyn_len > 4096 * sizeof(Elf64_Dyn) ||
      dyn_len % sizeof(Elf64_Dyn)) goto finish;
#ifdef VIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE
  stage = 2;
#endif
  Elf64_Dyn dyn[4096];
  if (pread(held_snapshots[index], dyn, (size_t)dyn_len,
            (off_t)dyn_off) != (ssize_t)dyn_len)
    goto finish;
  uint64_t str_va = 0, str_sz = 0;
  size_t needed[64], n_needed = 0, soname = SIZE_MAX, runpath = SIZE_MAX;
  bool terminated = false;
  for (size_t i = 0; i < dyn_len / sizeof(Elf64_Dyn); i++) {
    if (dyn[i].d_tag == DT_NULL) { terminated = true; break; }
    switch (dyn[i].d_tag) {
      case DT_STRTAB: if (str_va) goto finish; str_va = dyn[i].d_un.d_ptr; break;
      case DT_STRSZ: if (str_sz) goto finish; str_sz = dyn[i].d_un.d_val; break;
      case DT_NEEDED:
        if (n_needed >= 64) goto finish;
        needed[n_needed++] = (size_t)dyn[i].d_un.d_val; break;
      case DT_SONAME:
        if (soname != SIZE_MAX) goto finish;
        soname = (size_t)dyn[i].d_un.d_val; break;
      case DT_RUNPATH:
        if (runpath != SIZE_MAX) goto finish;
        runpath = (size_t)dyn[i].d_un.d_val; break;
      case DT_RPATH:
      case DT_AUDIT: case DT_DEPAUDIT:
      case DT_FILTER: case DT_AUXILIARY: goto finish;
      default: break;
    }
  }
  if (!terminated || !str_va || str_sz == 0 || str_sz > 16ULL * 1024 * 1024)
    goto finish;
#ifdef VIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE
  stage = 3;
#endif
  uint64_t string_offset;
  if (!vaddr_offset(str_va, str_sz, ph, h.e_phnum, &string_offset) ||
      string_offset > (uint64_t)st.st_size ||
      str_sz > (uint64_t)st.st_size - string_offset) goto finish;
  strings = malloc((size_t)str_sz + 1);
  if (!strings) goto finish;
  if (pread(held_snapshots[index], strings, (size_t)str_sz,
            (off_t)string_offset) !=
      (ssize_t)str_sz) goto finish;
  strings[str_sz] = 0;
#ifdef VIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE
  stage = 4;
#endif
  if (soname != SIZE_MAX) {
    if (soname >= str_sz ||
        !memchr(strings + soname, 0, (size_t)(str_sz - soname)) ||
        strcmp(strings + soname, files[index].name)) goto finish;
  }
  /* Ubuntu/Debian Node22 carries a relative fallback RUNPATH. Merely
   * observing this does not pin the library resolution performed by ld.so.
   * Permit its exact known syntax for inspection only, never authorization. */
  if (runpath != SIZE_MAX) {
    if (runpath >= str_sz ||
        !memchr(strings + runpath, 0, (size_t)(str_sz - runpath)) ||
        index != 0 ||
        strcmp(strings + runpath, "$ORIGIN/../lib:$ORIGIN/")) goto finish;
  }
  for (size_t i = 0; i < n_needed; i++) {
    if (needed[i] >= str_sz ||
        !memchr(strings + needed[i], 0, (size_t)(str_sz - needed[i])) ||
        !clean_name(strings + needed[i])) goto finish;
    int dep = find_lib(strings + needed[i]);
    if (dep < 0 || (size_t)dep == index) goto finish;
    files[dep].visited = true;
  }
#ifdef VIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE
  stage = 5;
#endif
  good = unchanged(fd, files[index].path, &st);
finish:
#ifdef VIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE
  if (!good) fprintf(stderr, "fixture ELF refused index %zu stage %d: %s\n",
                     index, stage, files[index].name);
#endif
  free(strings);
  close(fd);
  if (!good && held_snapshots[index] >= 0) {
    close(held_snapshots[index]);
    held_snapshots[index] = -1;
  }
  return good;
}
static bool native_guard(void) {
  struct utsname uname_info;
  if (uname(&uname_info) || strcmp(uname_info.sysname, "Linux") ||
      strcmp(uname_info.machine, "x86_64") ||
      getuid() != 0 || geteuid() != 0 ||
      getgid() != 0 || getegid() != 0 ||
      getauxval(AT_BASE) != 0) return false;
#ifndef VIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE
  if (strcasestr(uname_info.release, "microsoft") ||
      strcasestr(uname_info.release, "wsl")) return false;
#else
  if (strncmp(VIRKI_CLOSURE_INVENTORY,
              "/root/virki-elf-closure-fixture-", 32)) return false;
#endif
  extern char **environ;
  for (char **p = environ; p && *p; p++)
    if (strcmp(*p, "PATH=/usr/bin:/bin") &&
        strcmp(*p, "HOME=/nonexistent")) return false;
  return true;
}
int main(int argc, char **argv) {
  (void)argv;
  for (size_t i = 0; i < MAX_FILES; i++) held_snapshots[i] = -1;
  if (argc != 1 || !native_guard() || !inventory())
    goto blocked;
  for (size_t i = 0; i < total; i++) {
    if (!inspect_elf(i)) goto blocked;
  }
  for (size_t i = 1; i < total; i++)
    if (!files[i].visited) {
#ifdef VIRKI_DYNAMIC_CLOSURE_TEST_FIXTURE
      fprintf(stderr, "fixture unreachable: %s\n", files[i].name);
#endif
      goto blocked;
    }
  for (size_t i = 0; i < total; i++) close(held_snapshots[i]);
  puts("DEV_ONLY_REAL_NODE22_ELF_CLOSURE_MEASURED_NO_EXEC_NO_AUTHORITY");
  puts("PT_INTERP_PINNED_BYTES_ONLY; loader opens unpinned paths at actual exec");
  return 0;
blocked:
  for (size_t i = 0; i < total; i++)
    if (held_snapshots[i] >= 0) close(held_snapshots[i]);
  fputs("DYNAMIC_ELF_CLOSURE_BLOCKED; no independent signer, trusted exec, CAS or deploy\n", stderr);
  return 2;
}
