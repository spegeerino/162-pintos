#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "filesys/off_t.h"
#include "list.h"
#include "tests/filesys/base/syn-write.h"
#include "threads/arc.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "lib/float.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define SYSCALL_MAX_NARGS 5

static void syscall_handler(struct intr_frame*);
void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

/* Functions for reading and writing user memory */
static void segfault(void);
static void segfault_freeing(void*);
static void segfault_freeing_page(void*);
static bool get_byte(const char* uaddr, char* buf);
static bool put_byte(char* udst, char byte);

/* Higher-level memory functions */
static bool strlcpy_from_user(char* dst, const char* usrc, int maxsize);
static bool memcpy_from_user(void* dst, const void* usrc, int size);
static bool memcpy_to_user(void* udst, const void* src, int size);

// =============================
// Helpers for defining syscalls
// =============================

struct syscall {
  uint32_t syscall_number;
  uint32_t (*handler)(void* args);
  size_t args_size;
};

// clang-format off
#define __ARG_FIELDS(A,B,C,D,E,F,G,...) A; B; C; D; E; F; G;
#define ARG_FIELDS(...) __ARG_FIELDS(__VA_ARGS__,,,,,,)
#define ARG_STRUCT(...)
// clang-format on

#define SYSCALL_DEFINE(NAME, SYSCALL_NUMBER, RET_TYPE, ARGS, ...)                                  \
  struct __##NAME##_args {                                                                         \
    ARG_FIELDS(__VA_ARGS__)                                                                        \
  };                                                                                               \
  static RET_TYPE __##NAME##_impl(struct __##NAME##_args* ARGS);                                   \
  static uint32_t __##NAME##_handler(void* args) { return (uint32_t)__##NAME##_impl(args); }       \
  struct syscall NAME = {SYSCALL_NUMBER, __##NAME##_handler, sizeof(struct __##NAME##_args)};      \
  static RET_TYPE __##NAME##_impl(struct __##NAME##_args* ARGS)

// ========================
// Process control syscalls
// ========================

SYSCALL_DEFINE(sc_practice, SYS_PRACTICE, int, args, int value) { return args->value + 1; }

SYSCALL_DEFINE(sc_halt, SYS_HALT, void*, args UNUSED) {
  shutdown_power_off();
  NOT_REACHED();
}

SYSCALL_DEFINE(sc_exit, SYS_EXIT, void*, args, int status) {
  thread_current()->pcb->shared->exit_status = args->status;
  process_exit();
  NOT_REACHED();
}

SYSCALL_DEFINE(sc_exec, SYS_EXEC, int, args, char* cmd_line) {
  char* cl_copy = palloc_get_page(0);
  if (cl_copy == NULL)
    return -1;
  if (!strlcpy_from_user(cl_copy, args->cmd_line, PGSIZE))
    segfault();

  int result = process_execute(cl_copy);
  palloc_free_page(cl_copy);
  return result;
}

SYSCALL_DEFINE(sc_wait, SYS_WAIT, int, args, pid_t pid) { return process_wait(args->pid); }

// =======================
// File operation syscalls
// =======================

SYSCALL_DEFINE(sc_create, SYS_CREATE, bool, args, char* path, unsigned initial_size) {
  /* Copy path from user memory */
  autofreepage char* path = palloc_get_page(0);
  if (path == NULL)
    return false;
  if (!strlcpy_from_user(path, args->path, PGSIZE))
    segfault_freeing_page(path);

  /* Create file */
  lock_acquire(&global_filesys_lock);
  bool result = filesys_create_file(thread_current()->pcb->cwd, path, args->initial_size);
  lock_release(&global_filesys_lock);

  return result;
}

SYSCALL_DEFINE(sc_remove, SYS_REMOVE, bool, args, char* path) {
  /* Copy path from user memory */
  autofreepage char* path = palloc_get_page(0);
  if (path == NULL)
    return false;
  if (!strlcpy_from_user(path, args->path, PGSIZE))
    segfault_freeing_page(path);

  /* Remove file */
  lock_acquire(&global_filesys_lock);
  bool result = filesys_remove(thread_current()->pcb->cwd, path);
  lock_release(&global_filesys_lock);

  return result;
}

SYSCALL_DEFINE(sc_open, SYS_OPEN, int, args, char* path) {
  struct process* pcb = thread_current()->pcb;

  /* Copy path from user memory */
  autofreepage char* path = palloc_get_page(0);
  if (path == NULL)
    return -1;
  if (!strlcpy_from_user(path, args->path, PGSIZE))
    segfault_freeing_page(path);

  /* Allocate space for the new open inode */
  struct open_inode* inode = malloc(sizeof *inode);
  if (inode == NULL)
    return -1;

  /* Make sure to acquire the lock */
  lock_acquire(&global_filesys_lock);

  /* Open the inode */
  struct inode* inner = filesys_open(pcb->cwd, path);
  if (inner == NULL)
    goto cleanup;

  /* If inode is a directory */
  if (inner->type == DIRECTORY) {
    inode->type = DIRECTORY;
    inode->dir = dir_open(inner);
    if (inode->dir == NULL)
      goto cleanup;
  }

  /* If inode is a file */
  else if (inner->type == FILE) {
    inode->type = FILE;
    inode->file = file_open(inner);
    if (inode->file == NULL)
      goto cleanup;
  }

  /* This should not happen but just in case */
  else {
    goto cleanup;
  }

  inode->fd = pcb->next_fd++;
  lock_release(&global_filesys_lock);

  // puts the created struct file* into the fd table
  list_push_back(&pcb->open_inodes, &inode->elem);
  return inode->fd;

cleanup:;
  lock_release(&global_filesys_lock);
  free(inode);
  return -1;
}

/* Looks up a FD in the current thread's PCB. */
static struct open_inode* fd_lookup(int fd_to_lookup) {
  struct process* pcb = thread_current()->pcb;
  if (fd_to_lookup < 2)
    return NULL;
  return list_find(&pcb->open_inodes, struct open_inode, elem, file, file->fd == fd_to_lookup);
}

SYSCALL_DEFINE(sc_filesize, SYS_FILESIZE, off_t, args, int fd) {
  /* Look up FD from OFD */
  struct open_inode* inode = fd_lookup(args->fd);
  if (inode == NULL || inode->type != FILE)
    return -1;

  /* Return length of the file, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  off_t output = file_length(inode->file);
  lock_release(&global_filesys_lock);

  return output;
}

SYSCALL_DEFINE(sc_read, SYS_READ, off_t, args, int fd, void* dst, unsigned size) {
  if (args->size == 0)
    return 0;

  /* Handle reading from stdin (fd == 0). */
  if (args->fd == 0) {
    for (unsigned i = 0; i < args->size; i++)
      if (!put_byte(args->dst++, input_getc()))
        segfault();
    return args->size;
  }

  /* Look up FD from OFD */
  struct open_inode* inode = fd_lookup(args->fd);
  if (inode == NULL || inode->type != FILE)
    return -1;

  /* Allocate temporary buffer in kernel memory */
  uint8_t* buf = malloc(args->size);
  if (buf == NULL)
    return -1;

  /* Read from file to temporary buffer, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  off_t result = file_read(inode->file, buf, args->size);
  lock_release(&global_filesys_lock);

  /* Copy to user memory using the helper (this handles segfaults) */
  if (!memcpy_to_user(args->dst, buf, args->size)) {
    free(buf);
    segfault();
  }

  free(buf);
  return result;
}

SYSCALL_DEFINE(sc_write, SYS_WRITE, off_t, args, int fd, void* src, unsigned size) {
  if (args->size == 0)
    return 0;

  /* Allocate temporary buffer in kernel memory */
  char* buf = malloc(args->size);
  if (buf == NULL)
    return -1;

  /* Copy data to write into temporary buffer */
  if (!memcpy_from_user(buf, args->src, args->size)) {
    free(buf);
    segfault();
  }

  /* Handle writing to stdout (fd == 1) */
  if (args->fd == 1) {
    putbuf(buf, args->size);
    return args->size;
  }

  /* Look up FD from OFD */
  struct open_inode* inode = fd_lookup(args->fd);
  if (inode == NULL || inode->type != FILE)
    return -1;

  /* Read from temporary buffer to file, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  off_t result = file_write(inode->file, args->src, args->size);
  lock_release(&global_filesys_lock);

  return result;
}

SYSCALL_DEFINE(sc_seek, SYS_SEEK, int, args, int fd, unsigned position) {
  /* Look up FD from OFD */
  struct open_inode* inode = fd_lookup(args->fd);
  if (inode == NULL || inode->type != FILE)
    return -1;

  /* Seek, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  file_seek(inode->file, args->position);
  lock_release(&global_filesys_lock);

  return 0;
}

SYSCALL_DEFINE(sc_tell, SYS_TELL, off_t, args, int fd) {
  /* Look up FD from OFD */
  struct open_inode* inode = fd_lookup(args->fd);
  if (inode == NULL || inode->type != FILE)
    return -1;

  /* Don't need to acquire the lock here */
  return file_tell(inode->file);
}

SYSCALL_DEFINE(sc_close, SYS_CLOSE, int, args, int fd) {
  /* Look up FD from OFD */
  struct open_inode* inode = fd_lookup(args->fd);
  if (inode == NULL)
    return -1;

  /* Close the file or directory, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  if (inode->type == DIRECTORY)
    dir_close(inode->dir);
  else if (inode->type == FILE)
    file_close(inode->file);
  lock_release(&global_filesys_lock);

  /* Remove from the OFD table */
  list_remove(&inode->elem);
  free(inode);
  return 0;
}

SYSCALL_DEFINE(sc_chdir, SYS_CHDIR, bool, args, char* dir) {
  /* Copy path from user memory */
  autofreepage char* path = palloc_get_page(0);
  if (path == NULL)
    return false;
  if (!strlcpy_from_user(path, args->dir, PGSIZE))
    segfault_freeing_page(path);

  /* Open new directory */
  lock_acquire(&global_filesys_lock);
  struct dir* dir = filesys_open_dir(thread_current()->pcb->cwd, path);
  lock_release(&global_filesys_lock);
  if (dir == NULL)
    return false;

  /* Close old directory */
  lock_acquire(&global_filesys_lock);
  dir_close(thread_current()->pcb->cwd);
  lock_release(&global_filesys_lock);

  /* Set CWD in PCB */
  thread_current()->pcb->cwd = dir;

  return true;
}

SYSCALL_DEFINE(sc_mkdir, SYS_MKDIR, bool, args, char* dir) {
  /* Copy path from user memory */
  autofreepage char* path = palloc_get_page(0);
  if (path == NULL)
    return false;
  if (!strlcpy_from_user(path, args->dir, PGSIZE))
    segfault_freeing_page(path);

  /* Create directory */
  lock_acquire(&global_filesys_lock);
  bool result = filesys_create_dir(thread_current()->pcb->cwd, path);
  lock_release(&global_filesys_lock);

  return result;
}

SYSCALL_DEFINE(sc_readdir, SYS_READDIR, bool, args, int fd, char* name) {
  /* Look up FD from OFD */
  struct open_inode* inode = fd_lookup(args->fd);
  if (inode == NULL || inode->type != DIRECTORY)
    return false;

  /* Read directory entry, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  char name[NAME_MAX + 1];
  bool result = dir_readdir(inode->dir, name);
  lock_release(&global_filesys_lock);

  /* Copy name to user memory */
  if (!memcpy_to_user(args->name, name, NAME_MAX + 1))
    segfault();

  return result;
}

SYSCALL_DEFINE(sc_isdir, SYS_ISDIR, bool, args, int fd) {
  /* Look up FD from OFD */
  struct open_inode* inode = fd_lookup(args->fd);
  if (inode == NULL)
    return false;

  return inode->type == DIRECTORY;
}

SYSCALL_DEFINE(sc_inumber, SYS_INUMBER, int, args, int fd) {
  /* Look up FD from OFD */
  struct open_inode* inode = fd_lookup(args->fd);
  if (inode == NULL)
    return -1;

  /* Call on the corresponding inode */
  if (inode->type == DIRECTORY)
    return inode_get_inumber(inode->dir->inode);
  else if (inode->type == FILE)
    return inode_get_inumber(inode->file->inode);

  return -1;
}

// =================================
// Floating point operation syscalls
// =================================

SYSCALL_DEFINE(sc_compute_e, SYS_COMPUTE_E, int, args, int n) {
  if (args->n < 0)
    return -1;
  return sys_sum_to_e(args->n);
}

// =============================
// General syscall handler stuff
// =============================

struct syscall* syscall_table[] = {
    // Process control syscalls
    &sc_practice,
    &sc_halt,
    &sc_exit,
    &sc_exec,
    &sc_wait,

    // File operation syscalls
    &sc_create,
    &sc_remove,
    &sc_open,
    &sc_filesize,
    &sc_read,
    &sc_write,
    &sc_seek,
    &sc_tell,
    &sc_close,
    &sc_chdir,
    &sc_mkdir,
    &sc_readdir,
    &sc_isdir,
    &sc_inumber,

    // Floating point operation syscalls
    &sc_compute_e,
};

static struct syscall* syscall_lookup(uint32_t syscall_number) {
  for (unsigned i = 0; i < sizeof(syscall_table) / sizeof(syscall_table[0]); i++)
    if (syscall_table[i]->syscall_number == syscall_number)
      return syscall_table[i];
  return NULL;
}

static void syscall_handler(struct intr_frame* f) {
  /* Get first argument (syscall number) */
  uint32_t syscall_number;
  if (!memcpy_from_user(&syscall_number, f->esp, 4))
    segfault();

  /* Look up syscall number, returning -1 if invalid */
  struct syscall* syscall = syscall_lookup(syscall_number);
  if (syscall == NULL) {
    f->eax = -1;
    return;
  }

  /* Get the correct number of arguments from user memory */
  uint32_t args[SYSCALL_MAX_NARGS];
  if (!memcpy_from_user(args, f->esp + 4, syscall->args_size))
    segfault();

  /* Call handler and place result into eax */
  f->eax = syscall->handler(args);
}

static void segfault() {
  uint32_t args[] = {-1};
  sc_exit.handler(args);
}

static void segfault_freeing(void* ptr) {
  free(ptr);
  segfault();
}

static void segfault_freeing_page(void* ptr) {
  palloc_free_page(ptr);
  segfault();
}

// =======
// Helpers
// =======

/* Reads string starting at user virtual address USRC into DST.
   Returns true if successful, false if a segfault occurred. */
static bool strlcpy_from_user(char* dst, const char* usrc, int maxsize) {
  for (int i = 0; i < maxsize - 1; i++) {
    if (!get_byte(usrc++, dst))
      return false;
    if (*dst++ == '\0')
      return true;
  }

  *dst = '\0';
  return true;
}

/* Reads multiple bytes at user virtual address USRC into buf.
   Returns true if successful, false if a segfault occurred. */
static bool memcpy_from_user(void* dst, const void* usrc, int size) {
  for (int i = 0; i < size; i++)
    if (!get_byte(usrc++, dst++))
      return false;
  return true;
}

/* Writes multiple bytes to user virtual address UDST.
   Returns true if successful, false if a segfault occurred. */
static bool memcpy_to_user(void* udst, const void* src, int size) {
  for (int i = 0; i < size; i++)
    if (!put_byte(udst++, *(uint8_t*)src++))
      return false;
  return true;
}

/* Reads a byte at user virtual address UADDR into buf.
   Returns true if successful, false if a segfault occurred. */
static bool get_byte(const char* uaddr, char* buf) {
  if (uaddr >= (char*)PHYS_BASE)
    return false;

  int result;

  // For more inline asm documentation, read:
  // https://www.felixcloutier.com/documents/gcc-asm.html

  asm(
      // Move "1:" label to %0 (forced to be eax, see below).
      "movl $1f, %0\n\t"

      // Try to read from %1, which is the memory address we passed.
      // If this page faults, the page_fault handler will:
      //   1) put eax into eip
      //   2) put -1 into eax
      // Since we moved "1:" to eax, this will cause it to exit the
      // inline asm block while putting -1 into the result variable.
      "movzbl %1, %0\n\t"

      // Label for continuation.
      "1:\n\t"

      // Specifies an output operand (%0).
      // "a" means to pass result using the a register (al/ax/eax/rax).
      // "=&" means that the value is initially unspecified (early-clobber).
      : "=&a"(result)

      // Specifies an "input" operand (%1).
      // "m" means to pass it as a memory address.
      : "m"(*uaddr));

  if (result == -1)
    return false;

  *buf = result;
  return true;
}

/* Writes BYTE to user address UDST.
   Returns true if successful, false if a segfault occurred. */
static bool put_byte(char* udst, char byte) {
  if (udst >= (char*)PHYS_BASE)
    return false;

  int error_code;

  // For more inline asm documentation, read:
  // https://www.felixcloutier.com/documents/gcc-asm.html

  asm(
      // Move "1:" label to %0 (forced to be eax, see below).
      "movl $1f, %0\n\t"

      // Try to write %b2 (meaning the single-byte version of %2) to %1.
      // Page faults cause error_code to be -1 for same reason as in get_user.
      "movb %b2, %1\n\t"

      // Label for continuation.
      "1:\n\t"

      // Specifies two output operands (%0 and %1).
      // "=&a" means al/ax/eax/rax with early-clobber (as above).
      // "m" means memory address.
      : "=&a"(error_code), "=m"(*udst)

      // Specifies one input operand (%2).
      // "q" means to use a, b, c, or d general purpose registers.
      // (There is another one "r" which would use si and di too.)
      : "q"(byte));

  return error_code != -1;
}
