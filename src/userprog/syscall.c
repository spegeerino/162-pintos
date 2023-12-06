
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
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

#define SYSCALL_DEFINE(NAME, SYSCALL_NUMBER, ARGS, ...)                                            \
  struct __##NAME##_args {                                                                         \
    ARG_FIELDS(__VA_ARGS__)                                                                        \
  };                                                                                               \
  static uint32_t __##NAME##_impl(struct __##NAME##_args* ARGS);                                   \
  static uint32_t __##NAME##_handler(void* args) { return __##NAME##_impl(args); }                 \
  struct syscall NAME = {SYSCALL_NUMBER, __##NAME##_handler, sizeof(struct __##NAME##_args)};      \
  static uint32_t __##NAME##_impl(struct __##NAME##_args* ARGS)

// ========================
// Process control syscalls
// ========================

SYSCALL_DEFINE(sc_practice, SYS_PRACTICE, args, uint32_t value) { return args->value + 1; }

SYSCALL_DEFINE(sc_halt, SYS_HALT, args UNUSED) {
  shutdown_power_off();
  NOT_REACHED();
}

SYSCALL_DEFINE(sc_exit, SYS_EXIT, args, uint32_t status) {
  thread_current()->pcb->shared->exit_status = args->status;
  process_exit();
  NOT_REACHED();
}

SYSCALL_DEFINE(sc_exec, SYS_EXEC, args, char* cmd_line) {
  char* cl_copy = palloc_get_page(0);
  if (cl_copy == NULL)
    return -1;
  if (!strlcpy_from_user(cl_copy, args->cmd_line, PGSIZE))
    segfault();

  int result = process_execute(cl_copy);
  palloc_free_page(cl_copy);
  return result;
}

SYSCALL_DEFINE(sc_wait, SYS_WAIT, args, pid_t pid) { return process_wait(args->pid); }

// =======================
// File operation syscalls
// =======================

SYSCALL_DEFINE(sc_create, SYS_CREATE, args, char* path, unsigned initial_size) {
  autofreepage char* path = palloc_get_page(0);
  if (path == NULL)
    return false;
  if (!strlcpy_from_user(path, args->path, PGSIZE))
    segfault();

  lock_acquire(&global_filesys_lock);
  bool result = filesys_create(thread_current()->pcb->cwd, path, args->initial_size);
  lock_release(&global_filesys_lock);
  return result;
}

SYSCALL_DEFINE(sc_remove, SYS_REMOVE, args, char* file_name) {
  char fn_copy[16];
  if (!strlcpy_from_user(fn_copy, args->file_name, 16))
    segfault();

  lock_acquire(&global_filesys_lock);
  int output = filesys_remove(fn_copy);
  lock_release(&global_filesys_lock);
  return output;
}

SYSCALL_DEFINE(sc_open, SYS_OPEN, args, char* file_name) {
  struct process* pcb = thread_current()->pcb;
  char fn_copy[16];
  if (!strlcpy_from_user(fn_copy, args->file_name, 16))
    segfault();

  /* Allocate space for the new open file */
  struct open_file* file = malloc(sizeof *file);
  if (file == NULL)
    return -1;

  /* Open the file, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  file->fd = pcb->next_fd++;
  file->file = filesys_open(fn_copy);
  lock_release(&global_filesys_lock);

  if (file->file == NULL) {
    free(file);
    return -1;
  }

  // puts the created struct file* into the fd table
  list_push_back(&pcb->open_files, &file->elem);
  return file->fd;
}

/* Looks up a FD in the current thread's PCB. */
static struct open_file* fd_lookup(int fd_to_lookup) {
  struct process* pcb = thread_current()->pcb;
  if (fd_to_lookup < 2)
    return NULL;
  return list_find(&pcb->open_files, struct open_file, elem, file, file->fd == fd_to_lookup);
}

SYSCALL_DEFINE(sc_filesize, SYS_FILESIZE, args, int fd) {
  /* Look up FD from OFD */
  struct open_file* file = fd_lookup(args->fd);
  if (file == NULL)
    return -1;

  /* Return length of the file, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  off_t output = file_length(file->file);
  lock_release(&global_filesys_lock);

  return output;
}

SYSCALL_DEFINE(sc_read, SYS_READ, args, int fd, void* dst, unsigned size) {
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
  struct open_file* file = fd_lookup(args->fd);
  if (file == NULL)
    return -1;

  /* Allocate temporary buffer in kernel memory */
  uint8_t* buf = malloc(args->size);
  if (buf == NULL)
    return -1;

  /* Read from file to temporary buffer, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  int result = file_read(file->file, buf, args->size);
  lock_release(&global_filesys_lock);

  /* Copy to user memory using the helper (this handles segfaults) */
  if (!memcpy_to_user(args->dst, buf, args->size)) {
    free(buf);
    segfault();
  }

  free(buf);
  return result;
}

SYSCALL_DEFINE(sc_write, SYS_WRITE, args, int fd, void* src, unsigned size) {
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
  struct open_file* file = fd_lookup(args->fd);
  if (file == NULL)
    return -1;

  /* Read from temporary buffer to file, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  int result = file_write(file->file, args->src, args->size);
  lock_release(&global_filesys_lock);

  return result;
}

SYSCALL_DEFINE(sc_seek, SYS_SEEK, args, int fd, unsigned position) {
  /* Look up FD from OFD */
  struct open_file* file = fd_lookup(args->fd);
  if (file == NULL)
    return -1;

  /* Seek, making sure to acquire the lock */
  lock_acquire(&global_filesys_lock);
  file_seek(file->file, args->position);
  lock_release(&global_filesys_lock);

  return 0;
}

SYSCALL_DEFINE(sc_tell, SYS_TELL, args, int fd) {
  /* Look up FD from OFD */
  struct open_file* file = fd_lookup(args->fd);
  if (file == NULL)
    return -1;

  /* Don't need to acquire the lock here */
  return file_tell(file->file);
}

SYSCALL_DEFINE(sc_close, SYS_CLOSE, args, int fd) {
  /* Look up FD from OFD */
  struct open_file* file = fd_lookup(args->fd);
  if (file == NULL)
    return -1;

  lock_acquire(&global_filesys_lock);
  file_close(file->file);
  lock_release(&global_filesys_lock);

  /* Remove from the OFD table */
  list_remove(&file->elem);
  free(file);
  return 0;
}

// =================================
// Floating point operation syscalls
// =================================

SYSCALL_DEFINE(sc_compute_e, SYS_COMPUTE_E, args, int n) {
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
