#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
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
static void segfault(void);
static bool get_str(const uint8_t* uaddr, uint8_t* buf, int maxsize);
static bool get_bytes(const uint8_t* uaddr, uint8_t* buf, int size);
static bool get_byte(const uint8_t* uaddr, uint8_t* buf);
static bool put_bytes(uint8_t* udst, uint8_t* buf, int size);
static bool put_byte(uint8_t* udst, uint8_t byte);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

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
  if (!get_str((uint8_t*)args->cmd_line, (uint8_t*)cl_copy, PGSIZE))
    segfault();

  return process_execute(cl_copy);
}

SYSCALL_DEFINE(sc_wait, SYS_WAIT, args, pid_t pid) { return process_wait(args->pid); }

// =======================
// File operation syscalls
// =======================

SYSCALL_DEFINE(sc_create, SYS_CREATE, args, char* file_name, unsigned initial_size) {
  char fn_copy[16];
  if (!get_str((uint8_t*)args->file_name, (uint8_t*)fn_copy, 16))
    segfault();

  struct process* pcb = thread_current()->pcb;
  lock_acquire(pcb->global_filesys_lock);
  uint32_t output = filesys_create(fn_copy, args->initial_size);
  lock_release(pcb->global_filesys_lock);

  return output;
}

SYSCALL_DEFINE(sc_remove, SYS_REMOVE, args, char* file_name) {
  char fn_copy[16];
  if (!get_str((uint8_t*)args->file_name, (uint8_t*)fn_copy, 16))
    segfault();

  // remove file, using global lock on file operations to avoid races
  struct process* pcb = thread_current()->pcb;
  lock_acquire(pcb->global_filesys_lock);
  int output = (int)filesys_remove(fn_copy);
  lock_release(pcb->global_filesys_lock);

  return output;
}

SYSCALL_DEFINE(sc_open, SYS_OPEN, args, char* file_name) {
  char fn_copy[16];
  if (!get_str((uint8_t*)args->file_name, (uint8_t*)fn_copy, 16))
    segfault();

  // finds next open entry in fd table, potentially
  while (thread_current()->pcb->open_files[thread_current()->pcb->next_fd] != NULL) {
    // a bit odd syntax, but basically this increments by 1 unless equal to NOFILE - 1, in which case sets to be 2.
    thread_current()->pcb->next_fd = 2 + ((thread_current()->pcb->next_fd - 1) % (NOFILE - 2));
  }

  struct process* pcb = thread_current()->pcb;

  lock_acquire(pcb->global_filesys_lock);
  struct file* output = filesys_open(fn_copy);
  lock_release(pcb->global_filesys_lock);

  if (output == NULL)
    return -1;

  // puts the created file* into the fd table
  thread_current()->pcb->open_files[thread_current()->pcb->next_fd] = output;

  return thread_current()->pcb->next_fd;
}

SYSCALL_DEFINE(sc_filesize, SYS_FILESIZE, args, int fd) {
  // file descriptor corresponds to empty entry in fd table
  if (args->fd < 0 || args->fd >= NOFILE || thread_current()->pcb->open_files[args->fd] == NULL) {
    return -1;
  }

  struct process* pcb = thread_current()->pcb;

  lock_acquire(pcb->global_filesys_lock);
  // call the file function
  off_t output = file_length(thread_current()->pcb->open_files[args->fd]);
  lock_release(pcb->global_filesys_lock);

  return (int)output;
}

SYSCALL_DEFINE(sc_read, SYS_READ, args, int fd, void* dst, unsigned size) {
  if (args->fd == 0) {
    for (unsigned i = 0; i < args->size; i++)
      if (!put_byte(args->dst++, input_getc()))
        segfault();
    return args->size;
  }

  // if fd doesn't correspond to opened file
  if (args->fd < 0 || args->fd >= NOFILE || thread_current()->pcb->open_files[args->fd] == NULL) {
    return -1;
  }

  uint8_t* buf = malloc(args->size);

  struct process* pcb = thread_current()->pcb;
  lock_acquire(pcb->global_filesys_lock);
  int result = file_read(thread_current()->pcb->open_files[args->fd], buf, args->size);
  lock_release(pcb->global_filesys_lock);

  if (!put_bytes(args->dst, buf, args->size)) {
    free(buf);
    segfault();
  }
  free(buf);

  return result;
}

SYSCALL_DEFINE(sc_write, SYS_WRITE, args, int fd, void* src, unsigned size) {
  char* buf = malloc(args->size);
  if (!get_bytes(args->src, (uint8_t*)buf, args->size))
    segfault();

  if (args->fd == 1) {
    putbuf(buf, args->size);
    return args->size;
  }

  // if fd doesn't correspond to opened file
  if (args->fd < 0 || args->fd >= NOFILE || thread_current()->pcb->open_files[args->fd] == NULL) {
    return -1;
  }

  struct process* pcb = thread_current()->pcb;
  lock_acquire(pcb->global_filesys_lock);
  int result = file_write(thread_current()->pcb->open_files[args->fd], args->src, args->size);
  lock_release(pcb->global_filesys_lock);

  return result;
}

SYSCALL_DEFINE(sc_seek, SYS_SEEK, args, int fd, unsigned position) {
  struct process* pcb = thread_current()->pcb;
  bool success = args->fd >= 3 && args->fd < NOFILE; // fail if fd is out of range
  success = success && args->position >= 0;
  struct file* file = NULL;
  if (success) {
    file = pcb->open_files[args->fd];
    success = file != NULL; // fail if fd is not currently open
  }
  if (!success) {
    segfault();
  }
  file_seek(file, args->position);
  return 0;
}

SYSCALL_DEFINE(sc_tell, SYS_TELL, args, int fd) {
  struct process* pcb = thread_current()->pcb;
  bool success = args->fd >= 3 && args->fd < NOFILE; // fail if fd is out of range
  struct file* file = NULL;
  if (success) {
    file = pcb->open_files[args->fd];
    success = file != NULL; // fail if fd is not currently open
  }
  if (!success) {
    segfault();
  }
  return file_tell(file);
}

SYSCALL_DEFINE(sc_close, SYS_CLOSE, args, int fd) {
  bool success = true;
  if (args->fd == NULL || args->fd == 0 || args->fd == 1 || args->fd != (args->fd % NOFILE)) {
    success = false;
  }

  // malloc unnecessary as not creating new inode
  //if (success) {
  //  file_name = (char*) malloc(16); // max filesize
  //  success = get_str((uint8_t*)args[0], file_name, 16);
  //}

  if (!success) { // null or bad pointer
    segfault();
  }

  struct process* pcb = thread_current()->pcb;

  lock_acquire(pcb->global_filesys_lock);
  // closes the file; this function also frees everything
  file_close(thread_current()->pcb->open_files[args->fd]);
  lock_release(pcb->global_filesys_lock);

  // re-references the entry in the fd table to NULL
  thread_current()->pcb->open_files[args->fd] = NULL;

  return 0;
}

// =================================
// Floating point operation syscalls
// =================================

SYSCALL_DEFINE(sc_compute_e, SYS_COMPUTE_E, args, int n) {
  if (args->n < 0) {
    return -1;
  }
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
  for (unsigned i = 0; i < sizeof(syscall_table) / sizeof(syscall_table[0]); i++) {
    if (syscall_table[i]->syscall_number == syscall_number) {
      return syscall_table[i];
    }
  }
  return NULL;
}

static void syscall_handler(struct intr_frame* f) {
  uint32_t syscall_number;
  if (!get_bytes(f->esp, (uint8_t*)&syscall_number, 4)) {
    segfault();
  }

  struct syscall* syscall = syscall_lookup(syscall_number);
  if (syscall == NULL) {
    f->eax = -1;
    return;
  }

  uint32_t args[SYSCALL_MAX_NARGS];
  if (!get_bytes(f->esp + 4, (uint8_t*)args, syscall->args_size)) {
    segfault();
  }

  f->eax = syscall->handler(args);
}

static void segfault() {
  uint32_t args[] = {-1};
  sc_exit.handler(args);
}

// =======
// Helpers
// =======

/* Reads string starting at user virtual address UADDR into buf.
   Returns true if successful,
   false if a segfault occurred. */
static bool get_str(const uint8_t* uaddr, uint8_t* buf, int maxsize) {
  uint8_t tmp = 1;
  for (int i = 0; tmp && i < maxsize - 1; i++) {
    if (!get_byte(uaddr++, &tmp))
      return false;
    *(buf++) = tmp;
  }
  *buf = 0;
  return true;
}

/* Reads multiple bytes at user virtual address UADDR into buf.
   Returns true if successful,
   false if a segfault occurred. */
static bool get_bytes(const uint8_t* uaddr, uint8_t* buf, int size) {
  for (int i = 0; i < size; i++) {
    if (!get_byte(uaddr++, buf++)) {
      return false;
    }
  }
  return true;
}

/* Reads a byte at user virtual address UADDR into buf.
   Returns true if successful,
   false if a segfault occurred. */
static bool get_byte(const uint8_t* uaddr, uint8_t* buf) {
  if (uaddr >= (uint8_t*)PHYS_BASE) {
    return false;
  }

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

  if (result == -1) {
    return false;
  }

  *buf = result;
  return true;
}

/* Writes multiple bytes to user virtual address UDST.
   Returns true if successful,
   false if a segfault occurred. */
static bool put_bytes(uint8_t* udst, uint8_t* buf, int size) {
  for (int i = 0; i < size; i++) {
    if (!put_byte(udst++, *buf++)) {
      return false;
    }
  }
  return true;
}

/* Writes BYTE to user address UDST.
   Returns true if successful,
   false if a segfault occurred. */
static bool put_byte(uint8_t* udst, uint8_t byte) {
  if (udst >= (uint8_t*)PHYS_BASE) {
    return false;
  }

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
