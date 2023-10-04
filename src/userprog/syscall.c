#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

#define SYSCALL_MAX_NARGS 5

static void syscall_handler(struct intr_frame*);

static uint32_t sc_practice(struct intr_frame* f, uint32_t* args);
static uint32_t sc_exit(struct intr_frame* f, uint32_t* args) NO_RETURN;
static uint32_t sc_write(struct intr_frame* f, uint32_t* args);

static bool get_user_chunk(const uint8_t* uaddr, uint8_t* buf, int size);
static bool get_user(const uint8_t* uaddr, uint8_t* buf);
static bool put_user(uint8_t* udst, uint8_t byte);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

struct syscall_desc {
  uint32_t syscall_number;
  uint32_t (*fun)(struct intr_frame* f, uint32_t* args);
  int nargs;
};

struct syscall_desc syscall_table[] = {
    {SYS_PRACTICE, sc_practice, 1},
    {SYS_EXIT, sc_exit, 1},
    {SYS_WRITE, sc_write, 3},
};

static struct syscall_desc* syscall_lookup(uint32_t syscall_number) {
  for (unsigned i = 0; i < sizeof(syscall_table) / sizeof(*syscall_table); i++) {
    if (syscall_table[i].syscall_number == syscall_number) {
      return &syscall_table[i];
    }
  }
  return NULL;
}

static void segfault(struct intr_frame* f) {
  uint32_t args[] = {-1};
  sc_exit(f, args);
}

static void syscall_handler(struct intr_frame* f) {
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  uint32_t syscall_number;
  if (!get_user_chunk(f->esp, (uint8_t*)&syscall_number, 4)) {
    segfault(f);
  }

  struct syscall_desc* syscall = syscall_lookup(syscall_number);
  if (syscall == NULL) {
    f->eax = -1;
    return;
  }

  uint32_t args[SYSCALL_MAX_NARGS];
  if (!get_user_chunk(f->esp + 4, (uint8_t*)args, syscall->nargs * 4)) {
    segfault(f);
  }

  f->eax = syscall->fun(f, args);
}

// ==============================
// Handlers for specific syscalls
// ==============================

static uint32_t sc_practice(struct intr_frame* f UNUSED, uint32_t* args) {
  int arg = args[0];

  return arg + 1;
}

static uint32_t sc_exit(struct intr_frame* f, uint32_t* args) {
  int status = args[0];

  f->eax = status; // need to put it manually, this function will never return
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();

  NOT_REACHED();
}

static uint32_t sc_write(struct intr_frame* f UNUSED, uint32_t* args) {
  int fd = args[0];
  void* buffer = (void*)args[1];
  unsigned size = args[2];

  if (fd == 1) {
    putbuf(buffer, size);
  }

  // TODO: everything except stdout

  return size;
}

// =======
// Helpers
// =======

/* Reads multiple bytes at user virtual address UADDR into buf.
   Returns true if successful,
   false if a segfault occurred. */
static bool get_user_chunk(const uint8_t* uaddr, uint8_t* buf, int size) {
  for (int i = 0; i < size; i++) {
    if (!get_user(uaddr++, buf++)) {
      return false;
    }
  }
  return true;
}

/* Reads a byte at user virtual address UADDR into buf.
   Returns true if successful,
   false if a segfault occurred. */
static bool get_user(const uint8_t* uaddr, uint8_t* buf) {
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

/* Writes BYTE to user address UDST.
   Returns true if successful,
   false if a segfault occurred. */
static bool put_user(uint8_t* udst, uint8_t byte) {
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
