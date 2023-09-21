#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  }

  if (args[0] == SYS_WRITE) {
    int fd = args[1];
    const void* buffer = args[2];
    unsigned size = args[3];

    if (fd == 1) {
      putbuf(buffer, size);
    }
  }
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful,
   -1 if a segfault occurred. */
static int get_user(const uint8_t* uaddr) {
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

  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful,
   false if a segfault occurred. */
static bool put_user(uint8_t* udst, uint8_t byte) {
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
