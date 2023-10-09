#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
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
static void segfault(struct intr_frame*);
static bool get_str(const uint8_t* uaddr, uint8_t* buf, int maxsize);
static bool get_bytes(const uint8_t* uaddr, uint8_t* buf, int size);
static bool get_byte(const uint8_t* uaddr, uint8_t* buf);
static bool put_byte(uint8_t* udst, uint8_t byte);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

struct syscall_desc {
  uint32_t syscall_number;
  uint32_t (*fun)(struct intr_frame* f, uint32_t* args);
  int nargs;
};

// ==============================
// Handlers for specific syscalls
// ==============================

static uint32_t sc_practice(struct intr_frame* f, uint32_t* args);
static uint32_t sc_halt(struct intr_frame* f, uint32_t* args) NO_RETURN;
static uint32_t sc_exit(struct intr_frame* f, uint32_t* args) NO_RETURN;
static uint32_t sc_exec(struct intr_frame* f, uint32_t* args);
static uint32_t sc_wait(struct intr_frame* f, uint32_t* args);

static uint32_t sc_create(struct intr_frame* f, uint32_t* args);
static uint32_t sc_remove(struct intr_frame* f, uint32_t* args);
static uint32_t sc_open(struct intr_frame* f, uint32_t* args);
static uint32_t sc_filesize(struct intr_frame* f, uint32_t* args);
static uint32_t sc_read(struct intr_frame* f, uint32_t* args);
static uint32_t sc_write(struct intr_frame* f, uint32_t* args);
static uint32_t sc_seek(struct intr_frame* f, uint32_t* args);
static uint32_t sc_tell(struct intr_frame* f, uint32_t* args);
static uint32_t sc_close(struct intr_frame* f, uint32_t* args);

static uint32_t sc_compute_e(struct intr_frame* f, uint32_t* args);

struct syscall_desc syscall_table[] = {
    // Process control syscalls
    {SYS_PRACTICE, sc_practice, 1},
    {SYS_HALT, sc_halt, 0},
    {SYS_EXIT, sc_exit, 1},
    {SYS_EXEC, sc_exec, 1},
    {SYS_WAIT, sc_wait, 1},

    // file operation syscalls
    {SYS_CREATE, sc_create, 2},
    {SYS_REMOVE, sc_remove, 1},
    {SYS_OPEN, sc_open, 1},
    {SYS_FILESIZE, sc_filesize, 1},
    {SYS_READ, sc_read, 3},
    {SYS_WRITE, sc_write, 3},
    {SYS_SEEK, sc_seek, 2},
    {SYS_TELL, sc_tell, 1},
    {SYS_CLOSE, sc_close, 1},

    {SYS_COMPUTE_E, sc_compute_e, 1},
};

// ========================
// Process control syscalls
// ========================
static uint32_t sc_practice(struct intr_frame* f UNUSED, uint32_t* args) {
  int arg = args[0];

  return arg + 1;
}

static uint32_t sc_halt(struct intr_frame* f UNUSED, uint32_t* args UNUSED) {
  shutdown_power_off();
  NOT_REACHED();
}

static uint32_t sc_exit(struct intr_frame* f, uint32_t* args) {
  int status = args[0];

  f->eax = status; // need to put it manually, this function will never return
  thread_current()->pcb->shared->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();

  NOT_REACHED();
}

static uint32_t sc_exec(struct intr_frame* f, uint32_t* args) {
  char* cmd_line = palloc_get_page(0);
  if (!get_str((uint8_t*)args[0], (uint8_t*)cmd_line, PGSIZE))
    segfault(f);

  return process_execute(cmd_line);
}

static uint32_t sc_wait(struct intr_frame* f UNUSED, uint32_t* args) {
  int child_pid = args[0];
  return process_wait(child_pid);
}

// =======================
// File operation syscalls
// =======================

static uint32_t sc_create(struct intr_frame* f, uint32_t* args) {
  bool success = true;
  unsigned char* file_name;
  unsigned size;
  if ((void*)args[0] == NULL) {
    success = false;
  }
  if (success) {
    file_name = (char*)malloc(16); // max filesize
    success = get_str((uint8_t*)args[0], file_name, 16);
    size = args[1];
  }

  if (!success || file_name == NULL) { // null or bad pointer
    f->eax = -1;
    thread_current()->pcb->shared->exit_status = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();

    NOT_REACHED();
  }

  struct process* pcb = thread_current()->pcb;

  lock_acquire(pcb->global_filesys_lock);
  int output = (int)filesys_create((char*)file_name, size);
  lock_release(pcb->global_filesys_lock);

  return output;
}

static uint32_t sc_remove(struct intr_frame* f UNUSED, uint32_t* args) {
  bool success = true;
  char* file_name;
  if (args[0] == NULL) {
    success = false;
  }
  if (success) {
    file_name = (char*)malloc(16); // max filesize
    success = get_str((uint8_t*)args[0], file_name, 16);
  }

  if (file_name == NULL || !success) { // null or bad pointer
    f->eax = -1;
    thread_current()->pcb->shared->exit_status = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();

    NOT_REACHED();
  }

  // remove file, using global lock on file operations to avoid races
  struct process* pcb = thread_current()->pcb;

  lock_acquire(pcb->global_filesys_lock);
  int output = (int)filesys_remove(file_name);
  lock_release(pcb->global_filesys_lock);

  return output;
}

// args are: file name
static uint32_t sc_open(struct intr_frame* f UNUSED, uint32_t* args) {
  bool success = true;
  char* file_name;
  if (args[0] == NULL) {
    success = false;
  }
  if (success) {
    file_name = (char*)malloc(16); // max filesize
    success = get_str((uint8_t*)args[0], file_name, 16);
  }

  if (file_name == NULL || !success) { // null or bad pointer
    f->eax = -1;
    thread_current()->pcb->shared->exit_status = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();

    NOT_REACHED();
  }

  // finds next open entry in fd table, potentially
  while (thread_current()->pcb->open_files[thread_current()->pcb->next_fd] != NULL) {
    thread_current()->pcb->next_fd =
        2 +
        ((thread_current()->pcb->next_fd - 1) %
         (NOFILE -
          2)); // a bit odd syntax, but basically this increments by 1 unless equal to NOFILE - 1, in which case sets to be 2.
  }

  struct process* pcb = thread_current()->pcb;

  lock_acquire(pcb->global_filesys_lock);
  struct file* output = filesys_open(file_name);
  lock_release(pcb->global_filesys_lock);

  if (output == NULL) {
    return -1;
  }

  // puts the created file* into the fd table
  thread_current()->pcb->open_files[thread_current()->pcb->next_fd] = output;

  return thread_current()->pcb->next_fd;
}

// args are: fd
static uint32_t sc_filesize(struct intr_frame* f UNUSED, uint32_t* args) {
  bool success = true;
  if (args[0] == NULL) {
    success = false;
  }
  int fd = args[0];
  // malloc unnecessary as not creating new inode
  //if (success) {
  //  file_name = (char*) malloc(16); // max filesize
  //  success = get_str((uint8_t*)args[0], file_name, 16);
  //}

  if (!success) { // null or bad pointer
    f->eax = -1;
    thread_current()->pcb->shared->exit_status = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();

    NOT_REACHED();
  }

  // file descriptor corresponds to empty entry in fd table
  if (fd < 0 || fd >= NOFILE || thread_current()->pcb->open_files[fd] == NULL) {
    return -1;
  }

  struct process* pcb = thread_current()->pcb;

  lock_acquire(pcb->global_filesys_lock);
  // call the file function
  off_t output = file_length(thread_current()->pcb->open_files[fd]);
  lock_release(pcb->global_filesys_lock);

  return (int)output;
}

// args: fd, buffer, size
static uint32_t sc_read(struct intr_frame* f UNUSED, uint32_t* args) {
  int fd = args[0];
  void* buffer = (void*)args[1];
  unsigned size = args[2];

  bool success = true;

  if (buffer >= (uint8_t*)PHYS_BASE) {
    success = false;
  }

  if (!success) { // null or bad pointer
    f->eax = -1;
    thread_current()->pcb->shared->exit_status = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();

    NOT_REACHED();
  }

  if (fd == 0) {
    for (int i = 0; i < size; i++) {
      int8_t input_char = input_getc();
      ((char*)buffer)[i] = input_char;
    }
    return size;
  }

  // if fd doesn't correspond to opened file
  if (fd < 0 || fd >= NOFILE || thread_current()->pcb->open_files[fd] == NULL) {
    return -1;
  }

  return (uint32_t)file_read(thread_current()->pcb->open_files[fd], buffer, size);

  //  return size;
}

static uint32_t sc_write(struct intr_frame* f UNUSED, uint32_t* args) {
  int fd = args[0];
  void* buffer = (void*)args[1];
  unsigned size = args[2];

  bool success = true;

  if (buffer >= (uint8_t*)PHYS_BASE) {
    success = false;
  }

  if (!success) { // null or bad pointer
    f->eax = -1;
    thread_current()->pcb->shared->exit_status = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();

    NOT_REACHED();
  }

  if (fd == 1) {
    putbuf(buffer, size);
  }

  // if fd doesn't correspond to opened file
  if (fd < 0 || fd >= NOFILE || thread_current()->pcb->open_files[fd] == NULL) {
    return -1;
  }

  return file_write(thread_current()->pcb->open_files[fd], buffer, size);
}

static uint32_t sc_seek(struct intr_frame* f, uint32_t* args) {
  int fd = args[0];
  int position = args[1];
  struct process* pcb = thread_current()->pcb;
  bool success = fd >= 3 && fd < NOFILE; // fail if fd is out of range
  success = success && position >= 0;
  struct file* file = NULL;
  if (success) {
    file = pcb->open_files[fd];
    success = file != NULL; // fail if fd is not currently open
  }
  if (!success) {
    f->eax = -1;
    pcb->shared->exit_status = -1;
    printf("%s: exit(%d)\n", pcb->process_name, -1);
    process_exit();
  }
  file_seek(file, (unsigned)position);
  return 0;
}

static uint32_t sc_tell(struct intr_frame* f, uint32_t* args) {
  int fd = args[0];
  struct process* pcb = thread_current()->pcb;
  bool success = fd >= 3 && fd < NOFILE; // fail if fd is out of range
  struct file* file = NULL;
  if (success) {
    file = pcb->open_files[fd];
    success = file != NULL; // fail if fd is not currently open
  }
  if (!success) {
    f->eax = -1;
    pcb->shared->exit_status = -1;
    printf("%s: exit(%d)\n", pcb->process_name, -1);
    process_exit();
  }
  return file_tell(file);
}

// args are: fd
static uint32_t sc_close(struct intr_frame* f UNUSED, uint32_t* args) {
  bool success = true;
  int fd;
  if (args[0] == NULL || args[0] == 0 || args[0] == 1 || args[0] != (args[0] % NOFILE)) {
    success = false;
  }
  fd = args[0];

  // malloc unnecessary as not creating new inode
  //if (success) {
  //  file_name = (char*) malloc(16); // max filesize
  //  success = get_str((uint8_t*)args[0], file_name, 16);
  //}

  if (!success) { // null or bad pointer
    f->eax = -1;
    thread_current()->pcb->shared->exit_status = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();

    NOT_REACHED();
  }

  struct process* pcb = thread_current()->pcb;

  lock_acquire(pcb->global_filesys_lock);
  // closes the file; this function also frees everything
  file_close(thread_current()->pcb->open_files[fd]);
  lock_release(pcb->global_filesys_lock);

  // re-references the entry in the fd table to NULL
  thread_current()->pcb->open_files[fd] = NULL;

  return;
}

// ================================
// Floating point operation syscall
// ================================

static uint32_t sc_compute_e(struct intr_frame* f UNUSED, uint32_t* args) {
  int n = args[0];
  if (n < 0) {
    return -1;
  }
  return sys_sum_to_e(n);
}

// =============================
// General syscall handler stuff
// =============================

static struct syscall_desc* syscall_lookup(uint32_t syscall_number) {
  for (unsigned i = 0; i < sizeof(syscall_table) / sizeof(*syscall_table); i++) {
    if (syscall_table[i].syscall_number == syscall_number) {
      return &syscall_table[i];
    }
  }
  return NULL;
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
  if (!get_bytes(f->esp, (uint8_t*)&syscall_number, 4)) {
    segfault(f);
  }

  struct syscall_desc* syscall = syscall_lookup(syscall_number);
  if (syscall == NULL) {
    f->eax = -1;
    return;
  }

  uint32_t args[SYSCALL_MAX_NARGS];
  if (!get_bytes(f->esp + 4, (uint8_t*)args, syscall->nargs * 4)) {
    segfault(f);
  }

  f->eax = syscall->fun(f, args);
}

static void segfault(struct intr_frame* f) {
  uint32_t args[] = {-1};
  sc_exit(f, args);
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
