#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "list.h"
#include "threads/arc.h"
#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

extern struct lock global_filesys_lock;

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

  struct shared_proc_data* shared; /* Data shared between process and its parent (exec/wait)  */
  struct list children_shared;     /* List of children's process data (exec/wait) */

  struct list open_files;      /* List of process's open files */
  struct file* self_exec_file; /* Pointer to file executable to deny_write to executable */
  int next_fd;
};

struct open_file {
  int fd;
  struct file* file;
  struct list_elem elem;
};

struct shared_proc_data {
  pid_t pid;
  char* cmd_line;
  struct semaphore exec_sema;
  struct semaphore wait_sema;
  int exit_status;

  struct list_elem elem;
  struct arc arc;
};

void userprog_init(void);

int process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool shared_proc_data_init(struct shared_proc_data* shared);
void shared_proc_data_destroy(struct arc* arc);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
