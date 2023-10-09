/* Waits for an invalid pid.  This may fail or terminate the
   process with -1 exit code. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  pid_t child = exec("child-simple");
  msg("wait(exec()) = %d", wait((pid_t)0x0c020301));
  msg("wait(exec()) = %d", wait(child));
}
