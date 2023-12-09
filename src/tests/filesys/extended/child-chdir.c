/* Tests mkdir(). */

#include <stdlib.h>
#include <syscall.h>
#include "tests/lib.h"
#include <syscall.h>

int main(int argc, const char* argv[]) {
  CHECK(open("b") > 1, "see if \"b\" is inside directory");

  return 0;
}