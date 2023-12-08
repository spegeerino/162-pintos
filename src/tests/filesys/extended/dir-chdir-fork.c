/* Tests mkdir(). */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  pid_t children[1];
  CHECK(mkdir("a"), "mkdir \"a\"");
  CHECK(create("a/b", 512), "create \"a/b\"");
  CHECK(chdir("a"), "chdir \"a\"");

  exec_children("../child-chdir", children, 1);
  wait_children(children, 1);
  CHECK(open("b") > 1, "open \"b\"");
}
