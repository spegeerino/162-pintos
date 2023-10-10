/* Wait for a subprocess to finish, twice.
   The first call must wait in the usual way and return the exit code.
   The second wait call must return -1 immediately. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle1, handle2;
  handle2 = -1;

  CHECK(create("test.txt", 3), "create \"test.txt\"");

  for (int i = 0; i < 1000; i++) {
    handle1 = open("test.txt");
    if (handle1 < 2) {
      fail("open number %d returned invalid fd %d", 2 * i + 1, handle1);
    }
    if (handle1 == handle2) {
      fail("open number %d returned fd %d, same as previous open", 2 * i + 1, handle1);
    }
    handle2 = open("test.txt");
    if (handle2 < 2) {
      fail("open number %d returned invalid fd %d", 2 * i + 2, handle2);
    }
    if (handle1 == handle2) {
      fail("open number %d returned fd %d, same as previous open", 2 * i + 2, handle2);
    }
  }
}
