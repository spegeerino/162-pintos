/* Open a file twice. Then, write to file once from each fd.
    The second write should overwrite the first, so it should
    write completely.  */

#include <syscall.h>
#include "tests/userprog/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle1, handle2, handle3, handle4, byte_cnt;

  CHECK(create("test.txt", sizeof sample - 1), "create \"test.txt\"");
  CHECK(create("test2.txt", sizeof sample - 1), "create \"test2.txt\"");

  CHECK((handle1 = open("test.txt")) > 1, "open \"test.txt\" first time");
  CHECK((handle2 = open("test.txt")) > 1, "open \"test.txt\" second time");

  byte_cnt = write(handle1, sample, sizeof sample - 2);
  if (byte_cnt != sizeof sample - 2)
    fail("First test.txt open write() returned %d instead of %zu", byte_cnt, sizeof sample - 2);

  byte_cnt = write(handle2, sample, sizeof sample - 2);
  if (byte_cnt != sizeof sample - 2)
    fail("Second test.txt open write() returned %d instead of %zu", byte_cnt, sizeof sample - 2);

  CHECK((handle3 = open("test2.txt")) > 1, "open \"test2.txt\" first time");
  CHECK((handle4 = open("test2.txt")) > 1, "open \"test2.txt\" second time");

  byte_cnt = write(handle4, sample, sizeof sample - 1);
  if (byte_cnt != sizeof sample - 1)
    fail("First test2.txt open write() returned %d instead of %zu", byte_cnt, sizeof sample - 1);

  byte_cnt = write(handle3, sample, 3);
  if (byte_cnt != 3)
    fail("Second test2.txt open write() returned %d instead of %zu", byte_cnt, 3);
}
