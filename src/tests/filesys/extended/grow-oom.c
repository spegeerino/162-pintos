/* Create a file with initial size of 0 bytes, and attempt to grow it to an absurdly large size, resulting in a block allocation error. As rollback is the intended behavior here, we check that after the allocation error is handled the file size remains 0 bytes, AND that allocating another large file will be successful (i.e. the allocated blocks during the improper call were freed correctly). */

#include <syscall.h>
#include "tests/filesys/seq-test.h"
#include "tests/lib.h"
#include "tests/main.h"
#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <stdlib.h>
static char zero_buf[4];
static char buf[72345];

static size_t return_block_size(void) { return 345; }

static void check_file_size(int fd, long ofs) {
  long size = filesize(fd);
  if (size != ofs)
    fail("filesize not updated properly: should be %ld, actually %ld", ofs, size);
}

void test_main(void) {
  const char* file_name = "testfile";
  char zero = 0;
  int fd;

  CHECK(create(file_name, 0), "create \"%s\"", file_name);
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  msg("seek \"%s\"", file_name);
  seek(fd, INT32_MAX - 10);
  CHECK(write(fd, &zero_buf, 1) == 0, "successfully failed to write \"%s\"", file_name);
  check_file_size(fd, 0);
  msg("close \"%s\"", file_name);
  close(fd);

  seq_test("boondoggles", buf, sizeof buf, 0, return_block_size, NULL);
}