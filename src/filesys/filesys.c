#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/malloc.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); }

/* Extracts the directory path and file name from a given path.
   Returns the file name and sets *PATH to the directory path.
   WARNING: This function is extremely cursed.
   It mutates the original string to insert a null terminator if necessary.
   Somehow it's the least painful way I found to accomplish this. */
static char* extract_file_name(char** path) {
  char* last_sep = strrchr(*path, '/');
  if (last_sep == NULL) {
    char* result = *path;
    *path = ".";
    return result;
  } else if (last_sep == *path) {
    *path = "/";
    return last_sep + 1;
  } else {
    *last_sep = '\0';
    return last_sep + 1;
  }
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create_file(struct dir* cwd, const char* _path, off_t initial_size) {
  autofree char* path_copy = strdup(_path);
  char* path = path_copy;
  char* name = extract_file_name(&path);

  struct dir* dir = filesys_open_dir(cwd, path);
  if (dir == NULL)
    return false;

  block_sector_t inode_sector = 0;
  if (!free_map_allocate(1, &inode_sector))
    return false;
  if (!inode_create(inode_sector, initial_size, FILE))
    goto cleanup;
  if (!dir_add(dir, name, inode_sector))
    goto cleanup;

  dir_close(dir);
  return true;

cleanup:
  // FIXME: See comment in dir_create.
  free_map_release(inode_sector, 1);
  dir_close(dir);
  return false;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create_dir(struct dir* cwd, const char* _path) {
  autofree char* path_copy = strdup(_path);
  char* path = path_copy;
  char* name = extract_file_name(&path);

  struct dir* dir = filesys_open_dir(cwd, path);
  if (dir == NULL)
    return false;

  block_sector_t inode_sector = 0;
  if (!free_map_allocate(1, &inode_sector))
    return false;
  if (!dir_create(inode_sector, dir->inode->sector))
    goto cleanup;
  if (!dir_add(dir, name, inode_sector))
    goto cleanup;

  dir_close(dir);
  return true;

cleanup:
  // FIXME: See comment in dir_create.
  free_map_release(inode_sector, 1);
  dir_close(dir);
  return false;
}

/* Opens the inode at the given PATH.
   Returns the new inode if successful or a null pointer
   otherwise.
   Fails if no inode at PATH exists,
   or if an internal memory allocation fails. */
struct inode* filesys_open(struct dir* cwd, const char* path) {
  struct dir* dir = cwd == NULL ? dir_open_root() : dir_reopen(cwd);
  struct inode* inode = NULL;

  if (dir != NULL && !dir->inode->removed)
    dir_resolve(dir, path, &inode);
  dir_close(dir);

  return inode;
}

/* Opens the file at the given PATH.
   Returns the file if successful or a null pointer otherwise.
   Fails if no file at PATH exists,
   or if an internal memory allocation fails. */
struct file* filesys_open_file(struct dir* cwd, const char* path) {
  struct inode* inode = filesys_open(cwd, path);
  if (inode != NULL && inode->data.type == FILE)
    return file_open(inode);
  inode_close(inode);
  return NULL;
}

/* Opens the directory at the given PATH.
   Returns the directory if successful or a null pointer otherwise.
   Fails if no directory at PATH exists,
   or if an internal memory allocation fails. */
struct dir* filesys_open_dir(struct dir* cwd, const char* path) {
  struct inode* inode = filesys_open(cwd, path);
  if (inode != NULL && inode->data.type == DIRECTORY)
    return dir_open(inode);
  inode_close(inode);
  return NULL;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(struct dir* cwd, const char* _path) {
  autofree char* path_copy = strdup(_path);
  char* path = path_copy;
  char* name = extract_file_name(&path);

  struct dir* dir = filesys_open_dir(cwd, path);
  if (dir == NULL)
    return false;

  if (!dir_remove(dir, name))
    goto cleanup;
  dir_close(dir);
  return true;

cleanup:
  dir_close(dir);
  return false;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, ROOT_DIR_SECTOR))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
