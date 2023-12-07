#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/directory.h"
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */

/* Block device that contains the file system. */
extern struct block* fs_device;

void filesys_init(bool format);
void filesys_done(void);
bool filesys_create_file(struct dir* cwd, const char* path, off_t initial_size);
bool filesys_create_dir(struct dir* cwd, const char* path);
struct inode* filesys_open(struct dir* cwd, const char* path);
struct file* filesys_open_file(struct dir* cwd, const char* path);
struct dir* filesys_open_dir(struct dir* cwd, const char* path);
bool filesys_remove(struct dir* cwd, const char* path);

#endif /* filesys/filesys.h */
