#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <list.h>
#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"

struct bitmap;

enum inode_type { FILE, DIRECTORY };

/* Constants regarding inode structure. */
#define NUM_DIRECT_POINTERS 123
#define NUM_INDIRECT_POINTERS 2
#define INDIRECT_BLOCK_CAPACITY (BLOCK_SECTOR_SIZE / sizeof(block_sector_t))

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  off_t length;                                   /* File size in bytes. */
  enum inode_type type;                           /* FILE or DIRECTORY. */
  block_sector_t direct[NUM_DIRECT_POINTERS];     /* Pointers to direct data blocks. */
  block_sector_t indirect[NUM_INDIRECT_POINTERS]; /* Pointers to indirect blocks. */
  unsigned magic;                                 /* Magic number. */
};

/* In-memory inode. */
struct inode {
  enum inode_type type;  /* FILE or DIRECTORY. */
  struct lock lock;      /* Syncrhonization lock. */
  struct list_elem elem; /* Element in inode list. */
  block_sector_t sector; /* Sector number of disk location. */
  int open_cnt;          /* Number of openers. */
  bool removed;          /* True if deleted, false otherwise. */
  int deny_write_cnt;    /* 0: writes ok, >0: deny writes. */
};

/* Disk indirect block. */
struct indirect_block {
  block_sector_t sector_arr[INDIRECT_BLOCK_CAPACITY];
};

void inode_init(void);
void inode_done(void);
bool inode_create(block_sector_t, off_t, enum inode_type);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);

#endif /* filesys/inode.h */
