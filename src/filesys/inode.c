#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "devices/block.h"
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/buffer-cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define MAX(A, B) (A >= B ? A : B)
#define MIN(A, B) (A <= B ? A : B)

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }
static bool inode_disk_resize(struct inode_disk*, off_t);

/* Looks up a block in an indirect block. */
static block_sector_t indirect_block_lookup(block_sector_t indirect_sector, size_t index) {
  if (indirect_sector == 0)
    return 0;
  block_sector_t result;
  buffer_cache_read(indirect_sector, &result, sizeof result, index * sizeof(block_sector_t));
  return result;
}

/* Retrieves the sector corresponding to block IDX in the inode disk INODE_DISK.
   Returns 0 if the sector is not allocated. */
static block_sector_t inode_disk_get_sector(struct inode_disk* disk_inode, size_t idx) {
  if (idx < DIRECT_MAX) {
    return disk_inode->direct[idx];
  }

  if (idx < INDIRECT_MAX) {
    return indirect_block_lookup(disk_inode->indirect, idx - DIRECT_MAX);
  }

  if (idx < DOUBLY_INDIRECT_MAX) {
    size_t indirect_idx = (idx - INDIRECT_MAX) / INDIRECT_CAPACITY;
    size_t direct_idx = (idx - INDIRECT_MAX) % INDIRECT_CAPACITY;
    block_sector_t indirect = indirect_block_lookup(disk_inode->doubly_indirect, indirect_idx);
    return indirect_block_lookup(indirect, direct_idx);
  }

  return 0;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  struct inode_disk inode_disk;
  buffer_cache_read(inode->sector, &inode_disk, sizeof inode_disk, 0);
  if (pos >= inode_disk.length)
    return -1;
  block_sector_t result = inode_disk_get_sector(&inode_disk, pos / BLOCK_SECTOR_SIZE);
  if (result == 0)
    return -1;
  return result;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct lock open_inodes_lock;
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  lock_init(&open_inodes_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, enum inode_type type) {
  ASSERT(length >= 0);
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof(struct inode_disk) == BLOCK_SECTOR_SIZE);

  size_t sectors = bytes_to_sectors(length);
  if (sectors >= DOUBLY_INDIRECT_MAX)
    return false;

  /* Initialize inode_disk */
  autofree struct inode_disk* disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode == NULL)
    return false;
  disk_inode->type = type;
  disk_inode->length = 0;
  disk_inode->magic = INODE_MAGIC;

  /* Allocate blocks */
  if (!inode_disk_resize(disk_inode, length))
    return false;

  /* Write inode_disk to disk */
  buffer_cache_write(sector, disk_inode, sizeof *disk_inode, 0);

  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  lock_acquire(&open_inodes_lock);

  /* Check whether this inode is already open. */
  struct inode* inode = list_find(&open_inodes, struct inode, elem, inode, inode->sector == sector);
  if (inode != NULL) {
    inode = inode_reopen(inode);
    goto done;
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    goto done;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  lock_init(&inode->lock);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  /* Read in inode->type from disk */
  buffer_cache_read(sector, &inode->type, sizeof inode->type, offsetof(struct inode_disk, type));

done:
  lock_release(&open_inodes_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode == NULL)
    return NULL;
  lock_acquire(&inode->lock);
  if (inode->open_cnt == 0) {
    inode = NULL;
  } else {
    inode->open_cnt++;
  }
  lock_release(&inode->lock);
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire(&inode->lock);
  int open_cnt = --inode->open_cnt;
  lock_release(&inode->lock);

  /* If other still have it open, leave it there */
  if (open_cnt > 0) {
    return;
  }

  lock_acquire(&open_inodes_lock);

  /* Deallocate blocks if removed. */
  if (inode->removed) {
    struct inode_disk disk_inode;
    buffer_cache_read(inode->sector, &disk_inode, sizeof disk_inode, 0);
    inode_disk_resize(&disk_inode, 0);
    free_map_release(inode->sector, 1);
  }

  /* Remove from inode list */
  list_remove(&inode->elem);
  free(inode);

  lock_release(&open_inodes_lock);
  return;
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  lock_acquire(&inode->lock);
  inode->removed = true;
  lock_release(&inode->lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer, off_t size, off_t offset) {
  /* Read inode from disk */
  autofree struct inode_disk* disk_inode = malloc(sizeof *disk_inode);
  buffer_cache_read(inode->sector, disk_inode, sizeof *disk_inode, 0);

  block_sector_t sector = byte_to_sector(inode, offset);
  if (sector == (uint32_t)-1)
    return 0;

  off_t bytes_read = 0;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = disk_inode->length - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = MIN(inode_left, sector_left);

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = MIN(size, min_left);
    if (chunk_size <= 0)
      break;

    /* Copy bytes to buffer. */
    buffer_cache_read(sector, buffer + bytes_read, chunk_size, sector_ofs);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;

    /* Update cache if new sector required. */
    if (size > 0 && inode_left > chunk_size) { // chunk_size == sector_left and more to write
      sector = byte_to_sector(inode, offset);
      if (sector == (uint32_t)-1)
        break;
    }
  }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer, off_t size, off_t offset) {
  if (inode->deny_write_cnt)
    return 0;

  lock_acquire(&inode->lock);

  /* Read inode from disk */
  autofree struct inode_disk* disk_inode = malloc(sizeof *disk_inode);
  buffer_cache_read(inode->sector, disk_inode, sizeof *disk_inode, 0);

  /* In case we need to grow the inode */
  if (offset + size > disk_inode->length) {
    if (!inode_disk_resize(disk_inode, offset + size)) {
      lock_release(&inode->lock);
      return 0;
    }
    buffer_cache_write(inode->sector, disk_inode, sizeof *disk_inode, 0);
  }

  /* Check cache for desired entry. */
  block_sector_t sector = byte_to_sector(inode, offset);
  if (sector == (uint32_t)-1) {
    lock_release(&inode->lock);
    return 0;
  }

  off_t bytes_written = 0;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = disk_inode->length - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = MIN(inode_left, sector_left);

    /* Number of bytes to actually write into this sector. */
    int chunk_size = MIN(size, min_left);
    if (chunk_size <= 0)
      break;

    /* Copy bytes from buffer. */
    buffer_cache_write(sector, buffer + bytes_written, chunk_size, sector_ofs);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;

    /* Update cache if new sector required. */
    if (size > 0 && inode_left > chunk_size) { // sector_left = chunk_size and we have more to write
      sector = byte_to_sector(inode, offset);
      if (sector == (uint32_t)-1)
        break;
    }
  }

  lock_release(&inode->lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  lock_acquire(&inode->lock);
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  lock_acquire(&inode->lock);
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->lock);
}

/* Resize the indirect block at *SECTOR to have NEEDED blocks, allocating
   and freeing children blocks as necessary.
   Recursively calls itself to resize children blocks. DEPTH is the
   depth of the block, with 0 being a direct block, 1 being an indirect
   block, and 2 being a doubly indirect block.
   If NEEDED <= 0, also free the block (and children blocks).
   If NEEDED > 0, also allocate the block if it doesn't exist.
   Returns true on success, false on failure. */
static bool indirect_block_resize(int depth, block_sector_t* sector, int needed) {
  /* If we don't need a block and none is allocated, we are done */
  if (needed <= 0 && *sector == 0)
    return true;

  /* Allocate or read in a block */
  indirect_block_t block;
  if (*sector == 0) {
    if (!free_map_allocate(1, sector))
      return false;
    memset(block, 0, BLOCK_SECTOR_SIZE);
  } else {
    buffer_cache_read(*sector, &block, sizeof block, 0);
  }

  if (depth > 0) {
    /* Calculate child capacity */
    size_t child_capacity = 1;
    for (int i = 1; i < depth; i++)
      child_capacity *= INDIRECT_CAPACITY;

    /* Loop through child blocks */
    for (size_t idx = 0; idx < INDIRECT_CAPACITY; idx++)
      if (!indirect_block_resize(depth - 1, &block[idx], needed - idx * child_capacity))
        return false;
  }

  /* Write back block, or free it if we don't need it anymore */
  if (needed <= 0) {
    free_map_release(*sector, 1);
    *sector = (block_sector_t)0;
  } else {
    buffer_cache_write(*sector, &block, sizeof block, 0);
  }

  return true;
}

static bool inode_disk_resize(struct inode_disk* disk_inode, off_t new_length) {
  ASSERT(disk_inode != NULL);
  ASSERT(new_length >= 0);
  size_t new_sectors = bytes_to_sectors(new_length);

  for (size_t idx = 0; idx < DIRECT_MAX; idx++)
    if (!indirect_block_resize(0, &disk_inode->direct[idx], new_sectors - idx))
      goto cleanup;
  if (!indirect_block_resize(1, &disk_inode->indirect, new_sectors - DIRECT_MAX))
    goto cleanup;
  if (!indirect_block_resize(2, &disk_inode->doubly_indirect, new_sectors - INDIRECT_MAX))
    goto cleanup;

  disk_inode->length = new_length;
  return true;

cleanup:
  inode_disk_resize(disk_inode, disk_inode->length);
  return false;
}
