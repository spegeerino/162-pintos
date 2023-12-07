#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "devices/block.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "devices/timer.h"
#include "devices/block.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Helper macros for inode computations. */
#define GET_NEEDED_INDIRECT_BLOCKS(NUM_SECTORS)                                                    \
  (NUM_SECTORS <= NUM_DIRECT_POINTERS                                                              \
       ? 0                                                                                         \
       : (NUM_SECTORS - NUM_DIRECT_POINTERS + INDIRECT_BLOCK_CAPACITY - 1) /                       \
             INDIRECT_BLOCK_CAPACITY)
#define GET_INDIRECT_BLOCK_INDEX(SECTOR_IDX)                                                       \
  ((SECTOR_IDX - NUM_DIRECT_POINTERS) / INDIRECT_BLOCK_CAPACITY)
#define GET_DIRECT_BLOCK_INDEX(NUM_SECTORS)                                                        \
  (NUM_SECTORS < NUM_DIRECT_POINTERS                                                               \
       ? NUM_SECTORS                                                                               \
       : (NUM_SECTORS - NUM_DIRECT_POINTERS) % INDIRECT_BLOCK_CAPACITY)

#define MAX(A, B) (((A) >= (B)) ? (A) : (B))
#define MIN(A, B) (((A) <= (B)) ? (A) : (B))
#define RELU_SUBTRACT(A, B) (((A) < (B)) ? 0 : ((A) - (B)))

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
/* Size of filesystem buffer cache. */
#define BUFFER_SIZE 64

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }
static void free_inode_sectors(struct inode_disk*, block_sector_t);
static bool allocate_inode_sectors(struct inode_disk*, size_t, size_t);

/* Cache entry for file data buffer. */
struct filesys_cache_entry {
  struct rw_lock entry_lock;           /* rwlock for writing to this entry */
  bool valid;                          /* whether this cache entry is valid */
  bool modified;                       /* whether this sector has been modified */
  block_sector_t sector;               /* which sector this entry is for (tag) */
  int64_t last_used_tick;              /* tick the sector was last used (LRU replacement)*/
  uint8_t contents[BLOCK_SECTOR_SIZE]; /* contents of the sector */
};

/* Lock for iterating over/evicting from cache. */
static struct lock cache_lock;

/* The filesystem buffer cache. */
static struct filesys_cache_entry buffer_cache[BUFFER_SIZE];

/* Helper functions. */
void flush_cache_entry(int);
void replace_cache_entry(int, block_sector_t);
struct filesys_cache_entry* add_cache_entry(block_sector_t);
struct filesys_cache_entry* search_cache(block_sector_t, bool);
struct filesys_cache_entry* ensure_cache_entry(block_sector_t, bool);

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  struct inode_disk inode_disk;
  block_read(fs_device, inode->sector, &inode_disk);
  if (pos < inode_disk.length) {
    off_t block_idx = pos / BLOCK_SECTOR_SIZE;
    if (block_idx < NUM_DIRECT_POINTERS) {
      if (inode_disk.direct[block_idx] == 0)
        return -1;
      return inode_disk.direct[block_idx];
    } else {
      off_t indirect_block_idx = GET_INDIRECT_BLOCK_INDEX(block_idx);
      if (indirect_block_idx >= NUM_INDIRECT_POINTERS ||
          inode_disk.indirect[indirect_block_idx] == 0) {
        return -1;
      }

      struct indirect_block indirect_block;
      block_read(fs_device, inode_disk.indirect[indirect_block_idx], &indirect_block);

      return indirect_block.sector_arr[GET_DIRECT_BLOCK_INDEX(block_idx)];
    }
  } else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct lock open_inodes_lock;
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  lock_init(&open_inodes_lock);
  lock_init(&cache_lock);
  for (int i = 0; i < BUFFER_SIZE; i++) {
    rw_lock_init(&buffer_cache[i].entry_lock);
  }
}

/* Frees all resources in the inode module. */
void inode_done(void) {
  lock_acquire(&cache_lock);
  for (int i = 0; i < BUFFER_SIZE; i++)
    if (buffer_cache[i].valid)
      flush_cache_entry(i);
  lock_release(&cache_lock);
}

/* Flushes buffer cache entry at index i. */
void flush_cache_entry(int i) {
  struct filesys_cache_entry* to_flush = &buffer_cache[i];
  block_write(fs_device, to_flush->sector, to_flush->contents);
  to_flush->modified = false;
}

/* Evicts buffer cache entry at index i and replaces it with
   new entry with new sector. */
void replace_cache_entry(int i, block_sector_t sector) {
  ASSERT(lock_held_by_current_thread(&cache_lock));

  struct filesys_cache_entry* to_replace = &buffer_cache[i];
  rw_lock_acquire(&to_replace->entry_lock, false);
  if (to_replace->valid && to_replace->modified)
    flush_cache_entry(i); // sets .modified to false
  to_replace->sector = sector;
  lock_release(&cache_lock); // can't block on IO

  block_read(fs_device, sector, to_replace->contents);
  to_replace->valid = true;
  to_replace->last_used_tick = timer_ticks();
}

/* Evict least recently used cache block and replace it with newly needed sector. */
struct filesys_cache_entry* add_cache_entry(block_sector_t sector) {
  ASSERT(lock_held_by_current_thread(&cache_lock));

  int to_evict_idx = 0;
  for (int i = 1; i < BUFFER_SIZE; i++) {
    if (!buffer_cache[i].valid) {
      to_evict_idx = i;
      break;
    }
    if (buffer_cache[i].last_used_tick < buffer_cache[to_evict_idx].last_used_tick) {
      to_evict_idx = i;
    }
  }
  replace_cache_entry(to_evict_idx, sector); // releases cache lock
  return &buffer_cache[to_evict_idx];
}

/* Searches through cache to see if given sector is present.
   This function must be called with the cache lock held
   to prevent race conditions.
*/
struct filesys_cache_entry* search_cache(block_sector_t sector, bool reader) {
  ASSERT(lock_held_by_current_thread(&cache_lock));

  for (int i = 0; i < BUFFER_SIZE; i++) {
    if (buffer_cache[i].valid && sector == buffer_cache[i].sector) {
      rw_lock_acquire(&buffer_cache[i].entry_lock, reader);
      return &buffer_cache[i];
    }
  }
  return NULL;
}

/* Ensures that the cache has the desired sector in the cache,
   then acquires the entry lock for that entry.
   It does this by either finding the entry already present in the cache,
   or evicting something else from cache and writing the desired sector to the cache
   from disk.
   */
struct filesys_cache_entry* ensure_cache_entry(block_sector_t sector, bool reader) {
  lock_acquire(&cache_lock);
  struct filesys_cache_entry* out = search_cache(sector, reader);
  if (out != NULL) {
    lock_release(&cache_lock);
    return out;
  }
  /* Cache entry not present, need to add it and check for the cache */
  out = add_cache_entry(sector);
  if (reader)
    rw_lock_downgrade(&out->entry_lock); // downgrade to reader lock
  return out;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, enum inode_type type) {
  struct inode_disk* disk_inode = NULL;
  bool success = true;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    if (GET_NEEDED_INDIRECT_BLOCKS(sectors) > NUM_INDIRECT_POINTERS) {
      free(disk_inode);
      return false;
    }
    disk_inode->length = length;
    disk_inode->type = type;
    disk_inode->magic = INODE_MAGIC;

    if ((success &= allocate_inode_sectors(disk_inode, 0, sectors))) {
      /* write inode to disk and return. */
      block_write(fs_device, sector, disk_inode);
      free(disk_inode);
    } else {
      free_inode_sectors(disk_inode, 0);
      free(disk_inode);
    }

    return success;
  }
  return false;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  lock_acquire(&open_inodes_lock);
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      lock_release(&open_inodes_lock);
      return inode;
    }
  }

  struct inode_disk* disk = malloc(sizeof *disk);
  if (disk == NULL) {
    lock_release(&open_inodes_lock);
    return NULL;
  }
  block_read(fs_device, sector, disk);

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL) {
    lock_release(&open_inodes_lock);
    return NULL;
  }

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);

  lock_init(&inode->lock);
  inode->type = disk->type;
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_release(&open_inodes_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode == NULL)
    return NULL;
  lock_acquire(&inode->lock);
  inode->open_cnt++;
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
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      /* we avoid using malloc as handling memory allocation errors here is nontrivial */
      struct inode_disk disk_inode;
      memset(&disk_inode, 0, sizeof(struct inode_disk));
      block_read(fs_device, inode->sector, &disk_inode);
      free_inode_sectors(&disk_inode, 0);
      free_map_release(inode->sector, 1);
    }
    free(inode);
    return;
  }
  lock_release(&inode->lock);
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
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  struct inode_disk* disk_inode = calloc(1, BLOCK_SECTOR_SIZE);
  if (disk_inode == NULL) {
    return 0;
  }
  block_read(fs_device, inode->sector, disk_inode);

  block_sector_t sector = byte_to_sector(inode, offset);
  if (sector == (uint32_t)-1) {
    // inode does not contain data for a block at offset offset
    return 0;
  }
  struct filesys_cache_entry* to_read_from = ensure_cache_entry(sector, true);
  /* Now guaranteed to have a valid cache entry at to_read_from while holding
     the rw_lock as a reader. */
  uint8_t* buffer = buffer_;
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
    memcpy(buffer + bytes_read, to_read_from->contents + sector_ofs, chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
    to_read_from->last_used_tick = timer_ticks();

    /* Update cache if new sector required. */
    if (size > 0 && inode_left > chunk_size) { // chunk_size == sector_left and more to write
      block_sector_t next_sector = byte_to_sector(inode, offset);
      if (next_sector == (uint32_t)-1)
        break;
      rw_lock_release(&to_read_from->entry_lock, true);
      to_read_from = ensure_cache_entry(next_sector, true);
    }
  }

  free(disk_inode);
  rw_lock_release(&to_read_from->entry_lock, true);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  struct inode_disk* disk_inode = calloc(1, BLOCK_SECTOR_SIZE);
  if (disk_inode == NULL) {
    return 0;
  }
  block_read(fs_device, inode->sector, disk_inode);
  if (offset + size > disk_inode->length) {
    size_t new_num_sectors = bytes_to_sectors(offset + size);
    size_t old_num_sectors = bytes_to_sectors(disk_inode->length);
    if (!allocate_inode_sectors(disk_inode, old_num_sectors, new_num_sectors)) {
      free_inode_sectors(disk_inode, old_num_sectors);
      free(disk_inode);
      return 0;
    }
    disk_inode->length = offset + size;
    block_write(fs_device, inode->sector, disk_inode);
  }

  /* Check cache for desired entry. */
  block_sector_t sector = byte_to_sector(inode, offset);
  if (sector == (uint32_t)-1) {
    return 0;
  }
  struct filesys_cache_entry* to_write_to = ensure_cache_entry(sector, false);

  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt) {
    rw_lock_release(&to_write_to->entry_lock, false);
    return 0;
  }

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = disk_inode->length - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    to_write_to->modified = true;

    /* Copy bytes from buffer. */
    memcpy(to_write_to->contents + sector_ofs, buffer + bytes_written, chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
    to_write_to->last_used_tick = timer_ticks();

    /* Update cache if new sector required. */
    if (size > 0 && inode_left > chunk_size) { // sector_left = chunk_size and we have more to write
      block_sector_t next_sector = byte_to_sector(inode, offset);
      if (next_sector == (uint32_t)-1)
        break;
      rw_lock_release(&to_write_to->entry_lock, false);
      to_write_to = ensure_cache_entry(next_sector, false);
    }
  }

  rw_lock_release(&to_write_to->entry_lock, false);
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

static void free_inode_sectors(struct inode_disk* disk_inode, size_t start_sector_idx) {
  for (size_t i = start_sector_idx; i < NUM_DIRECT_POINTERS; ++i) {
    if (!disk_inode->direct[i]) {
      return;
    } else {
      free_map_release(disk_inode->direct[i], 1);
      disk_inode->direct[i] = 0;
    }
  }

  for (size_t i = RELU_SUBTRACT(GET_NEEDED_INDIRECT_BLOCKS(start_sector_idx + 1), 1);
       i < INDIRECT_BLOCK_CAPACITY; ++i) {
    if (!disk_inode->indirect[i]) {
      return;
    } else {
      struct indirect_block this_indirect_block;
      memset(&this_indirect_block, 0, sizeof(struct indirect_block));
      block_read(fs_device, disk_inode->indirect[i], &this_indirect_block);
      for (size_t j =
               RELU_SUBTRACT(start_sector_idx, NUM_DIRECT_POINTERS + i * INDIRECT_BLOCK_CAPACITY);
           j < INDIRECT_BLOCK_CAPACITY; ++j) {
        if (!this_indirect_block.sector_arr[j]) {
          free_map_release(disk_inode->indirect[i], 1);
          return;
        } else {
          free_map_release(this_indirect_block.sector_arr[i], 1);
        }
      }
      free_map_release(disk_inode->indirect[i], 1);
    }
  }
}

static bool allocate_inode_sectors(struct inode_disk* disk_inode, size_t start_sector_idx,
                                   size_t end_sector_idx) {
  bool success = true;
  /* start creating and zero-filling first-level data blocks*/
  static char zeros[BLOCK_SECTOR_SIZE];
  for (size_t i = start_sector_idx; success && i < end_sector_idx && i < NUM_DIRECT_POINTERS; ++i) {
    ASSERT(disk_inode->direct[i] == 0);
    if ((success &= free_map_allocate(1, &disk_inode->direct[i]))) {
      block_write(fs_device, disk_inode->direct[i], &zeros);
    }
  }

  for (size_t i = RELU_SUBTRACT(GET_NEEDED_INDIRECT_BLOCKS(start_sector_idx), 1);
       success && i < GET_NEEDED_INDIRECT_BLOCKS(end_sector_idx); ++i) {
    struct indirect_block* this_indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
    if (this_indirect_block == NULL) {
      success = false;
      break;
    }
    if (disk_inode->indirect[i] == 0) {
      success &= free_map_allocate(1, &disk_inode->indirect[i]);
      if (!success) {
        free(this_indirect_block);
        break;
      }
    } else {
      block_read(fs_device, disk_inode->indirect[i], this_indirect_block);
    }
    for (size_t j =
             RELU_SUBTRACT(start_sector_idx, NUM_DIRECT_POINTERS + i * INDIRECT_BLOCK_CAPACITY);
         j < MIN(INDIRECT_BLOCK_CAPACITY,
                 RELU_SUBTRACT(end_sector_idx, NUM_DIRECT_POINTERS + i * INDIRECT_BLOCK_CAPACITY));
         ++j) {

      ASSERT(this_indirect_block->sector_arr[j] == 0);
      if ((success &= free_map_allocate(1, &this_indirect_block->sector_arr[j]))) {
        block_write(fs_device, this_indirect_block->sector_arr[j], &zeros);
      }
    }

    if (!success) {
      if (this_indirect_block != NULL)
        free(this_indirect_block);
      break;
    }

    ASSERT(this_indirect_block != NULL);
    block_write(fs_device, disk_inode->indirect[i], this_indirect_block);
  }
  return success;
}
