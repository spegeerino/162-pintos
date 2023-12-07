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
#define BUFFER_SIZE 64
#define MAX(A, B) (A >= B ? A : B)
#define MIN(A, B) (A <= B ? A : B)

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }
static bool inode_disk_resize(struct inode_disk*, off_t);

static block_sector_t indirect_block_lookup(block_sector_t indirect_sector, size_t index) {
  if (indirect_sector == 0)
    return 0;
  indirect_block_t indirect_block;
  block_read(fs_device, indirect_sector, &indirect_block);
  return indirect_block[index];
}

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

  if (pos >= inode_disk.length)
    return -1;
  return inode_disk_get_sector(&inode_disk, pos / BLOCK_SECTOR_SIZE);
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
  ASSERT(length >= 0);
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof(struct inode_disk) == BLOCK_SECTOR_SIZE);

  size_t sectors = bytes_to_sectors(length);
  if (sectors >= DOUBLY_INDIRECT_MAX)
    return false;

  /* Initialize disk_inode */
  autofree struct inode_disk* disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode == NULL)
    return false;
  disk_inode->type = type;
  disk_inode->length = 0;
  disk_inode->magic = INODE_MAGIC;

  if (!inode_disk_resize(disk_inode, length))
    return false;

  block_write(fs_device, sector, disk_inode);
  return true;
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

  autofree struct inode_disk* disk = malloc(sizeof *disk);
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
      inode_disk_resize(&disk_inode, 0);
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
  /* Read inode from disk */
  autofree struct inode_disk* disk_inode = malloc(sizeof *disk_inode);
  if (disk_inode == NULL)
    return 0;
  block_read(fs_device, inode->sector, disk_inode);

  block_sector_t sector = byte_to_sector(inode, offset);
  if (sector == (uint32_t)-1)
    return 0;
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

  rw_lock_release(&to_read_from->entry_lock, true);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  if (inode->deny_write_cnt)
    return 0;

  /* Read inode from disk */
  autofree struct inode_disk* disk_inode = malloc(sizeof *disk_inode);
  if (disk_inode == NULL)
    return 0;
  block_read(fs_device, inode->sector, disk_inode);

  /* In case we need to grow the inode */
  if (offset + size > disk_inode->length) {
    if (!inode_disk_resize(disk_inode, offset + size))
      return 0;
    block_write(fs_device, inode->sector, disk_inode);
  }

  /* Check cache for desired entry. */
  block_sector_t sector = byte_to_sector(inode, offset);
  if (sector == (uint32_t)-1)
    return 0;
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
    int min_left = MIN(inode_left, sector_left);

    /* Number of bytes to actually write into this sector. */
    int chunk_size = MIN(size, min_left);
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
  block_sector_t block[INDIRECT_CAPACITY];
  if (*sector == 0) {
    if (!free_map_allocate(1, sector))
      return false;
    memset(block, 0, BLOCK_SECTOR_SIZE);
    // printf("Allocating %d\n", *sector);
  } else {
    // printf("Reading %d\n", *sector);
    block_read(fs_device, *sector, &block);
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
    // printf("Freeing %d\n", *sector);
    free_map_release(*sector, 1);
    *sector = (block_sector_t)0;
  } else {
    // printf("Writing %d\n", *sector);
    block_write(fs_device, *sector, &block);
  }

  return true;
}

static bool inode_disk_resize(struct inode_disk* disk_inode, off_t new_length) {
  // printf("\n\n\n\n========\nResizing to %d\n", new_length);
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
