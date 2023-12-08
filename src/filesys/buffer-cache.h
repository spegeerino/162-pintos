#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include "filesys/inode.h"
#include "devices/block.h"

#define BUFFER_SIZE 64

/* Cache entry for file data buffer. */
struct filesys_cache_entry {
  struct rw_lock entry_lock;           /* rwlock for writing to this entry */
  bool valid;                          /* whether this cache entry is valid */
  bool modified;                       /* whether this sector has been modified */
  block_sector_t sector;               /* which sector this entry is for (tag) */
  int64_t last_used_tick;              /* tick the sector was last used (LRU replacement)*/
  uint8_t contents[BLOCK_SECTOR_SIZE]; /* contents of the sector */
};

/* Helper functions. */
void buffer_cache_init(void);
void buffer_cache_done(void);

void buffer_cache_read(block_sector_t sector, void* buffer, off_t size, off_t offset);
void buffer_cache_write(block_sector_t sector, const void* buffer, off_t size, off_t offset);

void flush_cache_entry(int i);
void replace_cache_entry(int i, block_sector_t sector);
struct filesys_cache_entry* add_cache_entry(block_sector_t sector);
struct filesys_cache_entry* search_cache(block_sector_t sector, bool reader);
struct filesys_cache_entry* ensure_cache_entry(block_sector_t sector, bool reader);

#endif /* filesys/buffer-cache.h */
