#include <debug.h>
#include <string.h>
#include "devices/block.h"
#include "devices/timer.h"
#include "filesys/buffer-cache.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

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

/* Lock for iterating over/evicting from cache. */
static struct lock cache_lock;

/* The filesystem buffer cache. */
static struct filesys_cache_entry buffer_cache[BUFFER_SIZE];

/* Helper functions. */

/* Flushes buffer cache entry at index i. */
static void flush_cache_entry(int i) {
  struct filesys_cache_entry* to_flush = &buffer_cache[i];
  block_write(fs_device, to_flush->sector, to_flush->contents);
  to_flush->modified = false;
}

/* Evicts buffer cache entry at index i and replaces it with
   new entry with new sector. */
static void replace_cache_entry(int i, block_sector_t sector) {
  // ASSERT(lock_held_by_current_thread(&cache_lock));

  struct filesys_cache_entry* to_replace = &buffer_cache[i];
  rw_lock_acquire(&to_replace->entry_lock, false);
  if (to_replace->valid && to_replace->modified)
    flush_cache_entry(i); // sets .modified to false
  to_replace->sector = sector;
  // lock_release(&cache_lock); // can't block on IO

  block_read(fs_device, sector, to_replace->contents);
  to_replace->valid = true;
  to_replace->last_used_tick = timer_ticks();
}

/* Evict least recently used cache block and replace it with newly needed sector. */
static struct filesys_cache_entry* add_cache_entry(block_sector_t sector) {
  // ASSERT(lock_held_by_current_thread(&cache_lock));

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
static struct filesys_cache_entry* search_cache(block_sector_t sector, bool reader) {
  // ASSERT(lock_held_by_current_thread(&cache_lock));

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
static struct filesys_cache_entry* ensure_cache_entry(block_sector_t sector, bool reader) {
  // lock_acquire(&cache_lock);
  struct filesys_cache_entry* out = search_cache(sector, reader);
  if (out != NULL) {
    // lock_release(&cache_lock);
    return out;
  }
  /* Cache entry not present, need to add it and check for the cache */
  out = add_cache_entry(sector);
  if (reader)
    rw_lock_downgrade(&out->entry_lock); // downgrade to reader lock
  return out;
}

/* Public functions. */

void buffer_cache_init() {
  lock_init(&cache_lock);
  for (int i = 0; i < BUFFER_SIZE; i++) {
    rw_lock_init(&buffer_cache[i].entry_lock);
  }
}

void buffer_cache_done() {
  // lock_acquire(&cache_lock);
  for (int i = 0; i < BUFFER_SIZE; i++)
    if (buffer_cache[i].valid)
      flush_cache_entry(i);
  // lock_release(&cache_lock);
}

/* Reads data from sector SECTOR on the file system into
   the given BUFFER, using the buffer cache.
   Synchronizes internally, so calls are thread-safe. */
void buffer_cache_read(block_sector_t sector, void* buffer, off_t size, off_t offset) {
  ASSERT(offset + size <= BLOCK_SECTOR_SIZE);

  struct filesys_cache_entry* entry = ensure_cache_entry(sector, false);
  memcpy(buffer, entry->contents + offset, size);
  entry->last_used_tick = timer_ticks();
  rw_lock_release(&entry->entry_lock, false);
}

/* Writes data from the given BUFFER into sector SECTOR on
   the file system, using the buffer cache.
   Synchronizes internally, so calls are thread-safe. */
void buffer_cache_write(block_sector_t sector, const void* buffer, off_t size, off_t offset) {
  ASSERT(offset + size <= BLOCK_SECTOR_SIZE);

  struct filesys_cache_entry* entry = ensure_cache_entry(sector, false);
  memcpy(entry->contents + offset, buffer, size);
  entry->modified = true;
  entry->last_used_tick = timer_ticks();
  rw_lock_release(&entry->entry_lock, false);
}
