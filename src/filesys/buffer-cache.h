#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include "filesys/inode.h"
#include "devices/block.h"

#define BUFFER_SIZE 64

/* Helper functions. */
void buffer_cache_init(void);
void buffer_cache_done(void);

void buffer_cache_read(block_sector_t sector, void* buffer, off_t size, off_t offset);
void buffer_cache_write(block_sector_t sector, const void* buffer, off_t size, off_t offset);

#endif /* filesys/buffer-cache.h */
