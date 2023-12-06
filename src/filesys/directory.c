#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

// FIXME: This can be removed when extensible files are implemented.
#define DIR_MAX_ENTRIES 16

/* A directory. */
struct dir {
  struct inode* inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create(block_sector_t sector, block_sector_t parent_sector) {
  if (!inode_create(sector, DIR_MAX_ENTRIES * sizeof(struct dir_entry), DIRECTORY))
    return false;

  struct inode* inode = inode_open(sector);
  if (inode == NULL)
    goto cleanup;
  struct dir* dir = dir_open(inode);
  if (dir == NULL)
    goto cleanup;

  dir_add(dir, ".", sector);
  dir_add(dir, "..", parent_sector);
  return true;

cleanup:
  // FIXME:
  // We need to remove the disk allocated for the inode in the case
  // that disk allocation succeeds but the inode_open fails.
  // However, I'm not sure how to do this, since you need to inode_open
  // an inode to remove it.
  // Maybe push it into a list of inodes to be removed later?
  // But lists probably require allocation too lol.
  return false;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir* dir_open(struct inode* inode) {
  struct dir* dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL && inode->data.type == DIRECTORY) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir* dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir* dir_reopen(struct dir* dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir* dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode* dir_get_inode(struct dir* dir) {
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir* dir, const char* name, struct inode** inode) {
  struct dir_entry e;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (lookup(dir, name, &e, NULL))
    *inode = inode_open(e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Resolves the given PATH starting at DIR to a file
   and returns true if successful, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_resolve(struct dir* dir, const char* _path, struct inode** inode) {
  autofree char* path = strdup(_path);
  char* saveptr;

  /* Start at the root by default, or for absolute paths. */
  if (dir == NULL || path[0] == '/') {
    *inode = inode_open(ROOT_DIR_SECTOR);
  } else {
    *inode = inode_reopen(dir->inode);
  }

  /* If inode_(re)open failed */
  if (dir == NULL)
    return NULL;

  /* Iterate through each component of the path. We must be
     careful to make sure we close all intermediate inodes. */
  for (char* s = strtok_r(path, "/", &saveptr); s != NULL; s = strtok_r(NULL, "/", &saveptr)) {
    dir = dir_open(*inode);
    if (dir == NULL || !dir_lookup(dir, s, inode))
      goto cleanup;
    dir_close(dir);
  }

  return true;

cleanup:
  dir_close(dir);
  *inode = NULL;
  return false;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add(struct dir* dir, const char* name, block_sector_t inode_sector) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup(dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir* dir, const char* name) {
  struct dir_entry e;
  struct inode* inode = NULL;
  off_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Find directory entry. */
  if (!lookup(dir, name, &e, &ofs))
    return false;

  /* Open inode. */
  inode = inode_open(e.inode_sector);
  if (inode == NULL)
    return false;

  /* Make sure directories are empty */
  if (inode->data.type == DIRECTORY) {
    struct dir* child_dir = dir_open(inode);

    char name[NAME_MAX + 1];
    while (dir_readdir(child_dir, name)) {
      if (strcmp(name, ".") != 0 || strcmp(name, "..") != 0)
        continue;

      /* Fail if there is still an entry that is not . or .. */
      dir_close(child_dir);
      return false;
    }
  }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e) {
    inode_close(inode);
    return false;
  }

  /* Remove inode. */
  inode_remove(inode);
  inode_close(inode);

  return true;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir(struct dir* dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;

  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    if (e.in_use) {
      strlcpy(name, e.name, NAME_MAX + 1);
      return true;
    }
  }
  return false;
}
