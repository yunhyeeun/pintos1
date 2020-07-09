#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/fat.h"
#include "threads/thread.h"

// /* On-disk inode. 
//  * Must be exactly DISK_SECTOR_SIZE bytes long. */
// struct inode_disk {
// 	disk_sector_t start;                /* First data sector. */
// 	off_t length;                       /* File size in bytes. */
//     bool isdir;
//     bool symlinkFlg;
//     disk_sector_t parent_dir;
// 	unsigned magic;                     /* Magic number. */
// 	uint32_t unused[123];
// };

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors (off_t size) {
	return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
// struct inode {
// 	struct list_elem elem;              /* Element in inode list. */
// 	disk_sector_t sector;               /* Sector number of disk location. */
// 	int open_cnt;                       /* Number of openers. */
// 	bool removed;                       /* True if deleted, false otherwise. */
// 	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
// 	struct inode_disk data;             /* Inode content. */
// };


/* Returns the disk sector that contains byte offset POS within
 * INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) {
	// ASSERT (inode != NULL);
    if (inode == NULL) {
        return -1;
    }
    #ifdef EFILESYS
        // struct inode *tmp_inode = calloc(1, sizeof *tmp_inode);
        // disk_read(filesys_disk, inode->sector, &tmp_inode->data);
        // if (get_symlinkFlg(tmp_inode)) {
        //     memcpy(inode, tmp_inode, sizeof (struct inode));
        //     free(tmp_inode);
        // }
        // else {
        //     free(tmp_inode);
        // }
        if (inode->issymlink == 1) {
        // if (get_symlinkFlg(tmp)) {
            struct inode *tmp_inode = calloc(1, sizeof *tmp_inode);
            memcpy(tmp_inode, inode, sizeof *tmp_inode);
            disk_read(filesys_disk, inode->sector, &tmp_inode->data);               
            memcpy(inode, tmp_inode, sizeof (struct inode));
            free(tmp_inode);
        }
    #endif
    // printf("byte to sector : %d\n", tmp_inode->data.start);
    cluster_t inode_clst = sector_to_cluster(inode->data.start);
    if (pos < inode->data.length) {
        cluster_t tmp = inode_clst;
        for(int i=0; i<pos/DISK_SECTOR_SIZE;i++) {
            tmp = fat_get(tmp);
        }
        return cluster_to_sector(tmp);
	}
	else
		return -1;
}
// static disk_sector_t
// byte_to_sector (const struct inode *inode, off_t pos) {
// 	ASSERT (inode != NULL);

//     cluster_t inode_clst = sector_to_cluster(inode->data.start);
//     if (pos < inode->data.length) {
//         cluster_t tmp = inode_clst;
//         for(int i=0; i<pos/DISK_SECTOR_SIZE;i++) {
//             tmp = fat_get(tmp);
//         }
//         return cluster_to_sector(tmp);
// 	}
// 	else
// 		return -1;
// }

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) {
	list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * disk.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length, bool isdir) {
	struct inode_disk *disk_inode = NULL;
	bool success = false;
	ASSERT (length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);
    // printf("inode create : %d %d\n", fat_fs->data_start, fat_fs->data_start+1);
	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		size_t sectors = bytes_to_sectors (length);
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;
        disk_inode->isdir = isdir;
        disk_inode->symlinkFlg = false;
        
		if(isdir) {
            // printf("inode create is directory!!!!!!\n");
            if(thread_current()-> curr_dir == NULL){
                disk_inode -> parent_dir = cluster_to_sector(ROOT_DIR_CLUSTER);
            } else {
                disk_inode -> parent_dir = inode_get_inumber(dir_get_inode(thread_current()->curr_dir));
            }
        }

		cluster_t checkSector = sector_to_cluster(sector);

        if(fat_get(checkSector) == 0 || checkSector == ROOT_DIR_CLUSTER) {
            // allocate 
            if(fat_get(checkSector) == 0 ) {
                fat_put(checkSector, EOChain);
            }
            // fat_create_chain(checkSector);
            int cnt = 0;

            cluster_t tmp = 0;
            for(int i=0;i<sectors;i++) {
                tmp = fat_create_chain(tmp);   
                if(tmp==0){
                    break;
                }
                if(i==0) {
                    disk_inode->start = cluster_to_sector(tmp);
                }
            }

            if(tmp == 0) {
                disk_inode->start = 0;
                if(sectors == 0) {
                    tmp = fat_create_chain(tmp);   
                    if(tmp == 0) {
                        // printf("disk is full\n");
                        free (disk_inode);
                        return false;
                    } else {
                        disk_inode -> start = cluster_to_sector(tmp);
                        // printf("[inode create] sectors are zero : %d\n", disk_inode -> start);
                        disk_write(filesys_disk, sector, disk_inode);
                        success = true;
                    }
                } else {
                    free(disk_inode);
                   return false;
                }
            } else {
                disk_write (filesys_disk, sector, disk_inode);
                if (sectors > 0) {
                    static char zeros[DISK_SECTOR_SIZE];
                    size_t i;

                    disk_sector_t disk_tmp = disk_inode->start;
                    for (i = 0; i < sectors; i++) {
                        if(disk_tmp > disk_size(filesys_disk)) {
                            free(disk_inode);
                            return false;
                        } 
                        disk_write (filesys_disk, disk_tmp, zeros); 
                        cluster_t tmp = fat_get(sector_to_cluster(disk_tmp));
                        disk_tmp = cluster_to_sector(tmp);
                    }
                }
                success = true;
            }
            
        } else {
            // printf("disk is full\n");
            free (disk_inode);
            return false;
        } 
		// }
        // printf("root dir data start : %d\n", disk_inode->start);
		free (disk_inode);

	}
    // printf("inode create : %d\n", success);
	return success;
}

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) {
	// printf("inode open function\n");
	struct list_elem *e;
	struct inode *inode;

	/* Check whether this inode is already open. */
	for (e = list_begin (&open_inodes); e != list_end (&open_inodes); e = list_next (e)) {
		inode = list_entry (e, struct inode, elem);
		if (inode->sector == sector) {
			inode_reopen (inode);
			return inode; 
		}
	}

	/* Allocate memory. */
	inode = malloc (sizeof *inode);
	if (inode == NULL)
		return NULL;

	/* Initialize. */
	list_push_front (&open_inodes, &inode->elem);
	inode->sector = sector;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;
	disk_read (filesys_disk, inode->sector, &inode->data);
    if (get_symlinkFlg(inode)) {
        inode->issymlink = 1;
    } else {
        inode->issymlink = 0;
    }
    // printf("[inode open] inode->sector : %d, inode->data.start : %d\n", inode->sector, inode->data.start);

	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode) {
	if (inode != NULL)
		inode->open_cnt++;
	return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode) {
	return inode->sector;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) {
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

    #ifdef EFILESYS
        if (inode->removed && inode_is_dir(inode)) {
			// free_map_release (inode->sector, 1);
			// free_map_release (inode->data.start,
            fat_remove_chain(sector_to_cluster(inode->sector), 0);
            if(!get_symlinkFlg(inode)) {
                fat_remove_chain(sector_to_cluster(inode->data.start), 0);
            }
		}
    #else

    // disk_write(filesys_disk, inode->sector, &inode->data);
	/* Release resources if this was the last opener. */
        if (--inode->open_cnt == 0) {
            /* Remove from inode list and release lock. */
            list_remove (&inode->elem);
            
            /* Deallocate blocks if removed. */
            if (inode->removed) {
                // free_map_release (inode->sector, 1);
                // free_map_release (inode->data.start,
                fat_remove_chain(sector_to_cluster(inode->sector), 0);
                if(!get_symlinkFlg(inode)) {
                    fat_remove_chain(sector_to_cluster(inode->data.start), 0);
                }
            }

            free (inode); 
        }
    #endif
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove (struct inode *inode) {
	ASSERT (inode != NULL);
	inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) {
	uint8_t *buffer = buffer_;
	off_t bytes_read = 0;
	uint8_t *bounce = NULL;

    // printf("[inode write at] inode sector no : %d\n", inode->sector);
    #ifdef EFILESYS
        // struct inode *tmp_inode = calloc(1, sizeof *tmp_inode);
        // disk_read(filesys_disk, inode->sector, &tmp_inode->data);
        // if (get_symlinkFlg(tmp_inode)) {
        //     // printf("[inode read at] symlink data start : %d\n", tmp_inode->data.start);
        //     memcpy(inode, tmp_inode, sizeof (struct inode));
        // }
        // free(tmp_inode);
        if (inode->issymlink == 1) {
        // if (get_symlinkFlg(tmp)) {
            struct inode *tmp_inode = calloc(1, sizeof *tmp_inode);
            memcpy(tmp_inode, inode, sizeof *tmp_inode);
            disk_read(filesys_disk, inode->sector, &tmp_inode->data);               
            memcpy(inode, tmp_inode, sizeof (struct inode));
            free(tmp_inode);
        }
    #endif
    // printf("inode read at : %d\n", inode_length(inode));
	while (size > 0) {
        // printf("inode read at : %d\n", size);
		/* Disk sector to read, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector (inode, offset);
		// printf("[inode reat_at] sector_idx : %x\n", sector_idx);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			/* Read full sector directly into caller's buffer. */
			disk_read (filesys_disk, sector_idx, buffer + bytes_read); 
		} else {
			/* Read sector into bounce buffer, then partially copy
			 * into caller's buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}
			disk_read (filesys_disk, sector_idx, bounce);
			memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_read += chunk_size;
	}
	free (bounce);
	return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
		off_t offset) {
	const uint8_t *buffer = buffer_;
	off_t bytes_written = 0;
	uint8_t *bounce = NULL;

    // printf("[inode write at] inode sector no : %d\n", inode->sector);
    #ifdef EFILESYS
        // struct inode *tmp_inode = calloc(1, sizeof *tmp_inode);
        // disk_read(filesys_disk, inode->sector, &tmp_inode->data);
        // if (get_symlinkFlg(tmp_inode)) {
        //     // printf("[inode write at] symlink data start : %d\n", tmp_inode->data.start);
        //     memcpy(inode, tmp_inode, sizeof (struct inode));
        //     free(tmp_inode);
        // } else{
        //     free(tmp_inode);
        // }
        if (inode->issymlink == 1) {
        // if (get_symlinkFlg(tmp)) {
            struct inode *tmp_inode = calloc(1, sizeof *tmp_inode);
            disk_read(filesys_disk, inode->sector, &tmp_inode->data);               
            memcpy(inode, tmp_inode, sizeof (struct inode));
            free(tmp_inode);
        }
    #endif
    // printf("inode write at : %d\n", inode->data.start);
	if (inode->deny_write_cnt) {
		return 0;
    }
    
    disk_sector_t sector_tmp = byte_to_sector (inode, offset + size -1);
    if(sector_tmp == -1) {
        inode->data.length = size + offset;
        int len = size + offset;
        cluster_t tmp= sector_to_cluster(inode->data.start);
		// printf("[inode write at] inode data.start : %d tmp : %x \n", inode->data.start, tmp);
        cluster_t prev;
        for(int i=0;i<len/DISK_SECTOR_SIZE;i++) {
            if(fat_get(tmp)==EOChain) {
                // printf("eochian\n");
                prev= tmp;
                tmp = fat_create_chain(tmp);
                if(tmp == 0) {
                    // fat_remove_chain(prev, 0);
                    inode->data.length = offset;
                    return 0;
                }
            } else {
                prev= tmp;
                tmp = fat_get(tmp);
                if(tmp == 0) {
                    // fat_remove_chain(prev, 0);
                    inode->data.length = offset;
                    return 0;
                }
            }
        }
        if(inode->sector > disk_size(filesys_disk)) {
            return false;
        } 
        disk_write(filesys_disk, inode->sector, &inode->data);
    }
    
    disk_sector_t sector_idx2 = byte_to_sector (inode, offset);
    // printf("inode write at sector idx : %d\n", sector_idx2);
	while (size > 0) {
		/* Sector to write, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector (inode, offset);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;
        

		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0) {
			break;
        } 

        if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
            /* Write full sector directly to disk. */
            // printf("[inode write at] write whole sector : %d\n", bytes_written);
            disk_write (filesys_disk, sector_idx, buffer + bytes_written); 
        } else {
            /* We need a bounce buffer. */
            if (bounce == NULL) {
                bounce = malloc (DISK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }

            /* If the sector contains data before or after the chunk
            we're writing, then we need to read in the sector
            first.  Otherwise we start with a sector of all zeros. */
            if (sector_ofs > 0 || chunk_size < sector_left) {
                disk_read (filesys_disk, sector_idx, bounce);
            }
            else
                memset (bounce, 0, DISK_SECTOR_SIZE);
            memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
            if(sector_idx> disk_size(filesys_disk)) {
                return false;
            } 
            disk_write (filesys_disk, sector_idx, bounce); 
        }
    
		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
	}
	free (bounce);

	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
	inode->deny_write_cnt++;
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) {
	ASSERT (inode->deny_write_cnt > 0);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode) {
	return inode->data.length;
}

bool
get_symlinkFlg (struct inode *inode) {
    return inode->data.symlinkFlg;
}

bool
inode_is_dir (struct inode *inode) {
    return inode->data.isdir;
}

disk_sector_t
inode_to_parent_sector (struct inode *inode) {
    return inode->data.parent_dir;
}

disk_sector_t
inode_to_data_start (struct inode *inode) {
    return inode->data.start;
}

bool
is_removed (struct inode *inode) {
    return inode->removed;
}
