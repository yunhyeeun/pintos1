#include "filesys/fat.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

struct fat_fs *fat_fs;

void fat_boot_create (void);
void fat_fs_init (void);
cluster_t fat_find_empty (void);

void
fat_init (void) {
	fat_fs = calloc (1, sizeof (struct fat_fs));
	if (fat_fs == NULL)
		PANIC ("FAT init failed");

	// Read boot sector from the disk
	unsigned int *bounce = malloc (DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC ("FAT init failed");
	disk_read (filesys_disk, FAT_BOOT_SECTOR, bounce);
	memcpy (&fat_fs->bs, bounce, sizeof (fat_fs->bs));
	free (bounce);

	// Extract FAT info
	if (fat_fs->bs.magic != FAT_MAGIC)
		fat_boot_create ();
	fat_fs_init ();
}

void
fat_open (void) {
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT load failed");

	// Load FAT directly from the disk
	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	off_t bytes_read = 0;
	off_t bytes_left = sizeof (fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		bytes_left = fat_size_in_bytes - bytes_read;
		if (bytes_left >= DISK_SECTOR_SIZE) {
			disk_read (filesys_disk, fat_fs->bs.fat_start + i,
			           buffer + bytes_read);
			bytes_read += DISK_SECTOR_SIZE;
		} else {
			uint8_t *bounce = malloc (DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC ("FAT load failed");
			disk_read (filesys_disk, fat_fs->bs.fat_start + i, bounce);
			memcpy (buffer + bytes_read, bounce, bytes_left);
			bytes_read += bytes_left;
			free (bounce);
		}
	}
}

void
fat_close (void) {
	// Write FAT boot sector
    // printf("[fat close function]\n");
	uint8_t *bounce = calloc (1, DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC ("FAT close failed");
	memcpy (bounce, &fat_fs->bs, sizeof (fat_fs->bs));
	disk_write (filesys_disk, FAT_BOOT_SECTOR, bounce);
	free (bounce);

	// Write FAT directly to the disk
	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	off_t bytes_wrote = 0;
	off_t bytes_left = sizeof (fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		bytes_left = fat_size_in_bytes - bytes_wrote;
		if (bytes_left >= DISK_SECTOR_SIZE) {
			disk_write (filesys_disk, fat_fs->bs.fat_start + i,
			            buffer + bytes_wrote);
			bytes_wrote += DISK_SECTOR_SIZE;
		} else {
			bounce = calloc (1, DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC ("FAT close failed");
			memcpy (bounce, buffer + bytes_wrote, bytes_left);
			disk_write (filesys_disk, fat_fs->bs.fat_start + i, bounce);
			bytes_wrote += bytes_left;
			free (bounce);
		}
	}
}

void
fat_create (void) {
	// Create FAT boot
	fat_boot_create ();
	fat_fs_init ();

	// Create FAT table
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT creation failed");

	// Set up ROOT_DIR_CLST
	fat_put (ROOT_DIR_CLUSTER, EOChain);

	// Fill up ROOT_DIR_CLUSTER region with 0
	uint8_t *buf = calloc (1, DISK_SECTOR_SIZE);
	if (buf == NULL)
		PANIC ("FAT create failed due to OOM");
	disk_write (filesys_disk, cluster_to_sector (ROOT_DIR_CLUSTER), buf);
	free (buf);
}

void
fat_boot_create (void) {
	unsigned int fat_sectors =
	    (disk_size (filesys_disk) - 1)
	    / (DISK_SECTOR_SIZE / sizeof (cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
	fat_fs->bs = (struct fat_boot){
	    .magic = FAT_MAGIC,
	    .sectors_per_cluster = SECTORS_PER_CLUSTER,
	    .total_sectors = disk_size (filesys_disk),
	    .fat_start = 1,
	    .fat_sectors = fat_sectors,
	    .root_dir_cluster = ROOT_DIR_CLUSTER,
	};
}

void
fat_fs_init (void) {
	/* TODO: Your code goes here. */
    fat_fs->fat_length = (fat_fs->bs.fat_sectors)*(DISK_SECTOR_SIZE/sizeof(cluster_t));
    fat_fs->data_start = fat_fs->bs.fat_start + fat_fs->bs.fat_sectors;
    fat_fs->last_clst = fat_fs->bs.fat_start;
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. */
cluster_t
fat_create_chain (cluster_t clst) {
	/* TODO: Your code goes here. */
    //find a empty cluster in fat
    cluster_t empty_clst = fat_find_empty();
    if(empty_clst == 0) {
        return 0;
    }

    fat_fs->last_clst = empty_clst;

    if(clst == 0) {
        //allocate new chain
        fat_put(empty_clst, EOChain);

    } else {
        fat_put(clst, empty_clst);
        fat_put(empty_clst, EOChain);
    }

    return empty_clst;

}

/* Remove the chain of clusters starting from CLST.
 * If PCLST is 0, assume CLST as the start of the chain. */
void
fat_remove_chain (cluster_t clst, cluster_t pclst) {
	/* TODO: Your code goes here. */
    // printf("fat_remove chain : %d\n", clst);
    cluster_t tmp = clst;
    while(*(fat_fs->fat + tmp -1) != EOChain) {
        cluster_t next = *(fat_fs->fat + tmp -1);
        fat_put(tmp, 0);
        tmp = next;
        if(tmp == 0) {
            break;
        }
    }
    fat_put(tmp, 0);

    //if plsct == 0, it removes all the chain and 0 means boot sector
    if(pclst != 0) { 
        fat_put(pclst, EOChain);
    }
}

/* Update a value in the FAT table. */
void
fat_put (cluster_t clst, cluster_t val) {
	/* TODO: Your code goes here. */
    unsigned int* fat = fat_fs->fat;
    *(fat+clst-1) = val;
}

/* Fetch a value in the FAT table. */
cluster_t
fat_get (cluster_t clst) {
	/* TODO: Your code goes here. */
    return *(fat_fs->fat + clst -1);
}

cluster_t
fat_find_empty (void) {

    // printf("fat find empty : %d\n", fat_fs->fat_length);
    int empty_clst = -1;
    for(int i=fat_fs->last_clst;i<fat_fs->fat_length;i++) {
    // for(int i=fat_fs->last_clst;i<fat_fs->fat_length;i++) {
        //0 : boot sector, 1 : root dir sec
        if(*(fat_fs -> fat + i -1) == 0) {
            empty_clst = i;
            break;
        }
    }

    if(empty_clst == -1) {
        for(int i=2;i<fat_fs->last_clst;i++) {
            if(*(fat_fs -> fat + i -1) == 0) {
                empty_clst = i;
                break;
            }
        }
    }

    if(empty_clst == -1) {
        return 0;
    }
    return empty_clst;
}

/* Covert a cluster # to a sector number. */
disk_sector_t
cluster_to_sector (cluster_t clst) {
	/* TODO: Your code goes here. */
    if(clst == 1) {return fat_fs->data_start;}
    return fat_fs->data_start + clst + 1;
}

/* Covert a sector number to a cluster #. */
cluster_t
sector_to_cluster (disk_sector_t disk_sec) {
	/* TODO: Your code goes here. */
    if(disk_sec == fat_fs->data_start) {return 1;}
    return disk_sec - fat_fs->data_start -1;
}
