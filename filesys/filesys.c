#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "filesys/fat.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);
struct dir *parse_path(char *path_name, char *file_name);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();
#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();
#else
	/* Original FS */
	// free_map_init ();

	if (format)
		do_format ();

	// free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	// free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
    cluster_t empty = fat_find_empty();
    if(empty == 0) {
        return false;
    }
    disk_sector_t inode_sector = cluster_to_sector(empty);
    char *path = malloc(strlen(name) + 1);
    memcpy(path, name, strlen(name) + 1);
    char *file_name = calloc(1, strlen(name) + 1);
    struct dir *dir = parse_path(path, file_name);

    if (strlen(file_name) == 0) {
        // printf("filename is null\n");
        dir_close(dir);
        free(file_name);
        return false;
    }

	bool success = (dir != NULL 
            && file_name != NULL
			&& inode_create (inode_sector, initial_size, 0)
			&& dir_add (dir, file_name, inode_sector));
	if (!success && inode_sector != 0) {
        fat_remove_chain(empty, 0);
    }
	dir_close (dir);
    free(path);
	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
    char *path = malloc(strlen(name) + 1);
    memcpy(path, name, strlen(name) + 1);
    
    char *file_name = calloc(1, strlen(name) + 1);
    struct dir *dir = parse_path(path, file_name);
    if (strlen(file_name) == 0 || file_name == NULL) {
        if(!strcmp((const char *)path, "/") && strlen(path) == 1) {
            free(file_name);
            return file_open(inode_open(fat_fs->data_start + 1));
        }
        dir_close(dir);
        free(file_name);
        return NULL;
    }
  
	struct inode *inode = NULL;

	if (dir != NULL)
		dir_lookup (dir, file_name, &inode);
    
	dir_close (dir);
    free(path);
	return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
    char *path = malloc(strlen(name) + 1);
    memcpy(path, name, strlen(name) + 1);
    char *file_name = calloc(1, strlen(name) + 1);
    struct dir *dir = parse_path(path, file_name);

    if (strlen(file_name) == 0) {
        // printf("filename is null\n");
        dir_close(dir);
        free(file_name);
        return false;
    }
	// bool success = dir != NULL && dir_remove (dir, name);
	bool success = dir != NULL && file_name != NULL && dir_remove (dir, file_name);
	dir_close (dir);
    free(file_name);
	return success;
}

struct dir *parse_path (char *path_name, char *file_name) {
    // printf("parse path function : %s\n", path_name);
    if(path_name == NULL || file_name == NULL) {
        syscall_exit(-1);
    }
    if(strlen(path_name) == 0){
        return NULL;
    } 

    char *token;
    char *save_ptr;
    struct dir *dir;
    char *path = malloc(strlen(path_name) + 1);
    memcpy(path, path_name, strlen(path_name) + 1);
    if(path_name == '/') {
        
        dir = dir_open(inode_open(fat_fs->data_start + 1));
        if (is_removed(dir_get_inode(dir))){
            free(path);
            dir_close(dir);
            return NULL;
        }
        return dir;
    }

    if(path_name[0] == '/') {
        //absolute
        dir = dir_open(inode_open(fat_fs->data_start + 1));
    } else {
        if(thread_current() -> curr_dir == NULL) {
            dir = dir_open(inode_open(fat_fs->data_start + 1));
            // printf("root directory : %d\n", inode_to_sector( dir_get_inode(dir)));
        } else {
            dir = dir_reopen(thread_current()->curr_dir);
            // printf("existing direc : %d\n", inode_to_sector(dir_get_inode(dir)));
        }
    }

    token = strtok_r(path, "/", &save_ptr); 
    // printf("parse path : %s\n", token);
    while(token!=NULL){
        // printf("token : %s\n", token);
        struct inode *inode = calloc(1, sizeof(struct inode *));
        if(token == '..') {
            inode = inode_open(inode_to_parent_sector(dir_get_inode(dir)));
            struct dir *parent_dir = dir_open(inode);
            if(parent_dir == NULL) {
                dir_close(dir);
                free(path);
                return NULL;
            }
            dir_close(dir);
            dir = parent_dir;
            token = strtok_r(NULL, "/", &save_ptr);
        } else if (token == '.') {
            dir_close(dir);
            token = strtok_r(NULL, "/", &save_ptr);
        } else {
            if(dir_lookup(dir, token, &inode)) {
                if(inode_is_dir(inode)) {
                    //subdirectory
                    // printf("[parse path] subdir\n");
                    struct dir* next = dir_open(inode);
                    
                    if(next == NULL) {
                        // printf("next dir is null\n");
                        free(path);
                        dir_close(dir);
                        return NULL;
                    }
                    // printf("next dir inode sector : %d\n", inode_to_sector(dir_get_inode(dir)));
                    
                    memset(file_name, 0, strlen(file_name));
                    memcpy(file_name, token, strlen(token)+1);
                    token = strtok_r(NULL, "/", &save_ptr);  
                    if(token == NULL) {
                        // printf("next token is null : %d %s\n", inode_to_sector(dir_get_inode(dir)), file_name);
                        // dir_close(next);
                        free(path);
                        if (is_removed(dir_get_inode(dir))){
                            dir_close(dir);
                            return NULL;
                        }
                        return dir;
                    } else {
                        // printf("token not null : %d\n", inode_to_sector(dir_get_inode(dir)));
                        dir_close(dir); 
                        dir = next;
                    }
                    // printf("next dir inode sector : %d\n", inode_to_sector(inode));
                } else {
                    // printf("[parse path] file\n");
                    if(strlen(token) > 14){ // file length must be lower than 14
                        free(path);
                        // file_name = NULL;
                        return NULL;
                    }
                    memcpy(file_name, token, strlen(token)+1);
                    token = strtok_r(NULL, "/", &save_ptr);  
                }
            } else {
                char *next_ptr = strtok_r(NULL, "/", &save_ptr);  
                // printf("look up fail\n");
                if(next_ptr == NULL) {
                    if(strlen(token) > 14){ // file length must be lower than 14
                        // printf("file name is long\n");
                        free(path);
                        // file_name = NULL;
                        return NULL;
                    }
                    memcpy(file_name, token, strlen(token)+1);
                    // printf("file name : %s\n", file_name);
                    free(path);
                    if (is_removed(dir_get_inode(dir))){
                        dir_close(dir);
                        return NULL;
                    }
                    return dir;
                }
                dir_close(dir);
                free(path);
                return NULL;
            }
        }  
    }   
    if (is_removed(dir_get_inode(dir))){
        dir_close(dir);
        free(path);
        return NULL;
    }

    free(path);
    return dir;
}

/* create new directory in file system */
bool
filesys_create_dir (const char *name) {
    // printf("filesys create dir : %s\n", name);
    cluster_t empty = fat_find_empty();
    if(empty == 0) {
        return false;
    }
    disk_sector_t inode_sector = cluster_to_sector(empty);
    char *path = malloc(strlen(name) + 1);
    memcpy(path, name, strlen(name) + 1);
    char *file_name = calloc(1, strlen(name) + 1);
    struct dir *dir = parse_path(path, file_name);

    if (strlen(file_name) == 0) {
        // printf("filename is null\n");
        dir_close(dir);
        free(file_name);
        return false;
    }
    struct inode *inode = NULL;
	bool success = (dir != NULL 
            // && !dir_lookup(dir, file_name, &inode) 
			&& dir_create (inode_sector, 16)
			&& dir_add (dir, file_name, inode_sector));
	if (!success && inode_sector != 0)
        fat_remove_chain(sector_to_cluster(inode_sector), 0);
	dir_close (dir);
	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
    if (!dir_create (fat_fs->data_start+1, 16))
		PANIC ("root directory creation failed");
	fat_close ();
#else
	// free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	// free_map_close ();
#endif

	printf ("done.\n");
}
