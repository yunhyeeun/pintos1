/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "bitmap.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#define NUM_SECTOR_SWAP_SLOT PGSIZE/DISK_SECTOR_SIZE

struct lock swap_lock;
// struct bitmap* swap_bitmap;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
// int swap_bitmap[];
int *swap_bitmap;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	// swap_disk = NULL;
    lock_init(&swap_lock);
    swap_disk = disk_get(1,1);
    if(swap_disk != NULL){
        swap_bitmap = malloc(sizeof(int)*disk_size(swap_disk));
        // memset(swap_bitmap, 0, sizeof(*swap_bitmap));
        // memset(0, )
        // swap_bitmap = bitmap_create(disk_size(swap_disk)); //disk size returns the number of sector
    }
    
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *aux, vm_initializer *init) {
	/* Set up the handler */
    // printf("anon initializer\n");
	page->operations = &anon_ops;
    // struct lazy_file *tmp = (struct lazy_file *)aux;
	struct anon_page *anon_page = &page->anon;
    anon_page -> aux = aux;
    anon_page -> init = init;
    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
    // printf("swap in\n");
	struct anon_page *anon_page = &page->anon;
    lock_acquire(&swap_lock);
    //get disk contents of page and read to frame
    // memset(buffer, 0, sizeof(*buffer));
    for(int i=0;i<NUM_SECTOR_SWAP_SLOT;i++) {
        disk_read(swap_disk, page->swap_location + i, kva + i * DISK_SECTOR_SIZE);
        // bitmap_set(swap_bitmap, page->swap_location + i, false);
        // swap_bitmap[page->swap_location + i] = 0;
        *(swap_bitmap + page->swap_location + i) = 0;
        
    }
    page->swap_location = -1;
    // spt_insert_page(&thread_current()->spt, page);
    lock_release(&swap_lock);
    return pml4_set_page(thread_current()->pml4, page->va, kva, page->writable);
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
    // printf("swap out\n");
    lock_acquire(&swap_lock);
	struct anon_page *anon_page = &page->anon;

    // size_t first_fit = bitmap_scan_and_flip(swap_bitmap, 0, NUM_SECTOR_SWAP_SLOT, false);
    size_t first_fit = -1;
    for (size_t i=0;i<disk_size(swap_disk)-NUM_SECTOR_SWAP_SLOT;i++) {
        if(*(swap_bitmap+i)==0) {
            int cnt = 1;
            for (size_t j=i+1;j<i+NUM_SECTOR_SWAP_SLOT;j++) {
                // if(swap_bitmap[j] !=0) {
                if(*(swap_bitmap + j) != 0) { 
                    break;
                } else {
                    cnt++;
                }
                
            }
            if(cnt == 8) {
                first_fit = i;
                for(size_t x=i;x<i+NUM_SECTOR_SWAP_SLOT;x++) {
                    // swap_bitmap[j] = 1;
                    *(swap_bitmap + x) = 1;
                }
                break;
            }
        } else {
            continue;
        }
    }
    // if (first_fit == BITMAP_ERROR) {
    if (first_fit == -1) {
        lock_release(&swap_lock);
        PANIC("NO MORE FREE SLOT");
        return false;
    }
    for(int i=0;i<NUM_SECTOR_SWAP_SLOT;i++) {
        // printf("first bit + i : %x, page kva+i : %x\n", first_fit + i, page->frame->kva+i* DISK_SECTOR_SIZE);
        disk_write(swap_disk, first_fit + i, page->frame->kva + i * DISK_SECTOR_SIZE);
    }
    page->swap_location = first_fit;
    // lock_acquire(&lru_lock);
    list_remove(&page->lru_elem);
    // lock_release(&lru_lock);
    //if successfully write to disk, delete the page from PTE
    pml4_clear_page(thread_current()->pml4, page->va);
    lock_release(&swap_lock);
    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
