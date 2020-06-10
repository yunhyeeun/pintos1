/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "bitmap.h"
#include "threads/vaddr.h"
#define NUM_SECTOR_SWAP_SLOT PGSIZE/DISK_SECTOR_SIZE

struct lock swap_lock;
struct bitmap* swap_bitmap;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
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
        swap_bitmap = bitmap_create(disk_size(swap_disk)); //disk size returns the number of sector
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
    // swap_disk = disk_get(1,1);
    // if(page->swap_location > disk_size(swap_disk)) {
    //     lock_release(&swap_lock);
    //     return false;
    // }
    for(int i=0;i<NUM_SECTOR_SWAP_SLOT;i++) {
        disk_read(swap_disk, page->swap_location + i, kva + i * DISK_SECTOR_SIZE);
        bitmap_set(swap_bitmap, page->swap_location + i, false);
    }
    page->swap_location = -1;
    
    lock_release(&swap_lock);
    return pml4_set_page(thread_current()->pml4, page->va, kva, page->writable);
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
    // printf("swap out\n");
    lock_acquire(&swap_lock);
	struct anon_page *anon_page = &page->anon;
    // swap_disk = disk_get(1, 1);
    // printf("page swap loc : %d disk size : %d\n", page->swap_location, (size_t)disk_size(swap_disk));
    // if(page->swap_location > (size_t)disk_size(swap_disk)) {
    //     // printf("swap location is bigger than disk size\n");
    //     lock_release(&swap_lock);
    //     return false;
    // }

    size_t first_fit = bitmap_scan_and_flip(swap_bitmap, 0, NUM_SECTOR_SWAP_SLOT, false);
    if (first_fit == BITMAP_ERROR) {
        // printf("first bit is error\n");
        lock_release(&swap_lock);
        PANIC("NO MORE FREE SLOT");
        return false;
    }

    for(int i=0;i<NUM_SECTOR_SWAP_SLOT;i++) {
        disk_write(swap_disk, first_fit + i, page->frame->kva + i * DISK_SECTOR_SIZE);
    }
    page->swap_location = first_fit;
    list_remove(&page->lru_elem);
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
