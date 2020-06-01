/* file.c: Implementation of memory mapped file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "userprog/syscall.h"
#include "userprog/process.h"

static bool file_map_swap_in (struct page *page, void *kva);
static bool file_map_swap_out (struct page *page);
static void file_map_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_map_swap_in,
	.swap_out = file_map_swap_out,
	.destroy = file_map_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {

}

/* Initialize the file mapped page */
bool
file_map_initializer (struct page *page, enum vm_type type, void *aux, vm_initializer *init) {
	/* Set up the handler */
	page->operations = &file_ops;
    struct lazy_file *tmp = (struct lazy_file *)aux;
	struct file_page *file_page = &page->file;
    file_page -> aux = tmp;
    file_page -> init = init;

    page -> dirty = 0;
    return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_map_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_map_swap_out (struct page *page) {
	struct file_page *file_page = &page->file;
}

/* Destory the file mapped page. PAGE will be freed by the caller. */
static void
file_map_destroy (struct page *page) {
	struct file_page *file_page = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, int fd, off_t offset) {
    // printf("length : %p\n", length);
    if(!is_user_vaddr(addr)) {
        // printf("kernel access\n");
        return NULL;
    }
    if(length == 0 || addr == 0 || addr + length <=0) {
        // printf("length is negative\n");
        return NULL;
    }
    if(addr != pg_round_down(addr)) {
        //addr is not page aligned
        // printf("not page aligned\n");
        return NULL;
    }
    if(offset > PGSIZE) {
        // printf("invalid offset\n");
        return NULL;
    }
    if(fd == 0 || fd == 1) {
        //fd is console input or output or not exist in fd list
        return NULL;
    }

    // for(size_t i=0;i<file_len;i+=PGSIZE) {
    for(size_t i=0;i<length;i+=PGSIZE) {
        struct page *check_overlap = spt_find_page(&thread_current()->spt, addr+i);
        if(check_overlap) {
            //addr is overlapped existing page
            // printf("spt overlap\n");
            return NULL;
        }
    }
    // printf("before reopen\n");
    lock_acquire(&filesys_lock);
    struct file *mmap_opened = file_reopen(file);
    if(mmap_opened == NULL) {
        lock_release(&filesys_lock);
        return NULL;
    }
    // int mmap_fd = process_add_file(mmap_opened);
    // lock_release(&filesys_lock);

    off_t file_len = file_length(mmap_opened);
    lock_release(&filesys_lock);
    // printf("file length : %x length : %x, off: %x\n", file_len, length, offset);
    size_t read_byte = 0;
    size_t zero_byte = 0;

    struct mmap_file *m = malloc(sizeof *m);
    if(m==NULL){
        return NULL;
    }
    list_init(&m->mapped_page_list);
    m->file = mmap_opened;
    m->addr = addr;
    m->mm_writable = writable;
    // printf("mmap : writable :%d\n", writable);
    for(size_t i=0;i<file_len;i+=PGSIZE) {
        // printf("i : %x\n", i);
        struct lazy_file *mmap_lazy = malloc(sizeof *mmap_lazy);
        mmap_lazy -> load_file = mmap_opened;      
        if(i==0) {
            mmap_lazy -> load_ofs = offset;
        } else {
            mmap_lazy -> load_ofs = i;
            offset = 0;
        }

        if(PGSIZE <= length) {
            if(file_len < PGSIZE) {
                read_byte = file_len;
                zero_byte = PGSIZE - read_byte;
            } else {
                read_byte = PGSIZE;
                zero_byte = 0;
            }
        } else {
            if(file_len >= length) {
                read_byte = length;
                zero_byte = PGSIZE - read_byte;
            } else {
                read_byte = file_len;
                zero_byte = PGSIZE - read_byte;
            }
            
        }

        mmap_lazy -> load_read_byte = read_byte;
        mmap_lazy -> load_zero_byte = zero_byte;
        mmap_lazy -> writable = writable;
        // printf("read byte : %x, zero : %x ofs: %x\n", read_byte, zero_byte, mmap_lazy -> load_ofs );
        if(!vm_alloc_page_with_initializer(VM_FILE, i+addr, writable, lazy_load_segment, mmap_lazy)){
            free(mmap_lazy);
            // printf("alloc fail\n");
            return NULL;
        }
        
        struct page *allocated = spt_find_page(&thread_current() -> spt, addr+i);
        if(allocated == NULL) {
            // printf("not existed in spt\n");
            free(mmap_lazy);
            return NULL;
        }
        else {
            list_push_back(&m->mapped_page_list, &allocated ->page_elem);
        }
        // length -= read_byte;
    }
    
    list_push_back(&thread_current()->mm_list, &m -> mm_elem);
    return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
    // printf("addr : %x\n", addr);
    // lock_acquire(&filesys_lock);
    struct page *munmap_page = spt_find_page(&thread_current()->spt, addr);
    if(munmap_page == NULL) {
        // printf("munmpa page null\n");
        // lock_release(&filesys_lock);
        return;
    }
    enum vm_type type = page_get_type(munmap_page);
    if(type == 2) {
        // printf("file page!\n");
        struct list *mm_list = &thread_current() -> mm_list;
        int mm_list_size = list_size(mm_list);
    
        struct list_elem *e;
        struct mmap_file *tmp;
        for(e=list_begin(mm_list);e!=list_end(mm_list); e=list_next(e)){
            tmp = list_entry(e, struct mmap_file, mm_elem);
            if(tmp -> addr == addr) {
                // printf("find addr in mm list\n");
                break;
            }
        }
        // lock_acquire(&filesys_lock);
        //write back from page to the file 
        if(pml4_is_dirty(thread_current()->pml4, addr)) {
            // printf("pml4 is dirty\n");
            if(tmp->mm_writable) {
                // printf("writable file\n");
                file_write_at(tmp->file, munmap_page->va, munmap_page->read_byte, munmap_page -> offset);
            } else {
                // lock_release(&filesys_lock);
                // printf("not writable\n");
                return NULL;
            }
        }
        // lock_release(&filesys_lock);
        //remove the list
        if(tmp == NULL){
            // printf("tmp is null\n");
        }
        if(tmp!=NULL) {
            // printf("tmp is not null\n");
            struct list *page_mapped = &tmp -> mapped_page_list;
            for(int i=0;i<list_size(page_mapped);i++) {
                // printf("unmap page list : %d\n", i);
                struct page *unmap_pg = list_entry(list_begin(page_mapped), struct page, page_elem);
                list_pop_front(page_mapped);
                // file_close(unmap_pg -> file_data);
                // free(unmap_pg);
            }
            list_remove(&tmp->mm_elem);
            file_close(tmp->file);
            free(tmp);
            // lock_release(&filesys_lock);
            // printf("unmap success\n");
            return;
        }       
    }
    // lock_release(&filesys_lock);
    return;
}
