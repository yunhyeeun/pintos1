/* vm.c: Generic interface for virtual memory objects. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "vm/anon.h"
#include "vm/file.h"
#include "vm/uninit.h"
#include "threads/vaddr.h" 
#include "userprog/process.h"

#define STACK_GROWTH_LIMIT 0x100000
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */

struct lock spt_lock;
struct list lru_list;
struct lock lru_lock;
struct list_elem *lru_next = NULL;

unsigned spt_hash_func (const struct hash_elem *p_, void *aux);
bool spt_less_func (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux);

void spt_destroy_func (struct hash_elem *e, void *aux);

void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
    list_init(&lru_list);
    lock_init(&lru_lock);

#ifdef EFILESYS  /* For project 4 */
	pagecache_init (); 
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}
  
/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {
    // printf("alloc va : %x type : %x\n", upage, type);
	struct supplemental_page_table *spt = &thread_current () -> spt;
    // printf("vm alloc : %s\n", thread_current() -> name);
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
        struct page *newPage = calloc(1, sizeof *newPage);
		if (newPage == NULL) {
			goto err; 
		}
        
        struct lazy_file *arg = (struct lazy_file *)aux;
		uninit_new(newPage, upage, init, type, arg, &uninit_initialize);
        newPage->type = type;
        newPage -> writable = writable;
        newPage -> swap_location = -1;

		switch (type) {
			case 0: {
				break;
			}
			case 1: {
				struct uninit_page *uninit = &newPage->uninit;
				uninit->page_initializer = &anon_initializer;
				break; 
			}
			case 2: {
				struct uninit_page *uninit = &newPage->uninit;
				uninit->page_initializer = &file_map_initializer;
				break;
			}
            default: {
                break;
            }
		}

		/* Add writable to new_page. */
		/* TODO: Insert the page into the spt. */
		if (spt_insert_page(spt, newPage)) {
            // printf("insert succ\n");
			return true;
		} else {
            vm_dealloc_page(newPage);
			goto err;
		}
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *page = calloc(1, sizeof *page);
	/* TODO: Fill this function. */
    if(page == NULL) {
        return NULL;
    }
    page -> va = pg_round_down(va);
    lock_acquire(&spt_lock);
    struct hash_elem *e = hash_find(&spt->vm, &page -> spt_elem);
    free(page);
    if(e == NULL) {
        lock_release(&spt_lock);
        return NULL;
    } else {
        lock_release(&spt_lock);
        return hash_entry(e, struct page, spt_elem);
    }
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
    int succ = false;
	/* TODO: Fill this function. */
    if(page == NULL) {
        return false;
    }
    lock_acquire(&spt_lock);
    struct hash_elem *e = hash_insert(&spt->vm, &page -> spt_elem);
    if(e==NULL) {
        succ = true;
    } 
    lock_release(&spt_lock);
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
     if(lru_next == NULL) {
         lru_next = list_begin(&lru_list);
     }
    struct list_elem *e = lru_next;
    int lru_flg = 0;
    while(victim == NULL) {
        struct page *evict_check = list_entry(e, struct page, lru_elem);
        if(pml4_is_accessed(thread_current()->pml4, evict_check -> va)) {
            pml4_set_accessed(thread_current() -> pml4, evict_check ->va, false);
        } else {
            if(!lru_flg) {
                victim = evict_check -> frame;
                list_remove(&evict_check -> lru_elem);
                lru_flg = 1;
                lru_next = list_next(e);
                return victim;
            } 
        }
        if(e==list_end(&lru_list)) {
            e = list_begin(&lru_list);
        } else {
            e = list_next(e);
        }
        
    }

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
    bool check = swap_out(victim -> page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
    // printf("get frame function\n");
    struct frame *frame;
	struct page *page = palloc_get_page(PAL_USER);
	if (page == NULL) {
        frame = vm_evict_frame();
        
	} else {    
        frame = calloc(1, sizeof *frame);
        if (frame == NULL) {
            free(page);
            return NULL;
        }
        frame->uva = NULL;
        frame->kva = page;
        frame->page = page;
        frame->t = thread_current();
    }
	return frame;
}

/* Growing the stack. */
// static void
bool
vm_stack_growth (void *addr, void *cur_rsp) {
    if(!vm_alloc_page_with_initializer(VM_ANON, pg_round_down(addr), true, NULL, NULL)) {
        return false;
    }
    // printf("alloc success\n");
    return vm_claim_page(pg_round_down(addr));
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present ) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
    // printf(" try fault thread curr: %s %x %d %d\n", thread_current()->name, addr, write, not_present);
    struct page *bogus = spt_find_page(spt, addr);
	// struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
    
    //check whether the page is in spt or not
    if(not_present && is_user_vaddr(addr)) {
        // printf("not present\n");
        if(bogus == NULL) {
            if(user) {
                void *user_rsp = f -> rsp;
                // printf("user rsp : %x\n", user_rsp);
                if(addr < ((uint8_t *) USER_STACK) && addr >= ((uint8_t *) USER_STACK) - STACK_GROWTH_LIMIT) {
                    if(user_rsp - 8 <= addr) {
                        if(vm_stack_growth(addr, user_rsp)){
                            return true;
                        }
                    }  
                } else {
                    // printf("not large stack growth\n");
                    syscall_exit(-1);
                }
            } else {
                //kernel access
                void *kernel_rsp = thread_current() -> curr_rsp;
                // printf("kernerl rsp : %x\n", kernel_rsp);
                if(addr < ((uint8_t *) USER_STACK) && addr >= ((uint8_t *) USER_STACK) - STACK_GROWTH_LIMIT) {
                    if(kernel_rsp <= addr) {
                        if(vm_stack_growth(addr, kernel_rsp)){
                            return true;
                        }
                    } 
                } else {
                    // printf("not large stack growth kernel\n");
                    syscall_exit(-1);
                }
            }
        }
    	else {
			//invalid page fault
			// printf("invalid page fault\n");
            return vm_do_claim_page (bogus);
		}
		// printf("bogus va : %x ofs : %x read_byte : %x\n", bogus->va, bogus->offset, bogus->read_byte);
    } 
    if(!not_present && write) {
        syscall_exit(-1);

    }
    
    //bogus page fault
	return vm_do_claim_page (bogus);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	/* TODO: Fill this function */
	struct page *page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL) {
		return false;
	}
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	/* Set links */
	frame->page = page;
	page->frame = frame;
    frame->uva = page->va;
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if(pml4_get_page(thread_current()->pml4, frame->uva) == NULL) {
        if (!pml4_set_page(thread_current()->pml4, page -> va, frame->kva, page->writable)) {
            free(frame);
            return false;
        }
    } else {
        free(frame);
        return false;
    }
    
    pml4_set_dirty(thread_current()->pml4, page -> va, false);
    list_push_back(&lru_list, &page -> lru_elem);
    // printf("claim succ : %x, pa : %x\n", frame -> uva, frame -> kva);
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
    lock_init(&spt_lock);
    hash_init(&spt->vm, spt_hash_func, spt_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst, struct supplemental_page_table *src) {
    // printf("copy\n");
    struct hash_iterator hash_it;
    hash_first(&hash_it, &src -> vm);
    while(hash_next(&hash_it)) {
        struct page *page_it = hash_entry(hash_cur(&hash_it), struct page, spt_elem);
        enum vm_type page_type = VM_TYPE(page_it->operations->type);
        bool alloc_check;
        bool not_uninit;

        switch(page_type) {
            case VM_UNINIT: {
                not_uninit = false;
                struct uninit_page *uninit = &page_it->uninit;
                enum vm_type type_uninit = uninit->type;
                struct lazy_file *parent_aux = ((struct lazy_file *)(uninit->aux));
                struct lazy_file *child_aux = calloc(1, sizeof *parent_aux);

                if(child_aux == NULL){
                    return false;
                }

                child_aux -> load_file = parent_aux ->load_file;
                child_aux -> load_ofs = parent_aux -> load_ofs;
                child_aux->load_read_byte = parent_aux->load_read_byte;
                child_aux -> load_zero_byte = parent_aux -> load_zero_byte;
                child_aux -> mmapFlag = parent_aux -> mmapFlag;
                child_aux -> mmapStruct = parent_aux -> mmapStruct;

                alloc_check = vm_alloc_page_with_initializer(type_uninit, page_it->va, page_it->writable, page_it->uninit.init, child_aux);
                break;
            }
            case 1 : {
                not_uninit = true;
                alloc_check = vm_alloc_page_with_initializer(page_type, page_it -> va, page_it -> writable, NULL, NULL);
                break;
            }
            case 2: { 
                not_uninit = true;
                alloc_check = vm_alloc_page_with_initializer(page_type, page_it -> va, page_it -> writable, NULL, NULL);
                break;
            
            }
        }
        

        if(!alloc_check) {
            // free(child_aux);
            return false;
        }
        if(alloc_check && not_uninit) {
                struct page *page_child = spt_find_page(dst, page_it -> va);
                if (page_child == NULL) {
                    // printf("page null in claim\n");
                    // free(child_aux);
                    return false;
                }
                vm_do_claim_page (page_child);
                memcpy(page_child->frame->kva, page_it->frame->kva, PGSIZE);
        }
    }
    return true;
}



/* Free the resource hold by the supplemental page table */

unsigned
spt_hash_func (const struct hash_elem *p_, void *aux) {
  const struct page *p = hash_entry (p_, struct page, spt_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

bool
spt_less_func (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux) {
  const struct page *a = hash_entry (a_, struct page, spt_elem);
  const struct page *b = hash_entry (b_, struct page, spt_elem);

  return a->va < b->va;
}

void
spt_destroy_func (struct hash_elem *e, void *aux) {
    struct page *page = hash_entry(e, struct page, spt_elem);
    if(page != NULL) {
        vm_dealloc_page(page);
    } 
}

void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_destroy(&spt->vm, spt_destroy_func);\
}
