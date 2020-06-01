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
// struct hash frame_table;
// struct lock frame_table_lock;

unsigned spt_hash_func (const struct hash_elem *p_, void *aux);
bool spt_less_func (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux);
void frame_table_init (struct hash *frame_table); 
unsigned frame_hash_func (const struct hash_elem *p_, void *aux);
bool frame_less_func (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux);
void spt_destroy_func (struct hash_elem *e, void *aux);

void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();

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
 * `vm_alloc_page`.
 * DO NOT MODIFY THIS FUNCTION. */
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
        struct page *newPage = palloc_get_page(PAL_USER);
		if (newPage == NULL) {
			goto err; 
		}
        
        struct lazy_file *arg = (struct lazy_file *)aux;
		uninit_new(newPage, upage, init, type, arg, &uninit_initialize);
        newPage->type = type;
        newPage -> writable = writable;

		switch (type) {
			case 0: {
                newPage -> dirty = 0;
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
            // printf("insert : %s %x\n", thread_current() -> name, newPage->va);
			return true;
		} else {
            palloc_free_page(newPage);
			goto err;
		}
        // printf("end of vm initialize\n");
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *page = malloc(sizeof(struct page));
	/* TODO: Fill this function. */
    if(page == NULL) {
        free(page);
        return NULL;
    }
    page -> va = pg_round_down(va);
    struct hash_elem *e = hash_find(&spt->vm, &page -> spt_elem);
    if(e == NULL) {
        free(page);
        return NULL;
    } else {
        page = hash_entry(e, struct page, spt_elem);
    }
	return page;
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

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
    // lock_acquire(&frame_table_lock);
	struct frame *frame = malloc(sizeof(struct frame));
	if (frame == NULL) {
        // lock_release(&frame_table_lock);
		return NULL;
	}
	ASSERT (frame != NULL);
	// ASSERT (frame->page == NULL);
	struct page *page = palloc_get_page(PAL_USER);
	if (page == NULL) {
        free(frame);
        // lock_release(&frame_table_lock);
		PANIC("TODO EVICT");
	}
    // printf("frame : %x %x\n", frame->kva, frame->uva);
	frame->uva = NULL;
	frame->kva = page;
    frame->page = page;
    frame->t = thread_current();
    // printf("frame page kva : %x\n", page);
    // hash_insert(&frame_table, &frame ->frame_elem);
    // lock_release(&frame_table_lock);
	return frame;
}

/* Growing the stack. */
// static void
bool
vm_stack_growth (void *addr, void *cur_rsp) {
    if(!vm_alloc_page_with_initializer(VM_ANON, pg_round_down(addr), true, NULL, NULL)) {
        // printf("stack growth alloc fail\n");
        return false;
    }
    // printf("alloc success\n");
    return vm_claim_page(pg_round_down(addr));
    // return true;
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
    // printf("thread curr: %s %x\n", thread_current()->name, addr);
    struct page *bogus = spt_find_page(spt, addr);
	// struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
    
    //check whether the page is in spt or not
    if(not_present && is_user_vaddr(addr)) {
        // printf("not present\n");
        if(bogus == NULL) {
            // printf("stack boundary : %x %x\n", ((uint8_t *) USER_STACK), ((uint8_t *) USER_STACK) - STACK_GROWTH_LIMIT);
            // printf("bogus null : %x\n", addr);
            //kill
            // printf("bogus null\n");
            // syscall_exit(-1);
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
                    // printf("not large stack growth\n");
                    syscall_exit(-1);
                }
            }
        }
    	else {
			//invalid page fault
			// printf("invalid page fault\n");
			// syscall_exit(-1);
            // if(!bogus -> writable) {
            //     syscall_exit(-1);
            // }
            return vm_do_claim_page (bogus);
		}
		// printf("bogus va : %x ofs : %x read_byte : %x\n", bogus->va, bogus->offset, bogus->read_byte);
    } 
    // printf("present\n");
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
        // printf("find spt null claim\n");
		return false;
	}
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
    // printf("get frame\n");
	/* Set links */
	frame->page = page;
	page->frame = frame;
    frame->uva = page->va;
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if(pml4_get_page(thread_current()->pml4, frame->uva) == NULL) {
        // printf("already not exist in pml4\n");
        if (!pml4_set_page(thread_current()->pml4, frame->uva, frame->kva, frame->page->writable)) {
            // printf("set fail\n");
            return false;
        }
    } else {
        return false;
    }
    // printf("claim succ : %x, pa : %x\n", frame -> uva, frame -> kva);
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
    lock_init(&spt_lock);
    hash_init(&spt->vm, spt_hash_func, spt_less_func, NULL);
    // frame_table_init(&frame_table);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst, struct supplemental_page_table *src) {
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
                struct lazy_file *child_aux = malloc(sizeof *parent_aux);

                if(child_aux == NULL){
                    return false;
                }

                // child_aux -> load_file = parent_aux ->load_file;
                child_aux -> load_file = file_duplicate(parent_aux ->load_file);
                if(child_aux -> load_file  == NULL) {
                    free(child_aux);
                    return false;
                }
                child_aux -> load_ofs = parent_aux -> load_ofs;
                child_aux->load_read_byte = parent_aux->load_read_byte;
                child_aux -> load_zero_byte = parent_aux -> load_zero_byte;

                if(child_aux -> load_file == NULL){    
                    free(child_aux);
                    return false;
                }

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
            return false;
        }
        if(alloc_check && not_uninit) {
            if(pml4_get_page(thread_current()->parent->pml4, page_it -> va)!=NULL) {
                struct page *page_child = spt_find_page(dst, page_it -> va);
                if (page_child == NULL) {
                    // printf("page null in claim\n");
                    return false;
                }
                struct frame *frame_child = vm_get_frame ();
                // printf("parent kva : %x va : %x\n", page_it->frame->kva, page_it->frame->uva);
                frame_child -> page = page_child;
                frame_child -> uva = page_child -> va;
                page_child -> frame = frame_child;

                // memcpy(&frame_child ->kva, &page_it->frame->kva, sizeof(void *));
                // memcpy(frame_child->kva, page_it->frame->kva, PGSIZE);
                // printf("child kva : %x va : %x\n", frame_child ->kva, page_child->frame->uva);

                if(pml4_get_page(thread_current()->pml4, frame_child->uva) == NULL) {
                    if (!pml4_set_page(thread_current()->pml4, frame_child->uva, frame_child->kva, frame_child->page->writable)) {
                        return false;
                    }
                } else {
                    return false;
                }
                
                bool swap_check = swap_in(page_child, frame_child->kva); 
                if(!swap_check) {
                    return false;
                }
                memcpy(frame_child->kva, page_it->frame->kva, PGSIZE);
            }
        }
    }
    return true;
}



/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->vm, spt_destroy_func);
    // frame_table_kill(&frame_table);
}

// void
// frame_table_kill (struct hash *frame_table) {
// 	hash_clear(frame_table, frame_destroy_func);
// }

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

// void
// frame_table_init (struct hash *frame_table) {
//     lock_init(&frame_table_lock);
//     hash_init(frame_table, frame_hash_func, frame_less_func, NULL);
// }

// unsigned
// frame_hash_func (const struct hash_elem *p_, void *aux) {
//   const struct frame *p = hash_entry (p_, struct frame, frame_elem);
//   return hash_bytes (&p->kva, sizeof p->kva);
// }

// bool
// frame_less_func (const struct hash_elem *a_,
//            const struct hash_elem *b_, void *aux) {
//   const struct frame *a = hash_entry (a_, struct frame, frame_elem);
//   const struct frame *b = hash_entry (b_, struct frame, frame_elem);

//   return a->kva < b->kva;
// }

void
spt_destroy_func (struct hash_elem *e, void *aux) {
    destroy(hash_entry(e, struct page, spt_elem));
}

// void
// frame_destroy_func (struct hash_elem *e, void *aux) {
//     // destroy(hash_entry(e, struct frame, frame_elem));
//     struct frame *del_frame = hash_entry(e, struct frame, frame_elem);
//     hash_delete(&frame_table, &del_frame ->frame_elem);
// }
