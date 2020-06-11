#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"  
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"  
#include "vm/file.h"
#endif
 
static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
int process_add_file (struct file *f);
void process_close_file (int fd);
struct file_descriptor* find_fd(struct list *fd_list, int fd);
bool fd_less (const struct list_elem *a_, const struct list_elem *b_,
            void *aux UNUSED);   

struct lock rox_lock;
/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();

}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
    lock_init(&rox_lock);
    char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

    //get process name and pass it to create thread
    char *parsing;
    char *next_ptr;
    const char *delimetes = " ";
    parsing = strtok_r(file_name, delimetes, &next_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (parsing, PRI_DEFAULT, initd, fn_copy);

	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
    // frame_table_init(&thread_current() -> frame_table);
#endif
	process_init ();
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t 
process_fork (const char *name, struct intr_frame *if_ ) {
	/* Clone current thread to new thread.*/
    thread_current() ->fork_flag =1;
	tid_t pid = thread_create (name, PRI_DEFAULT, __do_fork, if_);
	if(pid == TID_ERROR) {
		thread_current() -> fork_flag = 0;
		sema_up(&thread_current()->child_create);
	}
	 sema_down(&thread_current() -> child_create);

    if(thread_current()->child_exit_status == -1) {
        pid = TID_ERROR;
        return pid;
    }
	return pid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
    void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
    if(!is_user_pte(pte)) {
        return true;
    }
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER);
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
        return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *current = thread_current ();
    struct thread *parent = current->parent;

	// /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = (struct intr_frame *)aux;
	bool succ = true;
	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	
	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
    
	supplemental_page_table_init (&current->spt);
    // frame_table_init(&current -> frame_table);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;

    // struct list_elem *m;
    // struct list *parent_mm_list = &parent -> mm_list;
    // struct list *child_mm_list = &current -> mm_list;

    // for(m=list_begin(parent_mm_list);m!=list_end(parent_mm_list);m=list_next(m)) {
    //     struct mmap_file *parent_mm = list_entry(m, struct mmap_file, mm_elem);
    //     // struct file *f = parent_mm -> file;
    //     struct file *child_file = parent_mm -> file;
	// 	// if (child_file == NULL) {
	// 	// 	goto error;
	// 	// }
    //     struct mmap_file *child_mm = calloc (1, sizeof(struct mmap_file));
    //     if (child_mm == NULL) {
	// 		goto error;
	// 	}
	// 	child_mm -> file = child_file;
    //     child_mm -> addr = parent_mm -> addr;
    //     child_mm -> mm_writable = parent_mm -> mm_writable;
    //     child_mm -> mapped_page_list = parent_mm -> mapped_page_list;

    //     list_push_back(child_mm_list, &child_mm->mm_elem);
    // }

#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)) {
		goto error;
	}
#endif
	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
    struct list_elem *e;
    struct list *parent_fd_list = &parent -> fd_list;
    struct list *child_fd_list = &current -> fd_list;

    for(e=list_begin(parent_fd_list);e!=list_end(parent_fd_list);e=list_next(e)) {
        struct file_descriptor *parent_file_descr = list_entry(e, struct file_descriptor, fd_elem);
        struct file *f = parent_file_descr -> file;
        struct file *child_file = file_duplicate(f);
		if (child_file == NULL) {
			goto error;
		}
        struct file_descriptor *child_file_descr = calloc (1, sizeof(struct file_descriptor));
        if (child_file_descr == NULL) {
			goto error;
		}
		child_file_descr -> file = child_file;
        child_file_descr -> fd = parent_file_descr -> fd;

        list_push_back(child_fd_list, &child_file_descr->fd_elem);
		if(current -> max_fd < child_file_descr -> fd) {
            current -> max_fd = child_file_descr->fd;
        }
    }

	process_init ();
    sema_up(&thread_current()->parent->child_create);

	/* Finally, switch to the newly created process. */
	if (succ) {
		if_.R.rax = 0;
		do_iret (&if_);
    }
error:
	thread_current()->parent->child_exit_status = -1;
    thread_current()->child_exit_status = -1;
	thread_exit ();
	sema_up(&thread_current()->parent->child_create);
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = calloc(1,strlen(f_name)+1);
    memcpy(file_name, f_name, strlen(f_name)+1);
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();
    #ifdef VM
        supplemental_page_table_init(&thread_current()->spt);
    #endif
	/* And then load the binary */
	// lock_acquire(&rox_lock);
	success = load (file_name, &_if);
    // lock_release(&rox_lock);
	/* If load failed, quit. */
	free(file_name);

	if (!success) {
        // printf("load fail\n");
        syscall_exit(-1);
        return -1;
    }
	
	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	// printf("wait child pid is : %d\n", child_tid);
 
    // printf("wait : !!!! curr name : %s\n", thread_current()->name);
    // printf("wait : %s %d\n", thread_current()->name, child_tid);
    if(child_tid == -1) {
        return -1;
    }

    struct thread *parent = thread_current();
    struct list *child_list = &parent -> child_list;
    struct list_elem *e;
    struct thread *child_tmp;
    int child_exit_status;
    int cnt = 0;

    for(e=list_begin(child_list);e!=list_end(child_list);e=list_next(e)) {
        child_tmp = list_entry(e, struct thread, child_elem);
        if(child_tmp -> tid == child_tid) {  
            cnt++;
            break;
        }
    }
    if(cnt == 0) { // there is no child in child list of parent
		return -1;
    }

    if(child_tmp -> child_exit_status == -1) {
        return -1;
    }

	sema_down(&child_tmp->exit_sema); 
    child_exit_status = child_tmp -> exit_status;

    if(child_tmp -> is_exit == true) {
        list_remove(e);
    }

    sema_up(&child_tmp->load_sema);
    return child_exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
    // printf("process exit\n");
    struct list *fd_list = &curr->fd_list;
	int fd_size = list_size(fd_list);
	if (fd_size > 0) {
		for (int i=0;i<fd_size;i++) {
			struct file_descriptor *e = list_entry(list_begin(fd_list), struct file_descriptor, fd_elem);
			list_pop_front(fd_list);
			file_close(e->file);
			free(e);
		}
	}

	if (curr->running_file) {
		file_allow_write(curr->running_file);
		file_close(curr->running_file);
	}

    if(curr->child_exit_status == -1 && curr -> parent-> fork_flag == 1) {    
        sema_up(&curr->parent->child_create);  
        list_remove(&curr->child_elem);
    }  

    // //munmap the mm list
    struct list *mm_list = &thread_current() -> mm_list;
    int mm_size = list_size(mm_list);
    if(mm_size) {
        for(int i=0;i<mm_size;i++) { 
            struct mmap_file *tmp = list_entry(list_begin(mm_list), struct mmap_file, mm_elem);
            do_munmap(tmp-> addr);
        }
    } 

	process_cleanup ();
	sema_up(&curr->exit_sema);
    sema_down(&curr->load_sema);
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	char **cmd_parsing = palloc_get_page(PAL_ZERO);
	char *token;
	char *next_ptr;
	int cnt = 0;
	token = strtok_r(file_name, " ", &next_ptr);
	while (token) {
		cmd_parsing[cnt] = token;
		token = strtok_r(NULL, " ", &next_ptr);
		cnt++;
	}

	/* Open executable file. */
    // lock_acquire(&rox_lock);
    // printf("file open : %s\n", cmd_parsing[0]);
	file = filesys_open (cmd_parsing[0]);
	if (file == NULL) {
        // lock_release(&rox_lock);
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

    t->running_file = file;
    file_deny_write(file);
    // lock_release(&rox_lock);

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable)) 
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_)) {
        // printf("setup stack fail\n");
		goto done;
    }
	/* Start address. */
	if_->rip = ehdr.e_entry;
	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	int arglen = 0;
	uint64_t *argvaddr = (uint64_t *) palloc_get_page(PAL_ZERO);
	// push string of argument in user stack
	for (int i = cnt-1; i >= 0; i--) {
		arglen = strlen(cmd_parsing[i]) + 1;
		//address of argv[1] which will be stored in user stack
		if_->rsp -= arglen;
		memcpy (if_->rsp, cmd_parsing[i], arglen);
		argvaddr[i] = (uint64_t) if_->rsp;
	}
	// word-align
	while (if_->rsp % 8 != 0) {
		if_->rsp --;
        memset((char *)if_->rsp, 0, 1);
	}
	// null-pointer
	if_->rsp -= 8;
    memset((char *)if_->rsp, 0, sizeof(char *));

	// push address of argument in user stack
	for (int i = cnt-1; i >= 0; i--) {
		if_->rsp -= 8;
        memcpy(if_->rsp, &argvaddr[i], 8);
	}

    if_-> R.rsi = if_ ->rsp;
	if_->R.rdi = cnt;

    //return address
	if_->rsp -= 8;
    memset((char *)if_->rsp, 0, 8);

    palloc_free_page(argvaddr);
	success = true;
done:
	/* We arrive here whether the load is successful or not. */

    palloc_free_page (cmd_parsing);
    t->is_load = success;
	return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

//add file to file descriptor table
int
process_add_file (struct file *f) {
    struct thread *t = thread_current();
    int max_fd = t->max_fd;
    struct file_descriptor *file_descr = calloc (1, sizeof(struct file_descriptor));
    if (file_descr == NULL) {
		file_close(f);
		return -1;
	}
	file_descr -> fd = ++max_fd;
    file_descr -> file = f;
    list_push_back(&t->fd_list, &file_descr->fd_elem);
	t->max_fd = max_fd;
    return max_fd;
}

// search file in file descriptor table
struct file *process_get_file (int fd) {
    struct list *fd_list = &thread_current() ->fd_list;
    int max_fd = thread_current() -> max_fd;
    if(max_fd == 2 || max_fd < fd){
        return NULL;
    } else {
        struct file_descriptor *fd_descr = find_fd(&thread_current() ->fd_list, fd);

        if(fd_descr == NULL) {
            return NULL;
        } else {
            return fd_descr->file;
        }
    }
}

struct file_descriptor* 
find_fd(struct list *fd_list, int fd){
    struct list_elem *e;
    for(e=list_begin(fd_list);e!=list_end(fd_list);e = list_next(e)){
        struct file_descriptor *file_descr = list_entry(e, struct file_descriptor, fd_elem);
        if(file_descr->fd == fd) {
            return file_descr;
        }
    }
    return NULL;
}

//close the file in file descriptor table
void
process_close_file (int fd) {
	struct list *file_descr = &thread_current()->fd_list;
    int max_fd = thread_current() -> max_fd;
    if(max_fd == 2 || max_fd < fd) {
        return;
    }
	struct file_descriptor *fd_descr = find_fd(file_descr, fd);
	struct file *cur_file = fd_descr->file;
	if (cur_file == NULL || fd_descr == NULL) {
		return;
	}
	list_remove(&fd_descr->fd_elem);
	if(fd == max_fd) {
		if(list_empty(file_descr)) {
			thread_current() -> max_fd = 2;
		} else {
			thread_current()->max_fd = fd-1;
		}
	}
	file_close(cur_file);
	free(fd_descr);
    
}


#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
    // lock_acquire(&filesys_lock);
    struct lazy_file *load = aux;
    void *kva = page->frame->kva;
	// printf("lazy_load÷c\n");
    if(load != NULL) { 
        page->file_data = load -> load_file;
        page->offset = load -> load_ofs;
        page->read_byte = load ->load_read_byte;
        page->zero_byte = load ->load_zero_byte;
        page->writable = load -> writable;
        // printf("thread :%s, aux read byte : %x va :%x\n", thread_current() -> name, page -> read_byte, page->va);
    }

    if(load->mmapFlag) {
        list_push_back(&load->mmapStruct->mapped_page_list, &page -> page_elem);   
    }
	// off_t reads = file_read(load -> load_file, kva, load -> load_read_byte);
	// off_t reads =file_read_at(load -> load_file, kva, load->load_read_byte, load->load_ofs);
    // printf("after file seek\n");
    // if(reads!= load->load_read_byte) {
	    // printf("read at fail read : %x, actual : %x off : %x\n", load -> load_read_byte, reads, load-> load_ofs);
  
    if(file_read_at(load -> load_file, kva, load->load_read_byte, load->load_ofs) != load->load_read_byte) {
        free(load);
        return false;
    }

    memset(kva + load->load_read_byte, 0, load->load_zero_byte);
    free(load);
    // printf("finish lazy load\n");
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);
    // printf("load va : %x\n", upage);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
        struct lazy_file *lazy_file = malloc(sizeof *lazy_file);
        lazy_file -> load_file = file;
        lazy_file -> load_ofs = ofs;
        lazy_file -> load_read_byte = page_read_bytes;
        lazy_file -> load_zero_byte = page_zero_bytes;
        lazy_file -> writable = writable;
        lazy_file -> mmapFlag = false;
        lazy_file -> mmapStruct = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage, writable, lazy_load_segment, lazy_file)) {
            free(lazy_file); 
            // lock_release(&filesys_lock);               
			return false;
        }

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
        ofs += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);
	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
    // printf("setup stack\n");
    if(!vm_alloc_page_with_initializer(VM_ANON, stack_bottom, true, NULL, NULL)) {
        // lock_release(&filesys_lock);
        // printf("alloc fail\n");
        return false;
    }

    if(vm_claim_page(stack_bottom)){
        success = true;
    }
    if(success) {
        if_ -> rsp = USER_STACK;
    }
    // printf("set up stack success\n");
	return success;
}
#endif /* VM */
