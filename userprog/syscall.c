#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "filesys/inode.h"
#include "userprog/process.h"
#define STACK_GROWTH_LIMIT 0x100000

void syscall_entry (void);
void syscall_handler (struct intr_frame *f);
void userMemoryAcess_check(void *addr);
void syscall_exit(int status);
bool syscall_create(const char *file, unsigned initial_size);
bool syscall_remove(const char *file);
int syscall_filesize (int fd);
int syscall_write (int fd, const void *buffer, unsigned size);
int syscall_read (int fd, void *buffer, unsigned size);
int syscall_open (const char *file);
void syscall_close (int fd);
void syscall_seek (int fd, unsigned position);
unsigned syscall_tell (int fd);
int syscall_exec (const char *cmd_line);
int syscall_fork(const char *name, struct intr_frame *if_);
int syscall_wait (pid_t pid);
static bool put_user (uint8_t *udst, uint8_t byte);
void * syscall_mmap(void *addr, size_t length, int writable, int fd, off_t offset);
void syscall_munmap(void *addr);
struct lock filesys_lock;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
    lock_init(&filesys_lock);
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
    userMemoryAcess_check(f->rsp);
    uint64_t syscall_num = f->R.rax; 
    thread_current()->curr_rsp = f->rsp;

    // printf("syscall num : %d\n", syscall_num);
    // get syscall_num from user stack
    // int args[6];
    switch (syscall_num) {
        case SYS_HALT:
            power_off();
            NOT_REACHED();
            break;
        case SYS_EXIT:
        {
            syscall_exit(f->R.rdi);
            break;
        }
        case SYS_FORK:
        {
            userMemoryAcess_check(f->R.rdi);
            int fork_ret = syscall_fork((const char *)(f->R.rdi), f);
            f->R.rax = fork_ret;
            break;
        }
        case SYS_EXEC:
        {
            int exec_ret = syscall_exec(f->R.rdi);
            f->R.rax =  exec_ret;
            break;
        }
        case SYS_WAIT:
        {
            userMemoryAcess_check(f->R.rdi);
            int wait_ret = syscall_wait(f->R.rdi);
            f->R.rax = wait_ret;
            break;
        }
        case SYS_CREATE:
        {
            bool success = syscall_create((char *)f->R.rdi, f->R.rsi);
            f ->R.rax = success;
            break;
        }
        case SYS_REMOVE:
        {
           bool remove_ret = syscall_remove((char *)(f->R.rdi));
            f->R.rax = remove_ret;
            break;
        }
        case SYS_OPEN:
        {
           int open_ret = syscall_open((char *)(f->R.rdi));
            f->R.rax = open_ret;
            break;
        }
        case SYS_FILESIZE:
        {
            int file_size = syscall_filesize(f->R.rdi);
            f->R.rax = file_size;
            break;
        }
        case SYS_READ:
        {
            int read_ret = syscall_read(f->R.rdi, (void *)(f->R.rsi), f->R.rdx);
            f->R.rax = read_ret;
            break;
        }
        case SYS_WRITE:
        {
            int write_ret = syscall_write(f->R.rdi, (const void *)(f->R.rsi), f->R.rdx);
            f->R.rax = write_ret;
            break;
        }
        case SYS_SEEK:
        {
            syscall_seek(f->R.rdi, f->R.rsi);
            break;
        }
        case SYS_TELL:
        {
            int tell_ret = syscall_tell(f->R.rdi);
            f->R.rax = tell_ret;
            break;
        }
        case SYS_CLOSE:
        {
            syscall_close(f->R.rdi);
            break;
        }
        case SYS_DUP2:
            break;
        case SYS_MMAP: {
            void *mmap_ret = syscall_mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
            f->R.rax = mmap_ret;
            break;
        }
        case SYS_MUNMAP: {
            syscall_munmap(f->R.rdi);
            break;
        }
        case SYS_CHDIR:
            break;
        case SYS_MKDIR:
            break;
        case SYS_READDIR:
            break;
        case SYS_ISDIR:
            break;
        case SYS_INUMBER:
            break;
        default:
            thread_exit ();
            break;
    }
}

void 
userMemoryAcess_check(void *addr) {
    // printf("check addr : %x\n", addr);
    if(!is_user_vaddr(addr)) {
        //excess the valid range -> exit
        // printf("kernel addr\n");
        syscall_exit(-1);
        return;
    } 
}

void 
syscall_exit(int status) {
    // printf("syscall exit : %d\n", status);
    thread_current()-> exit_status = status;
    thread_current() -> is_exit = true;
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
}

bool 
syscall_create(const char *file, unsigned initial_size) {
    userMemoryAcess_check(file);
    if(file == NULL) {
        syscall_exit(-1);
        return NULL;
    } else {
        return filesys_create(file, initial_size);
    }
}

bool
syscall_remove(const char *file) {
    userMemoryAcess_check(file);
    if(file == NULL) {
        syscall_exit(-1);
    } else {
        return filesys_remove(file);
    }
}

int 
syscall_filesize (int fd) { 
    struct file* opened = process_get_file(fd); 
    
    if(opened == NULL) {
        return -1;
    } 
    int size = file_length(opened);
    return size;
}

int
syscall_write (int fd, const void *buffer, unsigned size) {
    userMemoryAcess_check(buffer);
    lock_acquire(&filesys_lock);
    if(fd == 1) {
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        
        return size;
    }

    struct file* open_file = process_get_file(fd);
    if(open_file == NULL) {
        lock_release(&filesys_lock);
        return -1;
    } else {
        int actual_write = file_write(open_file, buffer, size);
        lock_release(&filesys_lock);
        return actual_write;
    }
}

int 
syscall_read (int fd, void *buffer, unsigned size) {
    userMemoryAcess_check(buffer);
    struct page *check_write = spt_find_page(&thread_current()->spt, buffer);
    if(check_write != NULL && check_write -> writable == false) {
        // printf("not writable\n");
        syscall_exit(-1);
    }
    lock_acquire(&filesys_lock);
    if(fd == 0) {
        for(int i=0;i<size;i++) {
            put_user((uint8_t *)buffer, input_getc());
        }
        lock_release(&filesys_lock);
        return size;
    }
    struct file* open_file = process_get_file(fd);
    if(open_file == NULL) {
        lock_release(&filesys_lock);
        return -1;
    } else {
        int actual_read = file_read(open_file, buffer, size);
        lock_release(&filesys_lock);
        return actual_read;
    }

} 

int
syscall_open (const char *file) {
    userMemoryAcess_check(file);
    if(file == NULL) {
        //when file name is NULL, then return NULL
        return -1;
    }
    lock_acquire(&filesys_lock);
    struct file* opened = filesys_open(file);
    
    if(opened == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }

    // printf("open file name : %s thread name : %s\n", file, thread_current()->name);
    if(!strcmp(thread_current()->name, file)) {
        file_deny_write(opened);
    } 

    int fd_add = process_add_file(opened);
    lock_release(&filesys_lock);
    return fd_add;
}

void
syscall_close (int fd) {
    process_close_file(fd);
}

void 
syscall_seek (int fd, unsigned position) {
    struct file *seek_file = process_get_file(fd);
    if(seek_file == NULL) {
        // printf("seek fail\n");
    } else {
        file_seek(seek_file, position);

    }
}

unsigned 
syscall_tell (int fd) {
    struct file *tell_file = process_get_file(fd);
    if(tell_file == NULL) {
        return -1;
    } else {
        int ret = file_tell(tell_file);

        return ret;
    }
}

int 
syscall_exec (const char *cmd_line) {
    userMemoryAcess_check(cmd_line);
    return process_exec(cmd_line);

}

int 
syscall_fork(const char * name, struct intr_frame *if_) {
    return process_fork(name, if_);
}

int
syscall_wait (pid_t pid) {
    int wait_ret = process_wait(pid);
	return wait_ret;
}

void *
syscall_mmap(void *addr, size_t length, int writable, int fd, off_t offset) {
    // userMemoryAcess_check(addr);
    // printf("fd : %d\n", fd);
    struct file *file = process_get_file(fd);
    if(file == NULL) {
        // printf("file null\n");
        syscall_exit(-1);
    }
    return do_mmap(addr, length, writable, file, fd, offset);
}

void
syscall_munmap(void *addr) {
    userMemoryAcess_check(addr);
    return do_munmap(addr);
}
/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile (
    "movabsq $done_put, %0\n"
    "movb %b2, %1\n"
    "done_put:\n"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));

    return error_code != -1;

}