#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
int process_add_file (struct file *f);
void process_close_file (int fd); 
struct file *process_get_file (int fd);
struct file_descriptor* 
find_fd(struct list *fd_list, int fd);
bool
fd_less (const struct list_elem *a_, const struct list_elem *b_,
            void *aux UNUSED);
bool lazy_load_segment (struct page *page, void *aux);
struct lock rox_lock;

#endif /* userprog/process.h */
