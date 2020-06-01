#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;
typedef bool vm_initializer (struct page *, void *aux);

struct file_page {
    vm_initializer *init;
	void *aux;
    // struct mmap_file *mmap_file;
};

struct mmap_file {
    // int mapid;
    void *addr;
    bool mm_writable;
    struct file *file;
    struct list_elem mm_elem;
    struct list mapped_page_list;
};

void vm_file_init (void);
bool file_map_initializer (struct page *page, enum vm_type type, void *kva, vm_initializer *init);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, int fd, off_t offset);
void do_munmap (void *va);
#endif
