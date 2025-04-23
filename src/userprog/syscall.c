#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

struct lock file_lock;

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int sys_call_code = *(int*)(f->esp);
  // printf("%p\n", sys_call_code);

  ASSERT(thread_current()->pagedir);

  if(is_kernel_vaddr(f->esp) || pagedir_get_page(thread_current()->pagedir, f->esp) == NULL){
    thread_exit();
  }

  switch(sys_call_code){

    case(SYS_HALT): {

      shutdown_power_off();
      break;
    }

    case(SYS_EXIT): {

      int status = *(int*)((f->esp+4));

      struct thread *cur = thread_current();
      f->eax = status;
      thread_exit();
      break;
    }

    case(SYS_WAIT): {
      tid_t pid = *(tid_t*)((f->esp+4));
      int status;

      status = process_wait(pid);
      f->eax = status;
      break;

    }

    case(SYS_EXEC): {

      tid_t tid;
      const char* cmd_line = (const char*)*((int*)(f->esp + 4));

      tid = process_wait(process_execute(cmd_line));
      f->eax = tid;
      break;
    }

    case(SYS_CREATE): {

      const char* file_name = (const char*)*((int*)(f->esp + 4));
      unsigned initial_size = *((unsigned*)(f->esp + 8));

      lock_acquire(&file_lock);
      bool success = filesys_create(file_name, initial_size);    
      lock_release(&file_lock);

      printf("name: %s, %d\n", file_name, success);
      // if(!success){
      //   printf("file could not be created :)\n");
      // }

      f->eax = success;
      break;
    }

    case(SYS_REMOVE): {
      const char* file_name = (const char*)*((int*)(f->esp + 4));

      lock_acquire(&file_lock);
      bool success = filesys_remove(file_name);    
      lock_release(&file_lock);

      // if(!success){
      //   printf("file could not be deleted :)\n");
      // }

      f->eax = success;
      break;
    }

    case(SYS_OPEN): {

      const char* file_name = (const char*)*((int*)(f->esp + 4));
      struct thread *cur = thread_current();

      lock_acquire(&file_lock);
      struct file* open_file = filesys_open(file_name);    
      lock_release(&file_lock);

      if(!open_file){
        // printf("file could not be opened\n");
        f->eax = -1;
        break;
      }

      cur->fd++;
      cur->fd_table[cur->fd] = open_file;

      f->eax = cur->fd;

      printf("fd=%d\n", cur->fd);

      break;
    }

    case(SYS_CLOSE): {

      int fd = *(int*)(f->esp + 4);
      struct thread *cur = thread_current();

      if(fd){
        lock_acquire(&file_lock);
        file_close(cur->fd_table[fd]);    
        lock_release(&file_lock);

        cur->fd_table[fd] = NULL;
      }
      break;
    }

    case(SYS_FILESIZE): {

      int fd = *(int*)(f->esp + 4);
      struct thread *cur = thread_current();
      
      if(fd){
        lock_acquire(&file_lock);
        f->eax = file_length(cur->fd_table[fd]);    
        lock_release(&file_lock);
      }
      break;
    }

    case(SYS_WRITE): {

      int fd = *(int*)(f->esp + 4);
      const void* buffer = *(void**)(f->esp + 8);
      unsigned size = *((unsigned*)(f->esp + 12));
      struct thread *cur = thread_current();

      if(fd == STDOUT_FILENO){

        putbuf(buffer, size);
        f->eax = size;

      } else {

        struct file *write_file = cur->fd_table[fd];
        
        if(write_file){
          
          lock_acquire(&file_lock);
          f->eax = file_write(write_file, buffer, size);    
          lock_release(&file_lock);

        } else {
          f->eax = 0;
        }

      }

      break;
    }

    case(SYS_READ): {

      int fd = *(int*)(f->esp + 4);
      char* buffer = *((char**)(f->esp + 8));
      unsigned size = *((unsigned*)(f->esp + 12));
      struct thread *cur = thread_current();
      int size_read = 0;

      struct file *read_file = cur->fd_table[fd];

      if(fd == STDIN_FILENO){

        for(int i=0; i < size; i++){
          buffer[i] = input_getc();
          size_read++;
        }
        f->eax = size_read;

      }else{

        if(read_file){
          lock_acquire(&file_lock);
          f->eax = file_read(cur->fd_table[fd], buffer, size);    
          lock_release(&file_lock);
        } else {
          f->eax = -1;
        }
      }
      break;
    }

  }
}
