#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/kernel/console.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "userprog/process.h"   /* for process_execute() */


#define STDOUT_FILENO 1
#define FD_MAX 128

extern struct lock filesys_lock;  /* Serializes file system operations */

tid_t process_execute (const char *cmdline);     

static void validate_ptr   (const void *uaddr);
static void validate_range (const void *uaddr, size_t size);
static void validate_str   (const char *s);


static void syscall_handler(struct intr_frame *);
static int get_argument(struct intr_frame *f, int n);

void sys_exit(int status);
int sys_write(int fd, const void *buffer, unsigned size);

/*
  syscall_init:
    Set up the system call entry point by registering interrupt 0x30.
    This makes user programs’ int 0x30 instructions invoke syscall_handler.
*/

void
syscall_init(void) 
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
  syscall_handler:
    Central dispatcher for handling system calls from user code.
    1) Validates the user stack pointer (esp).
    2) Reads the syscall number and its arguments safely.
    3) Calls the appropriate sys_* helper based on syscall_num.
    4) Places the helper’s return value into f->eax for the user.
*/

static void
syscall_handler(struct intr_frame *f) 
{
  /* Ensure the user stack pointer is valid before use. */
  validate_ptr(f->esp);

  /* Retrieve the syscall number (first argument). */
  int syscall_num = get_argument(f, 0);
  struct thread *cur = thread_current();

  switch (syscall_num) {
    /* Terminate the current process. */
    case SYS_EXIT: {
      int status = get_argument(f, 1);
      sys_exit(status);
      break;
    }

    case SYS_WRITE:
    /* SYS_WRITE(fd, buffer, size): Write to console or file. */ 
    {
      int fd = get_argument(f, 1);
      const void *buffer = (void *)get_argument(f, 2);
      unsigned size = (unsigned)get_argument(f, 3);

      /* Validate whole buffer range before writing. */
      if (size != 0) {
        validate_range (buffer, size);
      }

      /* Perform the write and store number of bytes written. */
      f->eax = sys_write(fd, buffer, size);
      break;
    }

    case SYS_REMOVE:
    /* SYS_REMOVE(file): Delete a file from the filesystem. */
    {
      const char *file = (const char *) get_argument (f, 1);
      validate_str (file);
      lock_acquire (&filesys_lock);
      f->eax = filesys_remove (file);
      lock_release (&filesys_lock);
      break;
    }
  
    case SYS_FILESIZE:
    /* SYS_FILESIZE(fd): Get size of an open file. */
    {
      int fd = get_argument (f, 1);
      if (fd >= 2 && fd < FD_MAX && cur->fd_table[fd]) {
        lock_acquire (&filesys_lock);
        f->eax = file_length (cur->fd_table[fd]);
        lock_release (&filesys_lock);
      }
      else f->eax = -1;
      break;
    }
  
    case SYS_SEEK:
    /* SYS_SEEK(fd, position): Reposition read/write pointer. */
    {
      int fd = get_argument (f, 1);
      unsigned pos = (unsigned) get_argument (f, 2);
      if (fd >= 2 && fd < FD_MAX && cur->fd_table[fd]) {
        lock_acquire (&filesys_lock);
        file_seek (cur->fd_table[fd], pos);
        lock_release (&filesys_lock);
      }
      break;
    }
  
    case SYS_TELL:
    /* SYS_TELL(fd): Report current position in file. */
    {
      int fd = get_argument (f, 1);
      if (fd >= 2 && fd < FD_MAX && cur->fd_table[fd]) {
        lock_acquire (&filesys_lock);
        f->eax = file_tell (cur->fd_table[fd]);
        lock_release (&filesys_lock);
      }
      else f->eax = -1;
      break;
    }

    case SYS_EXEC:
    /* SYS_EXEC(cmd): Spawn a new process running cmd. */
    {
      const char *cmd = (const char *) get_argument (f, 1);
      validate_str (cmd);                      

      tid_t tid = process_execute (cmd);       
      if (tid == TID_ERROR)
          f->eax = -1;                        
      else
          f->eax = tid;                      
      break;
    }
  
    case SYS_CREATE:
    /* SYS_CREATE(file, size): Create a new file or truncate it. */
    {
      const char *file = (const char *)get_argument(f, 1);
      unsigned initial_size = (unsigned)get_argument(f, 2);
      validate_str(file);
      lock_acquire(&filesys_lock);
      f->eax = filesys_create(file, initial_size);
      lock_release(&filesys_lock);
      break;
    }

    case SYS_WAIT:
    /* SYS_WAIT(tid): Wait for a child process to exit. */
    {
      tid_t tid = (tid_t) get_argument (f, 1);
      f->eax = process_wait (tid);
      break;
    }


    case SYS_OPEN:
    /* SYS_OPEN(file): Open an existing file for reading/writing. */
    {
      const char *file = (const char *)get_argument(f, 1);
      validate_str(file); /* Validate path */
      lock_acquire(&filesys_lock);
      struct file *opened_file = filesys_open(file);
      lock_release(&filesys_lock);

      if (opened_file == NULL) {
        f->eax = -1; /* Failed to open */
      } else {
        int fd = cur->next_fd++;
        if (fd >= FD_MAX) {
          lock_acquire(&filesys_lock);
          file_close(opened_file);
          lock_release(&filesys_lock);
          f->eax = -1; /* Descriptor table full */
        } else {
          cur->fd_table[fd] = opened_file;
          f->eax = fd; /* Return new fd */
        }
      }
      break;
    }

    case SYS_CLOSE:
    /* SYS_CLOSE(fd): Close a previously opened file descriptor. */
    {
      int fd = get_argument(f, 1);
      if (fd >= 2 && fd < FD_MAX && cur->fd_table[fd] != NULL) {
        lock_acquire(&filesys_lock);
        file_close(cur->fd_table[fd]);
        lock_release(&filesys_lock);
        cur->fd_table[fd] = NULL;
      }
      break;
    }

    case SYS_READ:
    /* SYS_READ(fd, buffer, size): Read bytes from fd into buffer. */
    {
      int fd = get_argument(f, 1);
      void *buffer = (void *)get_argument(f, 2);
      unsigned size = (unsigned)get_argument(f, 3);

      /* Validate entire user buffer before reading. */
      if (size != 0) {
        validate_range (buffer, size);
      }

      if (fd == 0) {
        /* STDIN: read from keyboard one char at a time. */
        unsigned i;
        uint8_t *buf = (uint8_t *)buffer;
        for (i = 0; i < size; i++) {
          uint8_t *phys = pagedir_get_page(thread_current()->pagedir, buf + i);
          if (phys == NULL)
            sys_exit(-1);
          *phys = input_getc();
        }
        f->eax = size;
      }
      else if (fd >= 2 && fd < FD_MAX && cur->fd_table[fd] != NULL) {
        lock_acquire(&filesys_lock);
        f->eax = file_read(cur->fd_table[fd], buffer, size);
        lock_release(&filesys_lock);
      } else {
        f->eax = -1;
      }
      break;
    }

    default:
      sys_exit(-1);
  }
}

/*
  sys_exit:
    Terminates the current process, printing its name and exit status,
    storing the status in the thread structure, and then exiting the thread.
*/

void
sys_exit(int status)
{
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->exit_status = status;
  thread_exit();
}

/*
  sys_write:
    Implements the write(fd, buffer, size) syscall.
    - If fd == STDOUT, writes to the console.
    - Otherwise, validates the file descriptor and writes to the file.
    Returns the number of bytes written, or -1 on error.
*/

int
sys_write(int fd, const void *buffer, unsigned size)
{
  struct thread *cur = thread_current();

  if (fd == STDOUT_FILENO) {
    putbuf((char *)buffer, size);
    return size;
  } else if (fd >= 2 && fd < FD_MAX && cur->fd_table[fd] != NULL) {
    lock_acquire(&filesys_lock);
    int bytes_written = file_write(cur->fd_table[fd], buffer, size);
    lock_release(&filesys_lock);
    return bytes_written;
  }
  return -1;
}

/*
  validate_ptr:
    Verifies that a single user pointer is non-null, in user space,
    and mapped in the page directory. If not, terminates the process.
*/

static void validate_ptr(const void *uaddr)
{
  if (uaddr == NULL || !is_user_vaddr(uaddr) ||
      pagedir_get_page(thread_current()->pagedir, uaddr) == NULL) {
    sys_exit(-1);
  }
}

/*
  validate_range:
    Validates every page in the byte range [uaddr, uaddr + size - 1]
    by rounding down to the page boundary and stepping through each page.
*/

static void
validate_range (const void *uaddr, size_t size)
{
  if (size == 0) return;

  uintptr_t start = (uintptr_t) uaddr;
  uintptr_t end   = start + size - 1;            

  
  for (uintptr_t page = start & ~PGMASK; page <= end; page += PGSIZE)
    validate_ptr ((const void *) page);

  validate_ptr ((const void *) end);
}

/*
  validate_str:
    Walks a NUL-terminated string, validating each character’s page
    so that it doesn’t straddle an unmapped page boundary.
*/

static void
validate_str (const char *s)
{
  while (true)
    {
      validate_ptr (s);
      if (*s == '\0')
        break;
      
      s++;
    }
}

/*
  get_argument:
    Fetches the n-th 32-bit word argument from the user stack,
    validates that the entire 4-byte word lies within mapped user pages,
    and returns its value.
*/
static int
get_argument (struct intr_frame *f, int n)
{
  int *arg_ptr = (int *) f->esp + n;
  validate_range (arg_ptr, sizeof (int));
  return *arg_ptr;
}


