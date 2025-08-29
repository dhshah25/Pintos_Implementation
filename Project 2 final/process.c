#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/timer.h"  /* For timer_sleep in process_wait() */

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

struct child_rec
{
  tid_t              tid;          /* Child TID                     */
  int                exit_status;  /* Set by child in process_exit  */
  bool               waited;       /* Has parent already waited?    */
  struct semaphore   dead;         /* Parent blocks here            */
  struct list_elem   elem;         /* In parent->child_list         */
};

/*
  process_execute:  
    Safely copies the entire command line into a new page, extracts the 
    bare program name for the thread title, spawns the loader thread
    (start_process), and then blocks until that child reports whether
    its load() succeeded.  Returns the child’s TID on success, or
    TID_ERROR if the thread couldn’t be created or load() failed.
*/

tid_t
process_execute (const char *cmdline)
{
  /* Copy full command line to avoid races with the parent’s stack. */
  char *cmdline_copy;
  tid_t tid;
  cmdline_copy = palloc_get_page(0);
  if (cmdline_copy == NULL)
    return TID_ERROR;
  strlcpy(cmdline_copy, cmdline, PGSIZE);

  /* Extract program name (first token) for naming the thread. */
  char tmp[NAME_MAX + 1];
  strlcpy(tmp, cmdline, sizeof tmp);

  char *space = strchr(tmp, ' ');
  if (space != NULL)
    *space = '\0';

  /* Spawn the loader thread, passing our copy of cmdline. */
  tid = thread_create(tmp, PRI_DEFAULT, start_process, cmdline_copy);

  if (tid == TID_ERROR)
  {
    palloc_free_page(cmdline_copy);
    return TID_ERROR;
  }

  /* Parent–child handshake: wait for the child to signal load() result. */
  struct thread *child = get_thread_by_tid(tid); 
  sema_down(&child->load_sema); 
  
  /* If child failed to load, return error. */
  if (!child->load_success) {
    return TID_ERROR;
  }
  return tid;
}

/*
  start_process:  
    Runs in the newly created thread.  Builds an initial CPU register
    frame (intr_frame), calls load() to map the ELF binary into memory
    and set up the user-mode stack with arguments, signals the parent
    on success or failure, and on success jumps into user mode via
    intr_exit().
*/

static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_; /* Holds the registers for intr_exit */
  bool success;

  /* Zero and initialize user-mode segments and flags. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  /* Attempt to load the executable and build its stack. */
  success = load (file_name, &if_.eip, &if_.esp);

  /* Wake up parent and record load success or failure. */
  struct thread *cur = thread_current ();
  cur->load_success = success;  
  sema_up(&cur->load_sema);     

  /* Free our copy of the command line. */
  palloc_free_page (file_name);

  /* If load failed, terminate this thread. */
  if (!success)
    thread_exit ();

  /* If load succeeded, enter user mode by “returning” from interrupt. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}




/*
 * process_wait:
 * Placeholder for waiting on a child process. Sleeps for a fixed
 * number of timer ticks to avoid busy-waiting.
 */

int
process_wait (tid_t child_tid UNUSED) 
{
  int wait_ticks = 100;  /* wait for 100 timer ticks */
  while (wait_ticks > 0)
    {
      timer_sleep (1); /* Sleep for 1 tick */
      wait_ticks--;
    }
  return -1;
}



/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}



/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Modified prototype of setup_stack:
   Now takes the full command line so that it can do argument passing.
 */
static bool setup_stack (void **esp, const char *cmdline);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/*
  load:
    Opens and parses the command line to extract the binary name,
    opens the ELF executable, verifies its header, and loads each
    PT_LOAD segment into the process’s page table.  After mapping
    all segments, it calls setup_stack() to build the initial
    user-mode stack (pushing argv, argc, etc).  On success, *eip
    is set to the program’s entry point and *esp to the top of
    the new stack.  Returns true if everything loads correctly,
    false on any error.
*/
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Create and activate a new page directory for this process. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Extract the program name (first token) and open the ELF file. */
  {
    char *fn_copy_aux = malloc(strlen(file_name) + 1);
    if (fn_copy_aux == NULL)
      goto done;
    strlcpy(fn_copy_aux, file_name, strlen(file_name) + 1);
    char *save_ptr;
    char *token = strtok_r(fn_copy_aux, " ", &save_ptr);
    file = filesys_open(token);
    if (file == NULL)
      {
        printf("load: %s: open failed\n", token);
        free(fn_copy_aux);
        goto done; 
      }
    free(fn_copy_aux);
  }

  /* Read and verify the ELF header to ensure this is a valid binary. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Iterate over program headers, loading each PT_LOAD segment. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      /* Bounds check and read this program header. */
      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);
      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;


      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* These segments are ignored. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          /* Unsupported segment types. */
          goto done;
        case PT_LOAD:
          /* Only load valid, in-range segments. */
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
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
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
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

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs.
*/
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
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

/*
  setup_stack:
    Allocates one zeroed page at the top of user virtual memory to serve
    as the initial stack. Then parses the command line to extract arguments,
    and arranges them on the stack in the exact format a C program expects:
      - Copies each argument string (in reverse order) onto the stack.
      - Adds padding to align the stack pointer to a multiple of 4 bytes.
      - Pushes a null pointer sentinel.
      - Pushes the addresses of each argument string (again in reverse order).
      - Pushes the address of this argv array.
      - Pushes the argument count (argc).
      - Pushes a fake return address (0).
    On success, *esp points to the bottom of this layout, and the function
    returns true. Returns false if any allocation fails.
*/

static bool
setup_stack (void **esp, const char *cmdline) 
{
  uint8_t *kpage;
  bool success = false;

  /* Allocate a zeroed page for the initial stack frame. */
  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    /* Map that page at the top of user space. */
    success = install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
    if (success) {
      /* Start with the stack pointer at PHYS_BASE. */
      *esp = PHYS_BASE;

      /* Align esp down to a 4-byte boundary. */
      uintptr_t esp_int = (uintptr_t) *esp;
      esp_int &= ~0x3;
      *esp = (void *) esp_int;

      /* Make a writable copy of cmdline for tokenization. */
      #define MAX_ARGS 128
      char *argv[MAX_ARGS];
      int argc = 0;
      char *cmdline_copy = palloc_get_page(0);
      if (cmdline_copy == NULL)
        return false;
      strlcpy(cmdline_copy, cmdline, PGSIZE);

      /* Split the copy into individual argument strings. */
      char *save_ptr;
      char *token = strtok_r(cmdline_copy, " ", &save_ptr);
      while (token != NULL && argc < MAX_ARGS) {
        argv[argc++] = token;
        token = strtok_r(NULL, " ", &save_ptr);
      }

      /* Push each argument string onto the stack in reverse order,
         recording its address in arg_addresses[]. */
      void *arg_addresses[MAX_ARGS];
      for (int i = argc - 1; i >= 0; i--) {
        size_t len = strlen(argv[i]) + 1;
        *esp -= len;
        memcpy(*esp, argv[i], len);
        arg_addresses[i] = *esp;
      }

      /* Add padding to align the stack pointer again. */
      uintptr_t esp_val = (uintptr_t)(*esp);
      size_t padding = esp_val % 4;
      if (padding) {
        *esp -= padding;
        memset(*esp, 0, padding);
      }

      /* Push a null pointer sentinel to terminate argv. */
      *esp -= sizeof(char *);
      memset(*esp, 0, sizeof(char *));

      /* Push the addresses of each argument string (reverse order). */
      for (int i = argc - 1; i >= 0; i--) {
        *esp -= sizeof(char *);
        memcpy(*esp, &arg_addresses[i], sizeof(char *));
      }

      /* Push the pointer to argv (i.e., the address of arg_addresses[0]). */
      void *argv_addr = *esp;
      *esp -= sizeof(char **);
      memcpy(*esp, &argv_addr, sizeof(char **));

      /* Push the argument count (argc). */
      *esp -= sizeof(int);
      memcpy(*esp, &argc, sizeof(int));

      /* Push a fake return address (0) so user code can call main(). */
      *esp -= sizeof(void *);
      memset(*esp, 0, sizeof(void *));

      /* Clean up the temporary command-line copy. */
      palloc_free_page(cmdline_copy);
    } else {
      /* If mapping failed, free the page. */
      palloc_free_page(kpage);
    }
  }
  return success;
}



/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails.
*/
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}