/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"


/* Compare two threads for ordering in a semaphore's waiters list. If priorities 
are equal, the thread with the lower arrival_order comes first otherwise 
the thread with the higher priority comes first.*/
static bool
sema_waiter_comparator (const struct list_elem *a,
                                    const struct list_elem *b,
                                    void *aux UNUSED)
{
  // Treat the list elements as threads.
  struct thread *t1 = list_entry(a, struct thread, elem);
  struct thread *t2 = list_entry(b, struct thread, elem);
  if (t1->priority == t2->priority)
    return t1->arrival_order < t2->arrival_order;
  
  // Higher priority threads should come first.
  return t1->priority > t2->priority;
}
     
void
sema_init (struct semaphore *sema, unsigned value) 
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init (&sema->waiters);
}

/* This is down operation on semaphore. If the semaphore's value is 0, insert 
the current thread into the waiters list and block it until the semaphore is available.*/
void
sema_down (struct semaphore *sema)
{
  enum intr_level old_level;

  ASSERT(sema != NULL);
  ASSERT(!intr_context());

  old_level = intr_disable();
  
  // Block while the semaphore value is zero.
  while (sema->value == 0) {
    list_insert_ordered(&sema->waiters, &thread_current()->elem, sema_waiter_comparator, NULL);
    thread_block();
  }

  sema->value--;
  intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema)
{
  enum intr_level old_level;
  bool success;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (sema->value > 0)
  {
    sema->value--;
    success = true;
  }
  else
    success = false;
  intr_set_level(old_level);

  return success;
}
  
/* This is up operation on semaphore. This will Increment the semaphore value and 
unblock the highest-priority waiting thread, if any and yield the CPU if necessary*/
void
sema_up (struct semaphore *sema)
{
  enum intr_level old_level;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (!list_empty(&sema->waiters)) {
  
    // Ensure the highest priority waiter is at the front.
    list_sort(&sema->waiters, sema_waiter_comparator, NULL);
    struct thread *t = list_entry(list_pop_front(&sema->waiters), struct thread, elem);
    thread_unblock(t);
  }
  sema->value++;
  intr_set_level(old_level);
  try_thread_yield();
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) 
{
  struct semaphore sema[2];
  int i;

  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) 
    {
      sema_up (&sema[0]);
      sema_down (&sema[1]);
    }
  printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) 
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) 
    {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock)
{
  ASSERT(lock != NULL);
  lock->holder = NULL;
  sema_init(&lock->semaphore, 1);
}


/* This is to acquire a lock. If the lock is already held, record the current 
thread's donation information and donate priority if needed, then block until the 
lock is available. Here, donation propagation remains active until 
the donation chain is done.*/
void
lock_acquire (struct lock *lock)
{
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(!lock_held_by_current_thread(lock));
  struct thread *curr = thread_current();
  if (lock->holder != NULL) {
    curr->waiting_lock = lock;

    // Record the thread to propagate donations to.
    curr->donation_target = lock->holder; 
    if (!thread_mlfqs) {
      donate_priority(curr, lock->holder, lock);
    }
  }
  sema_down(&lock->semaphore);

  /* Clear waiting_lock now that we are unblocked. */
  curr->waiting_lock = NULL;

  lock->holder = curr;
  
  // Add this lock to the list of locks held by the current thread.
  list_push_back(&curr->locks_held, &lock->elem);
}
  
  

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock)
{
  bool success;

  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success)
    lock->holder = thread_current ();
  return success;
}

/* This will release the lock. It will remove any donation records associated 
with the lock, reset the current thread's priority, update the thread's 
effective priority, and then unblock a waiting thread.*/
void
lock_release (struct lock *lock)
{
  ASSERT(lock != NULL);
  ASSERT(lock_held_by_current_thread(lock));
  struct thread *curr = thread_current();
  
  // Remove the lock from the list of locks held.
  list_remove(&lock->elem);
  if (!thread_mlfqs) {
    remove_donations(curr, lock);
    curr->priority = curr->real_priority;
    update_priority(curr);
  }
  lock->holder = NULL;
  sema_up(&lock->semaphore);
  
  // If no locks remain that could affect donation, clear donation_target.
  if (list_empty(&curr->locks_held))
    curr->donation_target = NULL;
}
  

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock)
{
  ASSERT(lock != NULL);

  return lock->holder == thread_current();
}

/* One semaphore in a list. */

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond)
{
  ASSERT (cond != NULL);

  list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */

/* Compare two semaphore elements by their stored priority and 
is used to order waiters on a condition variable.*/
static bool
compare_semaphore_elem_by_priority (const struct list_elem *a,
                                    const struct list_elem *b,
                                    void *aux UNUSED)
{
  struct semaphore_elem *sema_a = list_entry(a, struct semaphore_elem, elem);
  struct semaphore_elem *sema_b = list_entry(b, struct semaphore_elem, elem);
  return sema_a->priority < sema_b->priority;
}

/* Wait on a condition variable. Here, the current thread releases the 
given lock, then blocks until the condition is signaled. Once signaled, it 
acquires the lock again before returning.*/
void
cond_wait (struct condition *cond, struct lock *lock)
{
  struct semaphore_elem waiter;
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  // Initialize a semaphore element with an initial value of 0.
  sema_init(&waiter.semaphore, 0);

  // Set the waiter’s priority to the current thread's effective priority.
  waiter.priority = thread_get_priority();

  // Insert the waiter into the condition variable's waiters list in order.
  list_insert_ordered(&cond->waiters, &waiter.elem,
                      compare_semaphore_elem_by_priority, NULL);

  // Release the lock and block on the semaphore.
  lock_release(lock);
  sema_down(&waiter.semaphore);

  lock_acquire(lock);
}

/* This is to signal a condition variable. Wake up one thread 
waiting on the condition, if any and the highest priority waiting thread is selected*/
void
cond_signal (struct condition *cond, struct lock *lock UNUSED)
{
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));
  if (!list_empty(&cond->waiters)) {
    // Pop the highest-priority waiter from the condition's waiters list.
    struct semaphore_elem *waiter = list_entry(list_pop_back(&cond->waiters),
                                                  struct semaphore_elem, elem);
    sema_up(&waiter->semaphore);
  }
}
/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock)
{
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  while (!list_empty(&cond->waiters))
    cond_signal(cond, lock);
}

  