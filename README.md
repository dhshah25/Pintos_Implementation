# Pintos Implementation

Implemented Pintos OS features including alarm clock (sleep list, no busy-wait), priority-aware semaphores/condvars, full nested priority donation, MLFQS scheduler with fixed-point math, process creation with argument passing, syscall handling with per-process FDs, global FS lock, and safe user-mode exception handling.

## Highlights
- **Alarm Clock:** `timer_sleep()` via ordered sleep list (no busy-wait).
- **Priority Aware Sync:** `sema_up()` / `cond_signal()` wake highest priority.
- **Priority Donation:** Nested donation on `lock_acquire()` / restore on release.
- **MLFQS:** 4.4BSD formulas w/ fixed-point (`load_avg`, `recent_cpu`, priority).
- **Process Exec & Args:** Parent–child load handshake; argv/argc pushed on stack.
- **Syscalls:** Safe dispatcher (0x30); `exit`, `exec`, `wait`, file ops (`open/close/read/write/create/remove/...`) guarded by global FS lock.
- **FD Table:** Per-process descriptors with lookup and cleanup.
- **User Exceptions:** Kill misbehaving user processes; kernel faults panic.

## Build & Test (example)
```bash
# threads / userprog / filesys as applicable
cd src/threads && make check
cd ../userprog && make check
cd ../filesys && make check
