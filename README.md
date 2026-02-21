This is the analysis I prepared using WinDbg and viewing it through IDA, naturally and simply.
***

The disassembled usermode section of the syscall obtained on Win11 25H2:

```assembly
NtQueueApcThreadEx2:
    mov  r10, rcx                    ; [1] Store the first argument in r10
                                     ;     (syscall convention: rcx is overwritten!!!!)
    mov  eax, 173h                   ; [2] Syscall number = 0x173 for this specific build
    test byte ptr [7ffe0308h], 1     ; [3] SystemCall mode is being checked
                                     ;     SharedUserData->SystemCall
    jne  .via_int2e                  ; [4] If the bit is set → legacy path
    syscall                          ; [5] Quick way: SYSCALL instruction
    ret                              ;     Return from kernel - ntoskrnl.exe
.via_int2e:
    int  2Eh                         ; [6] The slow path: interruption :P
    ret                              ;   Objectively speaking, trash
```

In any case, it's the body, what's there to talk about?

```c
NTSTATUS __fastcall NtQueueApcThreadEx2(
    HANDLE       ThreadHandle,        // a1 — Target thread descriptor
    HANDLE       ReserveHandle,       // a2 — Reserve object descriptor (or NULL)
    ULONG        QueueUserApcFlags,   // a3 — Flags (0x1 = Special, 0x10000 = Force) HERE IT IS
    PVOID        ApcRoutine,          // a4 — Callback address
    PVOID        SystemArgument1,     // a5 — First argument
    PVOID        SystemArgument2,     // a6 — Second argument
    PVOID        SystemArgument3      // a7 — Third argument
)
```

Based on this, looking at IDA by chains, everything goes like this:

<img width="961" height="617" alt="image" src="https://github.com/user-attachments/assets/34f829c0-c1ce-4851-aa23-ffdf91ce1876" />

I started from the point where flag validation takes place.

```c
    BOOLEAN     isUserMode;           // v10 — APC mode: 1=User, 0=Kernel
    KPROCESSOR_MODE PreviousMode;     // Where the call came from
    BOOLEAN     isSpecialApc;         // v12 — Special User APC flag
    PETHREAD    TargetThread;         // v14 — Target thread object
    PKPROCESS   CallerProcess;        // Process — Calling process
    PKAPC       ApcObject;            // Pool2 — Allocated KAPC
    PKKERNEL_ROUTINE KernelRoutine;   // v17 — Kernel callback function
    PKRUNDOWN_ROUTINE RundownRoutine; // v18 — Cleanup function
    NTSTATUS    status;               // v19 — Operation result

    isUserMode = TRUE;  // Default — User Mode APC
    PreviousMode = KeGetCurrentThread()->PreviousMode;
    
    // Check that only valid flags are set
    // Valid: bit 0 (Special APC) and bit 16 (Force)
    // Mask 0xFFFEFFFE = all bits except 0 and 16
    if ((QueueUserApcFlags & 0xFFFEFFFE) != 0) {
        return STATUS_INVALID_PARAMETER;  // -1073741811 = 0xC000000D
    }
```

<img width="588" height="501" alt="image" src="https://github.com/user-attachments/assets/b3b4067f-0a42-4ce4-b4e2-09570325e886" />

Next, we have the definition of the APC type.

```c
    if ((QueueUserApcFlags & 1) == 0) {
        // Regular User APC (not Special ^_:)
        isSpecialApc = FALSE;
    }
    else {
        // Special User APC requested
        // IMPORTANT: Reserve Object CANNOT be used with Special APC
        if (ReserveHandle != NULL) {
            return STATUS_INVALID_PARAMETER;
        }
        isSpecialApc = TRUE;
    }
```

Next up is more fun: getting the object stream.

<img width="915" height="360" alt="image" src="https://github.com/user-attachments/assets/b3878e51-e56b-41bd-be15-fdb4c9fb8d49" />

```c
    TargetThread = NULL;
    
    status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_SET_CONTEXT,           // 0x10 — required access
        PsThreadType,                 // Object type
        PreviousMode,                 // Access check
        &TargetThread,                // Output pointer
        NULL                          // Handle Information
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
```

Next shock: Microsoft Corp. decided to protect this feature, specifically, that is to say....

```c
    // Check 1: CrossThreadFlags — APC disabled
    // Bit 10 (0x400) in CrossThreadFlags = APC queue disabled
    if ((TargetThread->CrossThreadFlags & 0x400) != 0) {
        status = STATUS_INVALID_PARAMETER_2;  // -1073741816 = 0xC0000008  
        goto Cleanup;
    }
   
    // Check 2: ARM/ARM64 process on x64 system (punch out way)
    // Checks CHPE (Compiled Hybrid PE) / ARM64EC scenario
    CallerProcess = KeGetCurrentThread()->ApcState.Process;
    
    if (CallerProcess->SomeField != 0) {  // Process[1].ReadyTime
        USHORT machineType = /* Process machine type */;
        
        // 332 = IMAGE_FILE_MACHINE_ARM (0x14C)
        // 452 = IMAGE_FILE_MACHINE_ARMNT (0x1C4) 
        if (machineType == 332 || machineType == 452) {
            
            ULONG64 threadInfo = TargetThread->SomeField;  // offset 68*8=0x220
            
            // Check that the target thread is compatible
            if (!*(PVOID*)(threadInfo + 784) ||          // +0x310
                *(USHORT*)(threadInfo + 1772) == 0x8664) // +0x6EC = AMD64
            {
                // APC routine address check for ARM→x64
                // -(a4 >> 2) <= 0xFFFFFFFF
                // This checks that the APC routine address
                // is within the valid 32-bit range [Holy shit]
                if ((ULONG64)(-((__int64)ApcRoutine >> 2)) <= 0xFFFFFFFF) {
                    status = STATUS_INVALID_PARAMETER_2;
                    goto Cleanup;
                }
            }
        }
    }
```

I'll provide the trash part, lazily showing the chain 

<img width="1124" height="625" alt="image" src="https://github.com/user-attachments/assets/6222b9bd-d292-4600-b0be-b2a696622cac" />

This APC has two initialization methods!!! 

```c
    if (ReserveHandle == NULL) {
        //  Option: Without Reserve Object
        
        // Allocate KAPC from pool
        // 0x41 = POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED
        ApcObject = (PKAPC)ExAllocatePool2(0x41, sizeof(KAPC), 'cpaK');
        
        if (!ApcObject) {
            status = STATUS_INSUFFICIENT_RESOURCES;  // -1073741801
            goto Cleanup;
        }
        
        // Select KernelRoutine and RundownRoutine
        // depending on the APC type
        
        if (isSpecialApc) {
            // Special UserAPC
            KernelRoutine  = KeSpecialUserApcKernelRoutine;
            RundownRoutine = ExFreePool;  // Just free up memory
            isUserMode     = FALSE;       // isSpecialApc XOR 1 = 0
            // BUT! isUserMode here means ApcMode
            // 0 = KernelMode in KeInitializeApc
            // This is the most interesting part— APC is set
            // as Kernel-mode APC, but with User callback!
        }
        else {
            // Regular User APC
            KernelRoutine  = PspUserApcKernelRoutine;
            RundownRoutine = ExFreePool;
            isUserMode     = TRUE;  // 1 = UserMode
        }
        
        goto InitializeAndInsert;
    }
    else {
        //  Another one with Reserve Object (guaranteed delivery, I believe)
        
        PVOID ReserveObject = NULL;
        
        status = ObReferenceObjectByHandle(
            ReserveHandle,
            2,                                    // Minimum access
            PspMemoryReserveObjectTypes,          // Reserve Object type
            PreviousMode,
            &ReserveObject,
            NULL
        );
        
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
        
        // Atomically capture Reserve Object
        // CompareExchange: if 0 → set to 1 (busy)
        if (InterlockedCompareExchange(
                (volatile LONG*)ReserveObject, 1, 0) != 0) {
            // Already occupied by someone else
            ObDereferenceObject(ReserveObject);
            status = STATUS_INVALID_PARAMETER;  // -1073741584
            goto Cleanup;
        }
        
        // Reserve Object contains a built-in KAPC with an offset of +8
        ApcObject      = (PKAPC)((PUCHAR)ReserveObject + 8);
        KernelRoutine  = PspUserApcReserveKernelRoutine;
        RundownRoutine = PspUserApcReserveRundownRoutine;
        
        goto InitializeAndInsert;
    }
    
InitializeAndInsert:
```

And then, deeper... KAPC initialization!

```c
    KeInitializeApc(
        ApcObject,              // Pointer to KAPC
        TargetThread,           // Target thread
        OriginalApcEnvironment, // 0 = Original environment
        KernelRoutine,          // Kernel processing function
        RundownRoutine,         // Function at thread completion
        ApcRoutine,             // Any payload as a loader
        isUserMode,             // APC Mode (0=Kernel for Special!)
        SystemArgument1         // First argument (NormalContext)
    );
```

After initialization, a check is performed with the flag “16”. - ForceFlag, 0x10000

```c
    // Flag 0x10000 = QUEUE_USER_APC_FLAGS_FORCE
    // Sets the bit in KAPC.SpareByte0
    if ((QueueUserApcFlags & 0x10000) != 0) {
        ApcObject->SpareByte0 |= 1;
        // This allows the APC to be delivered even
        // in certain situations when the thread is frozen
    }
```

Nothing else definite, insertion into the queue

```c
    if (KeInsertQueueApc(
            ApcObject,
            SystemArgument2,    // Second argument
            SystemArgument3,    // Third argument
            0                   // IO_NO_INCREMENT (priority)
        )) 
    {
        // Success — APC in queue
        status = STATUS_SUCCESS;
    }
    else {
        // Thread terminates or APC cannot be delivered
        // Call RundownRoutine for cleanup
        RundownRoutine(ApcObject);  // guard_dispatch_icall
        status = STATUS_UNSUCCESSFUL;  // -1073741823 = 0xC0000001
    }
    
Cleanup:
    ObDereferenceObject(TargetThread);
    return status;
```

Based on all this chatter, we draw a conclusion.

> `KeInitializeApc(..., Mode = KernelMode)` // as a key  
> → APC is placed in the KernelMode queue  
> → But NormalRoutine (payload) points to the usermode address  
> → KernelMode APC is delivered on ANY return from the kernel  
> → `KeSpecialUserApcKernelRoutine` switches the context to usermode and calls the payload via `KiUserApcDispatcher`

This is a hybrid: APC with kernel priority, but with a callback in usermode.

Regarding the question of why `PspUserApcReserveKernelRoutine` is needed, it functions as a liberator for `KAPC`. (Resets `InterlockedFlag`)
