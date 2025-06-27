

This project was initially created as a learning exercise to deepen my understanding of C programming, low-level system concepts, and operating system security principles.

The keylogger is a proof of concept developed entirely from scratch, with the primary goal of avoiding the use of high-level Win32 API functions, which are commonly detected by various antimalware solutions such as antivirus programs and EDRs. Additionally, other evasion techniques are planned for implementation in the future, including string obfuscation, packing, and more.



1. THERE ARE TWO CORE COMPONENTS
This repository consists of two separate components that work together as part of a malware deployment chain:
    Injector – a standalone executable responsible for loading the DLL and injecting shellcode into a target process.
    Keylogger – a fully self-contained keylogging component, compiled as shellcode, which is injected and executed within the context of the target process.
Each component serves a distinct role and is described in detail below.

2. HOW INJECTOR WORKS
The injector is intended to be used in conjunction with a DLL-based malware technique,
such as DLL proxying.
There is no full-fledged solution or even an example demonstrating how to use this in a
real-world attack scenario.
The basic setup involves a program that, upon execution, loads the DLL as a dynamic
library and then injects shellcode — preferably into the same process or even another
one, assuming it is running.
The shellcode consists of a compiled keylogger component that runs in a separate
thread within the target process.

3. HOW KEYLOGGER WORKS
As mentioned above, the shellcode is a complete keylogger.
The keylogger's main thread provides core keylogging functionality.
Additionally, a secondary thread — nested within the main keylogger thread
(since the entire keylogger itself runs as a secondary thread inside the target
process) — periodically sends the captured keystrokes along with identifying metadata.
The transmissions are delayed at random or configurable intervals to evade
detection mechanisms that monitor consistent outbound traffic patterns.

4. REGEDIT
The persistence mechanism is implemented through modifications to the regedit.
Each infected user is uniquely identified using a generated UUID.
The server is designed to receive periodic requests containing this identifier and subsequently stores the captured keystrokes in files named according to the associated UUID.

to do
5. USED EVASION TECHNIQUES

The most important technique used to avoid detection by EDR programs is invoking indirect syscalls instead of basic Win32 API calls.
This technique is particularly common in real-time EDRs, which monitor and analyze API calls through the use of specialized hooks, typically placed inside ntdll.dll.
These hooks intercept system calls before they reach the kernel, allowing the EDR to inspect, log, or block suspicious behavior in user mode.
Unfortunately, most of API calls used in a malware development are considered suspicious, especially if some of their parameters indicate higher-privilege operations, for instance:

NtAllocateVirtualMemory
Allocates memory in a local or remote process.
    ⚠️ Suspicious when:
        PAGE_EXECUTE_READWRITE is used.
        Target is a remote process.
    🎯 Used for: shellcode allocation in injection or reflective loading.


NtWriteVirtualMemory
Writes data to a remote process's memory.
    ⚠️ Suspicious when:
        Writing binary payload (e.g., shellcode).
        Target address is recently allocated memory.
    🎯 Used for: injecting code into remote memory.


NtProtectVirtualMemory
Changes memory protection flags.
    ⚠️ Suspicious when:
        Changing to PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE.
    🎯 Used for: making shellcode executable after injection.


NtCreateThreadEx
Creates a thread in a local or remote process.
    ⚠️ Suspicious when:
        Start address points to injected shellcode.
        Process handle ≠ current process.
    🎯 Used for: executing injected payloads.


Moreover, there are plenty 


regedit.h





self deletation mechanism
payload staging
string obfuscation 
