# Keylogger Proof of Concept

This project was initially created as a learning exercise to deepen my understanding of:

- C programming  
- Low-level system concepts  
- Operating system security principles  

The **keylogger** is a proof-of-concept developed entirely from scratch. The primary objective was to avoid the use of high-level **Win32 API** functions, which are commonly detected by modern antimalware solutions such as **antivirus programs** and **EDRs** (Endpoint Detection and Response).

---

## 1. Core Components

This repository consists of two components that work together as part of a malware deployment chain:

- **Injector** – A standalone executable responsible for loading the DLL and injecting shellcode into a target process.  
- **Keylogger** – A fully self-contained keylogger compiled as shellcode. It is injected and executed within the context of the target process.

Each component serves a distinct role and is described below.

---

## 2. How the Injector Works

The injector is designed to operate in conjunction with **DLL-based malware techniques**, such as *DLL proxying*.

While this project does not include a real-world deployment example, the intended usage is as follows:

1. The injector loads a specially crafted DLL.
2. The DLL then injects the compiled **keylogger shellcode** into a target process (same or remote).
3. The shellcode runs in a separate thread within that process.

---

## 3. How the Keylogger Works

The injected shellcode contains a complete, self-contained keylogger. Its architecture:

- **Main Thread** – Handles low-level keystroke capture.
- **Secondary Thread** – Periodically sends logged data along with metadata (user's UUID) to a remote server.

---

## 4. Persistence via Regedit

Persistence is implemented through modifications to the Windows **registry** (`regedit`):

- Each infected user is uniquely identified by a **generated UUID**.
- Logged keystrokes are supposed to be sorted and stored on the server in files refering to UUID.

---

## 5. Used Evasion Techniques

### Avoiding High-Level Win32 API

The project avoids standard API calls and instead uses **indirect syscalls** to bypass EDR monitoring mechanisms.  
EDRs typically hook functions inside `ntdll.dll` to detect suspicious behavior in user space.  
This implementation jumps directly to unhooked system call stubs to evade detection.

---

### Common Suspicious Syscalls

Below are examples of system calls often flagged by EDRs — especially when used with specific parameters:

#### `NtAllocateVirtualMemory`

> Allocates memory in the current or remote process.

- **Suspicious When**:
  - Using `PAGE_EXECUTE_READWRITE`.
  - Targeting a *remote* process.

- **Used For**: Shellcode allocation during injection.

---

#### `NtWriteVirtualMemory`

> Writes data into the memory space of another process.

- **Suspicious When**:
  - Writing binary payloads (e.g. shellcode).
  - Address belongs to freshly allocated memory.

- **Used For**: Payload injection.

---

#### `NtProtectVirtualMemory`

> Changes memory protection on a memory region.

- **Suspicious When**:
  - Changing protection to `PAGE_EXECUTE_READ` or `PAGE_EXECUTE_READWRITE`.

- **Used For**: Making shellcode executable after writing it.

---

#### `NtCreateThreadEx`

> Creates a thread in the current or a remote process.

- **Suspicious When**:
  - Start address points to injected shellcode.
  - Process handle refers to a different process.

- **Used For**: Triggering execution of injected code.

---

### Staging Payload

Hardcoding a keylogger payload directly into the binary would be easily flagged by static analysis tools and antivirus engines due to its obvious malicious footprint.
To evade detection, the payload is dynamically staged — downloaded at runtime from a remote server using low-level socket communication.
The staging mechanism includes a retrying system to handle temporary network failures, ensuring higher reliability and operational resilience. 

---

### Replacing common High-Level Win32 API with custom versions

Common high-level Windows API functions like `GetModuleHandleW` and `GetProcAddress` are frequently monitored or hooked by EDR solutions.
To bypass such monitoring, custom equivalents of these functions were implemented from scratch, directly parsing Windows internal structures such as the PE headers, PEB, and module lists.

---

### 9. To Do

Implement string obfuscation.

Add self-deletion mechanism.

Unpacking mechanism (?).

Simulation of an attack using DLL proxying or a similar technique.

Add smooth handling of certain operations with retry logic instead of exiting immediately.

Replace user identification with UUID stored in the registry.

---

### 10. Notes & Considerations

Some functions are duplicated between the injector and keylogger components, as they are compiled separately and operate as independent entities.
