# Keylogger Proof of Concept Template

This project was created as a learning exercise to deepen understanding of:

- C programming  
- Low-level system concepts  
- Operating system security principles  

The keylogger is a proof-of-concept developed from scratch. The main goal was to avoid using high-level Win32 API functions often flagged by modern antivirus and EDR solutions.

---

## Intended Use and Technique

The intended deployment method in a real-world simulation or red team context is **DLL proxying**. This involves hijacking legitimate DLLs used by applications to inject functionality stealthily.

This project is a technical template demonstrating core functionality under controlled conditions. Additional integration steps would be required for real-world usage and have been omitted deliberately to prevent misuse.

Key missing steps include:  
- Matching exported functions to preserve app behavior  
- Ensuring proper initialization timing  

These details are application-specific and partially excluded.

---

## Ethical Disclosure

For ethical and legal reasons, full plug-and-play functionality is not implemented.  
The project contains no self-propagation, stealth installation, persistence, or autonomous execution.

It is intended solely for educational and research purposes.  
Use outside lawful, explicit, controlled environments is strongly discouraged.

---

## 1. Core Components

This repository contains three components that form the malware deployment chain:

- **Injector** – Loads the DLL and injects shellcode into the target process.  
- **Keylogger** – Self-contained keylogger shellcode executed in the target process context.  
- **Server** – TCP server sending the keylogger payload and collecting logged keystrokes tagged by unique user IDs.

More on the server can be found here: [server/README.md](https://github.com/x03xd/keyloggerServer/blob/main/README.md)

---

## 2. How the Injector Works

This proof-of-concept uses DLL proxying to execute code inside a target process.

Example scenario: Discord. The attack replaces the `libEGL.dll` in Discord’s install folder:

1. The original `libEGL.dll` is renamed to preserve functionality.  
2. A malicious DLL named `libEGL.dll` is placed instead.  
3. The malicious DLL exports and forwards all functions to the original DLL to keep app behavior intact.  
4. In the malicious DLL’s `DllMain`, after app initialization, injector code runs and injects the keylogger shellcode into Discord’s memory.

From the attacker’s perspective, this works well because Discord is often installed in the user’s local app data directory (e.g., `C:\Users\<username>\AppData\Local\Discord\app-1.0.9200`), which doesn’t require elevated privileges to modify.

An alternative technique is DLL load order hijacking, placing a malicious DLL with a common name in the application directory so it loads before the legitimate one if the full path isn’t specified.

---

## 3. How the Keylogger Works

The injected shellcode implements a keylogger with:

- A main thread capturing low-level keystrokes.  
- A secondary thread periodically sending logged data with a unique UUID to a remote TCP server.

---

## 4. Persistence via Windows Registry

Persistence is achieved by modifying the Windows registry:  

- Each infected user has a unique UUID.  
- Logged keystrokes are stored server-side in files indexed by these UUIDs.

---

## 5. Evasion Techniques

### Avoiding High-Level Win32 API

The project uses indirect syscalls instead of standard Win32 API calls to bypass EDR hooks often placed on common API functions inside `ntdll.dll`.

### Common Suspicious Syscalls

Examples include:  

- `NtAllocateVirtualMemory` — Allocates executable memory, suspicious if in a remote process.  
- `NtWriteVirtualMemory` — Writes shellcode to memory.  
- `NtProtectVirtualMemory` — Changes memory protection to executable.  
- `NtCreateThreadEx` — Starts a thread at injected shellcode.

### Dynamic Payload Staging

The keylogger payload is not hardcoded but downloaded at runtime from a remote server to avoid static detection.

### Custom API Implementations

Functions like `GetModuleHandleW` and `GetProcAddress` are implemented manually by parsing PE headers and the Process Environment Block (PEB) to avoid detection.

---

## 6. Versions and Environment

- **Windows versions tested:** Windows 10.0.19045.6093
- **Compiler:** GCC 7.3.0 (MinGW-w64)  
- **Assembler:** NASM 2.16.01 
- **Shellcode converter tool:** [TheWover/donut](https://github.com/TheWover/donut)

---

## 7. To Do

- Implement advanced string obfuscation to improve stealth  
- Add a self-deletion mechanism to automatically remove the binary from disk **if a critical error prevents the malware from functioning properly** (e.g., incompatible environment).
- Improve robustness with retry logic on critical operations  

---

## 8. Notes and Considerations

- Some functions are duplicated in the injector and keylogger as they are compiled separately and run independently.  
- This project is for educational use only. Usage for malicious purposes is illegal and unethical.
