# 🧩 Keylogger Proof of Concept Template

This project was initially created as a learning exercise to deepen my understanding of:

- C programming  
- Low-level system concepts  
- Operating system security principles  

The **keylogger** is a proof-of-concept developed entirely from scratch. The primary objective was to avoid using high-level **Win32 API** functions, which are commonly flagged by modern antimalware solutions, such as antivirus software and **EDRs** (Endpoint Detection and Response).

---

## 🎯 Intended Use & Technique

The intended deployment technique for this keylogger, in a real-world malware simulation or red teaming context, would be through **DLL proxying**. This approach allows injecting functionality by hijacking legitimate DLLs used by applications, providing stealth and persistence.

However, this project is intended as a **technical template or foundation** — it demonstrates core functionality that works under controlled conditions, but **additional steps would be required** to make it function end-to-end in a realistic attack scenario.

> ❌ These steps were **deliberately omitted to prevent misuse**.

In particular, in a real-world case such as DLL injection via **DLL proxying** into a target application (e.g. Discord or another GUI app), several integration steps would be necessary to ensure the keylogger interacts properly with the host process.

This includes:
- 🧩 Matching exported functions to preserve legitimate app behavior,
- 🕒 Ensuring proper initialization timing,
- 📦 Adapting the logging mechanism so that it runs reliably within the memory and execution context of the target.

These details are **application-specific** and have been intentionally left out to avoid facilitating malicious use.

---

## ⚠️ Ethical Disclosure

For ethical and legal reasons, **full plug-and-play functionality has not been implemented**.  
This project does not contain self-propagation, stealth installation, persistence mechanisms, or any form of autonomous execution.

It is designed purely for **educational and research purposes**.  
Any use of this code outside of lawful, explicit, and controlled environments is strictly discouraged.

> ⚠️ **Do not use this project for malicious purposes. You are responsible for complying with all applicable laws.**

---

## 1. 🧩 Core Components

This repository consists of three components that work together as part of a malware deployment chain:

- **Injector** – A standalone executable responsible for loading the DLL and injecting shellcode into a target process.  
- **Keylogger** – A fully self-contained keylogger compiled as shellcode. It is injected and executed within the context of the target process.
- **Server** – A TCP-based server responsible for:
  - Sending the keylogger payload to connecting clients,
  - Collecting keystrokes sent back by infected machines, tagged with unique `userId`s for persistence and identification.

👉 **More details about the server component can be found here:** [server/README.md](https://github.com/x03xd/keyloggerServer/blob/main/README.md)

---

## 2. 🚀 How the Injector Works

In this proof-of-concept, the **DLL proxying technique** is used as the method of code execution and injection into a target process.

In the demonstrated scenario, the target application was **Discord**. The attack involved **placing a malicious DLL** in Discord’s installation directory and exploiting the way Windows resolves and loads DLLs:

1. The original `libEGL.dll` (used legitimately by Discord) was **renamed** — e.g., to `libEGL-original-but-renamed.dll` — to preserve its functionality without breaking the application.
2. A **malicious DLL** was crafted and named `libEGL.dll`, matching the exact name expected by the application.
3. A `.def` file was added during compilation to **export and forward all functions** to the renamed original DLL (`libEGL-original-but-renamed.dll`). This maintains the normal behavior of the host application.
4. In the **`DllMain` entry point** of the malicious DLL, **custom code is executed after the legitimate application logic is initialized** — this ensures stability before proceeding with injection. At this point, the injector loads and executes the keylogger shellcode directly into Discord’s memory space.

📂 From the attacker's perspective, this works particularly well because **the Discord installation is often located in the user’s local app data directory**, such as:

- C:\Users\<username>\AppData\Local\Discord\app-1.0.9200

🧩 Additionally, instead of directly replacing DLL names, an attacker can experiment with **DLL load order hijacking**, where a malicious DLL with a commonly used name is placed in the application directory. If the target binary does not fully qualify the DLL path, Windows will resolve the local copy first — effectively loading the attacker’s version.

This method is highly dependent on the application’s loading behavior and is a common technique for stealthy execution and persistence.

---

## 3. 🧠 How the Keylogger Works

The injected shellcode contains a complete, self-contained keylogger. Its architecture includes:

- 🧵 **Main Thread** – Handles low-level keystroke capture.
- 🔁 **Secondary Thread** – Periodically sends logged data along with metadata (user's UUID) to a remote L4 TCP server.

---

## 4. 🔗 Persistence via Regedit

Persistence is implemented through modifications to the Windows **registry** (`regedit`):

- 🆔 Each infected user is uniquely identified by a **generated UUID**.
- 🗃️ Logged keystrokes are organized and stored server-side in files mapped to individual UUIDs.

---

## 5. 🛡️ Evasion Techniques

### 🚫 Avoiding High-Level Win32 API

The project avoids standard API calls and instead uses **indirect syscalls** to bypass EDR monitoring mechanisms.  
EDRs typically hook functions inside `ntdll.dll` to detect suspicious behavior in user space.  
This implementation jumps directly to unhooked system call stubs to evade detection.

---

### 🧨 Common Suspicious Syscalls

Below are examples of system calls often flagged by EDRs — especially when used with specific parameters:

#### 📦 `NtAllocateVirtualMemory`
> Allocates memory in the current or remote process.

- **Suspicious When**:
  - Using `PAGE_EXECUTE_READWRITE`.
  - Targeting a *remote* process.
- **Used For**: Shellcode allocation during injection.

#### ✍️ `NtWriteVirtualMemory`
> Writes data into the memory space of another process.

- **Suspicious When**:
  - Writing binary payloads (e.g. shellcode).
  - Address belongs to freshly allocated memory.
- **Used For**: Payload injection.

#### 🔐 `NtProtectVirtualMemory`
> Changes memory protection on a memory region.

- **Suspicious When**:
  - Changing protection to `PAGE_EXECUTE_READ` or `PAGE_EXECUTE_READWRITE`.
- **Used For**: Making shellcode executable after writing it.

#### 🧵 `NtCreateThreadEx`
> Creates a thread in the current or a remote process.

- **Suspicious When**:
  - Start address points to injected shellcode.
  - Process handle refers to a different process.
- **Used For**: Triggering execution of injected code.

---

### 🪂 Staging Payload

Hardcoding a keylogger payload directly into the binary would be easily flagged by static analysis tools and antivirus engines due to its obvious malicious footprint.  
To evade detection, the payload is **dynamically staged** — downloaded at runtime from a remote server using low-level socket communication.

---

### 🧱 Replacing Common Win32 API

Common high-level Windows API functions like `GetModuleHandleW` and `GetProcAddress` are frequently monitored or hooked by EDR solutions.  
To bypass such monitoring, **custom equivalents** of these functions were implemented from scratch, directly parsing Windows internal structures such as:

- PE headers  
- PEB (Process Environment Block)  
- Module lists  

---

## 9. 🛠️ To Do

- 🔒 Implement a more advanced string obfuscation mechanism to improve stealth and avoid static detection.
- 🧹 Add a self-deletion routine to remove traces after execution.
- 🔁 Improve robustness by introducing retry logic for critical operations instead of failing immediately.

---

## 10. 📝 Notes & Considerations

Some functions are duplicated between the injector and keylogger components, as they are compiled separately and operate as independent entities.
