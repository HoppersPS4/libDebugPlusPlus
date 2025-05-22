# PS4Debug C++ Port

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ What It Does

- Connects to PS4 consoles over LAN
- Reads/writes memory in active processes
- Hooks and patches live code
- Sends system notifications
- Attaches a debugger to games or apps
- Gives access to registers, threads, and breakpoints
- Dumps system info and memory maps

## 🔧 Key Features

### 🔌 Connection
- **Auto Discovery**: Find consoles on your local network
- **Stable Connections**: Built-in retry and keep-alive logic

### 🧠 Process & Memory
- **List Running Processes**: Find and inspect all active titles
- **Read/Write Memory**: Modify game/app memory directly
- **Memory Mapping**: View and work with virtual memory regions
- **Memory Scan**: Search for values or patterns
- **Allocate & Protect**: Manage memory access and allocation

### 🐞 Debugging Tools
- **Attach a Debugger**: Hook into processes and monitor activity
- **Breakpoints & Watchpoints**: Control execution flow
- **Thread Management**: Get thread IDs and states
- **Register Access**: View/edit CPU registers
- **Debugger Callbacks**: Handle events with your own code

### 🛠 System Access
- **Send Notifications**: Push messages to the PS4 UI
- **Get System Info**: Firmware version, process paths, etc.
- **Kernel Access**: Read/write kernel memory (if permitted)
- **Console Reboot**: Reboot directly (use with caution)

### ⚙️ Utility
- **ELF Loader**: Inject and run custom binaries
- **Remote Procedure Calls**: Execute functions remotely
- **Logging**: Optional built-in logger for debugging output

## 📋 Getting Started

### Requirements
- Windows development environment
- C++17 compatible compiler
- WinSock2

## 🧪 Example Usage

### Connect to Your PS4

```cpp
#include "PS4Debug.h"
#include <iostream>

int main() {
    try {
        std::string ps4_ip = PS4Debug::PS4DBG::FindPlayStation();
        std::cout << "Found PS4 at: " << ps4_ip << std::endl;

        PS4Debug::PS4DBG ps4(ps4_ip);
        ps4.Connect();

        std::cout << "Connected to PS4" << std::endl;

        std::cout << "Library Version: " << ps4.GetLibraryDebugVersion() << std::endl;
        std::cout << "Console Version: " << ps4.GetConsoleDebugVersion() << std::endl;

        ps4.Disconnect();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
```

### Process Management

```cpp
auto processList = ps4.GetProcessList();
std::cout << "Processes Found: " << processList.processes.size() << std::endl;

auto process = processList.FindProcess("eboot.bin");
if (process) {
    int pid = process->pid;
    auto info = ps4.GetProcessInfo(pid);

    std::cout << "Name: " << info.name << std::endl;
    std::cout << "Path: " << info.path << std::endl;
    std::cout << "Title ID: " << info.titleid << std::endl;
}
```

### Memory Access

```cpp
// Read memory
auto data = ps4.ReadMemory(pid, 0x7FC5FAA0, 16);

// Write memory
std::vector<uint8_t> patch = { 0xC6, 0x80, 0xA1, 0x3A, 0x00, 0x00, 0x01 };
ps4.WriteMemory(pid, 0x7FC5FAA0, patch);

// Change protection
ps4.ChangeProtection(pid, 0x7FC5FAA0, 1024, PS4Debug::VM_PROTECTIONS::VM_PROT_ALL);
```

### Debugging

```cpp
ps4.AttachDebugger(pid, [](uint32_t lwpid, uint32_t status, const std::string& tdname,
                          const PS4Debug::regs& regs, const PS4Debug::fpregs& fpregs,
                          const PS4Debug::dbregs& dbregs) {
    std::cout << "Debug event in thread: " << tdname << std::endl;
    std::cout << "RIP: " << std::hex << regs.r_rip << std::endl;
});

ps4.ChangeBreakpoint(0, true, 0x7FC5FAA0);

auto threads = ps4.GetThreadList();
auto regs = ps4.GetRegisters(threads[0]);
regs.r_rax = 0x1234;
ps4.SetRegisters(threads[0], regs);

ps4.DetachDebugger();
```

### System Functions

```cpp
ps4.Notify(222, "Hello from PS4Debug C++ Port!");

// ps4.Reboot(); // Be careful with this
```

## 📚 API Quick Reference

### Core
- `FindPlayStation()`
- `Connect()`
- `Disconnect()`

### Process
- `GetProcessList()`
- `GetProcessInfo(pid)`
- `GetProcessMaps(pid)`

### Memory
- `ReadMemory(pid, addr, size)`
- `WriteMemory(pid, addr, data)`
- `AllocateMemory(pid, size)`
- `FreeMemory(pid, addr)`
- `ChangeProtection(pid, addr, size, flags)`
- `ScanProcess(pid, value)`

### Debug
- `AttachDebugger(pid, callback)`
- `DetachDebugger()`
- `ChangeBreakpoint(index, enable, addr)`
- `ChangeWatchpoint(...)`
- `GetThreadList()`
- `GetRegisters(tid)`
- `SetRegisters(tid, regs)`

### System
- `GetLibraryDebugVersion()`
- `GetConsoleDebugVersion()`
- `Notify(type, msg)`
- `Print(msg)`
- `Reboot()`

## ⚠️ Notes

- Works only on jailbroken PS4s with proper firmware
- yes this readme was written using AI.
- Always call `Disconnect()` before exiting

## 📄 License

MIT License — free to use, modify, and redistribute.

## 🙌 Credits

- **hoppers** – C++ port and integration
- **[EchoStretch/ps4debug](https://github.com/EchoStretch/ps4debug)** – Protocol reference and base tool
- **ChatGPT** – Assistance with code cleanup and error handling
- **Colek** - helping me not go crazy.

---

Version 1.0.0 | © 2025 | Built for the PS4 homebrew scene
