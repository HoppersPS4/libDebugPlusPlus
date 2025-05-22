#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <optional>
#include <array>
#include <variant>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sstream>
#include <iostream>
#include <fstream>

// Logging system
#include "Logger.h"

#define CMD_PACKET_MAGIC 0xFFAABBCC

namespace PS4Debug {

class Process;
class ProcessList;
class ProcessMap;
class MemoryEntry;

constexpr int PS4DBG_PORT = 744;
constexpr int PS4DBG_DEBUG_PORT = 755;
constexpr int NET_MAX_LENGTH = 262144;
constexpr int BROADCAST_PORT = 1010;
constexpr uint32_t BROADCAST_MAGIC = 0xFFFFDEAD;
constexpr uint32_t MAX_BREAKPOINTS = 10;
constexpr uint32_t MAX_WATCHPOINTS = 4;

struct acc {
    std::array<uint8_t, 10> fp_bytes;
    std::array<uint8_t, 6> fp_pad;
};

struct dbregs {
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr4;
    uint64_t dr5;
    uint64_t dr6;
    uint64_t dr7;
    uint64_t dr8;
    uint64_t dr9;
    uint64_t dr10;
    uint64_t dr11;
    uint64_t dr12;
    uint64_t dr13;
    uint64_t dr14;
    uint64_t dr15;
};

struct envxmm {
    uint16_t en_cw;
    uint16_t en_sw;
    uint8_t en_tw;
    uint8_t en_zero;
    uint16_t en_opcode;
    uint64_t en_rip;
    uint64_t en_rdp;
    uint32_t en_mxcsr;
    uint32_t en_mxcsr_mask;
};

struct xmmacc {
    std::array<uint8_t, 16> xmm_bytes;
};

struct ymmacc {
    std::array<uint8_t, 16> ymm_bytes;
};

struct xstate_hdr {
    uint64_t xstate_bv;
    std::array<uint8_t, 16> xstate_rsrv0;
    std::array<uint8_t, 40> xstate_rsrv;
};

struct savefpu_xstate {
    xstate_hdr sx_hd;
    std::array<ymmacc, 16> sx_ymm;
};

struct fpregs {
    envxmm svn_env;
    std::array<acc, 8> sv_fp;
    std::array<xmmacc, 16> sv_xmm;
    std::array<uint8_t, 96> sv_pad;
    savefpu_xstate sv_xstate;
};

struct regs {
    uint64_t r_r15;
    uint64_t r_r14;
    uint64_t r_r13;
    uint64_t r_r12;
    uint64_t r_r11;
    uint64_t r_r10;
    uint64_t r_r9;
    uint64_t r_r8;
    uint64_t r_rdi;
    uint64_t r_rsi;
    uint64_t r_rbp;
    uint64_t r_rbx;
    uint64_t r_rdx;
    uint64_t r_rcx;
    uint64_t r_rax;
    uint32_t r_trapno;
    uint16_t r_fs;
    uint16_t r_gs;
    uint32_t r_err;
    uint16_t r_es;
    uint16_t r_ds;
    uint64_t r_rip;
    uint64_t r_cs;
    uint64_t r_rflags;
    uint64_t r_rsp;
    uint64_t r_ss;
};

struct ThreadInfo {
    int pid;
    int priority;
    char name[32];
};

struct ProcessInfo {
    int pid;
    char name[40];
    char path[64];
    char titleid[16];
    char contentid[64];
};

enum class CMDS : uint32_t {
    CMD_VERSION = 0xBD000001,
    CMD_PROC_LIST = 0xBDAA0001,
    CMD_PROC_READ = 0xBDAA0002,
    CMD_PROC_WRITE = 0xBDAA0003,
    CMD_PROC_MAPS = 0xBDAA0004,
    CMD_PROC_INTALL = 0xBDAA0005,
    CMD_PROC_CALL = 0xBDAA0006,
    CMD_PROC_ELF = 0xBDAA0007,
    CMD_PROC_PROTECT = 0xBDAA0008,
    CMD_PROC_SCAN = 0xBDAA0009,
    CMD_PROC_INFO = 0xBDAA000A,
    CMD_PROC_ALLOC = 0xBDAA000B,
    CMD_PROC_FREE = 0xBDAA000C,

    CMD_DEBUG_ATTACH = 0xBDBB0001,
    CMD_DEBUG_DETACH = 0xBDBB0002,
    CMD_DEBUG_BREAKPT = 0xBDBB0003,
    CMD_DEBUG_WATCHPT = 0xBDBB0004,
    CMD_DEBUG_THREADS = 0xBDBB0005,
    CMD_DEBUG_STOPTHR = 0xBDBB0006,
    CMD_DEBUG_RESUMETHR = 0xBDBB0007,
    CMD_DEBUG_GETREGS = 0xBDBB0008,
    CMD_DEBUG_SETREGS = 0xBDBB0009,
    CMD_DEBUG_GETFPREGS = 0xBDBB000A,
    CMD_DEBUG_SETFPREGS = 0xBDBB000B,
    CMD_DEBUG_GETDBGREGS = 0xBDBB000C,
    CMD_DEBUG_SETDBGREGS = 0xBDBB000D,
    CMD_DEBUG_STOPGO = 0xBDBB0010,
    CMD_DEBUG_THRINFO = 0xBDBB0011,
    CMD_DEBUG_SINGLESTEP = 0xBDBB0012,

    CMD_KERN_BASE = 0xBDCC0001,
    CMD_KERN_READ = 0xBDCC0002,
    CMD_KERN_WRITE = 0xBDCC0003,

    CMD_CONSOLE_REBOOT = 0xBDDD0001,
    CMD_CONSOLE_END = 0xBDDD0002,
    CMD_CONSOLE_PRINT = 0xBDDD0003,
    CMD_CONSOLE_NOTIFY = 0xBDDD0004,
    CMD_CONSOLE_INFO = 0xBDDD0005
};

enum class CMD_STATUS : uint32_t {
    CMD_SUCCESS = 0x80000000,
    CMD_ERROR = 0xF0000001,
    CMD_TOO_MUCH_DATA = 0xF0000002,
    CMD_DATA_NULL = 0xF0000003,
    CMD_ALREADY_DEBUG = 0xF0000004,
    CMD_INVALID_INDEX = 0xF0000005
};

enum class VM_PROTECTIONS : uint32_t {
    VM_PROT_NONE = 0,
    VM_PROT_READ = 1,
    VM_PROT_WRITE = 2,
    VM_PROT_EXECUTE = 4,
    VM_PROT_DEFAULT = 3,
    VM_PROT_ALL = 7,
    VM_PROT_NO_CHANGE = 8,
    VM_PROT_COPY = 16,
    VM_PROT_WANTS_COPY = 16
};

enum class WATCHPT_LENGTH : uint32_t {
    DBREG_DR7_LEN_1 = 0,
    DBREG_DR7_LEN_2 = 1,
    DBREG_DR7_LEN_4 = 3,
    DBREG_DR7_LEN_8 = 2
};

enum class WATCHPT_BREAKTYPE : uint32_t {
    DBREG_DR7_EXEC = 0,
    DBREG_DR7_WRONLY = 1,
    DBREG_DR7_RDWR = 3
};

enum class ScanValueType : uint8_t {
    valTypeUInt8 = 0,
    valTypeInt8,
    valTypeUInt16,
    valTypeInt16,
    valTypeUInt32,
    valTypeInt32,
    valTypeUInt64,
    valTypeInt64,
    valTypeFloat,
    valTypeDouble,
    valTypeArrBytes,
    valTypeString
};

enum class ScanCompareType : uint8_t {
    ExactValue = 0,
    FuzzyValue,
    BiggerThan,
    SmallerThan,
    ValueBetween,
    IncreasedValue,
    IncreasedValueBy,
    DecreasedValue,
    DecreasedValueBy,
    ChangedValue,
    UnchangedValue,
    UnknownInitialValue
};

#pragma pack(push, 1)
struct CMDPacket {
    uint32_t magic;
    uint32_t cmd;
    uint32_t datalen;
};

struct DebuggerInterruptPacket {
    uint32_t lwpid;
    uint32_t status;
    char tdname[40];
    regs reg64;
    fpregs savefpu;
    dbregs dbreg64;
};
#pragma pack(pop)

using DebuggerInterruptCallback = std::function<void(uint32_t lwpid, uint32_t status, const std::string& tdname, const regs& regs, const fpregs& fpregs, const dbregs& dbregs)>;

class MemoryEntry {
public:
    std::string name;
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint32_t prot;
};

class Process {
public:
    Process(const std::string& name, int pid);
    std::string ToString() const;

    std::string name;
    int pid;
};

class ProcessList {
public:
    ProcessList(int number, const std::vector<std::string>& names, const std::vector<int>& pids);
    std::shared_ptr<Process> FindProcess(const std::string& name, bool contains = false) const;

    std::vector<std::shared_ptr<Process>> processes;
};

class ProcessMap {
public:
    ProcessMap(int pid, const std::vector<std::shared_ptr<MemoryEntry>>& entries);
    std::shared_ptr<MemoryEntry> FindEntry(const std::string& name, bool contains = false) const;
    std::shared_ptr<MemoryEntry> FindEntry(uint64_t size) const;

    int pid;
    std::vector<std::shared_ptr<MemoryEntry>> entries;
};

class PS4DBG {
public:
    PS4DBG(const std::string& ip);
    PS4DBG(const sockaddr_in& addr);
    ~PS4DBG();

    static std::string FindPlayStation();
    void Connect();
    void Disconnect();

    // Internal Debugging
    std::string GetStatusString(CMD_STATUS status);
    std::string GetWSAErrorString(int error);

    std::string ToHexString(uint64_t val);

    std::string GetLibraryDebugVersion() const;
    std::string GetConsoleDebugVersion();

    void Reboot();
    void Print(const std::string& str);
    void Notify(int messageType, const std::string& message);
    void GetConsoleInformation();

    uint64_t KernelBase();
    std::vector<uint8_t> KernelReadMemory(uint64_t address, int length);
    void KernelWriteMemory(uint64_t address, const std::vector<uint8_t>& data);

    void AttachDebugger(int pid, const DebuggerInterruptCallback& callback);
    void DetachDebugger();
    void ProcessStop();
    void ProcessKill();
    void ProcessResume();
    void ChangeBreakpoint(int index, bool enabled, uint64_t address);
    void ChangeWatchpoint(int index, bool enabled, WATCHPT_LENGTH length, WATCHPT_BREAKTYPE breaktype, uint64_t address);
    std::vector<uint32_t> GetThreadList();
    ThreadInfo GetThreadInfo(uint32_t lwpid);
    void StopThread(uint32_t lwpid);
    void ResumeThread(uint32_t lwpid);
    regs GetRegisters(uint32_t lwpid);
    void SetRegisters(uint32_t lwpid, const regs& regs);
    fpregs GetFloatRegisters(uint32_t lwpid);
    void SetFloatRegisters(uint32_t lwpid, const fpregs& fpregs);
    dbregs GetDebugRegisters(uint32_t lwpid);
    void SetDebugRegisters(uint32_t lwpid, const dbregs& dbregs);
    void SingleStep();

    ProcessList GetProcessList();
    std::vector<uint8_t> ReadMemory(int pid, uint64_t address, int length);
    void WriteMemory(int pid, uint64_t address, const std::vector<uint8_t>& data);
    ProcessMap GetProcessMaps(int pid);
    uint64_t InstallRPC(int pid);
    uint64_t Call(int pid, uint64_t rpcstub, uint64_t address, const std::vector<std::variant<char, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t, float, double>>& args);
    void LoadElf(int pid, const std::vector<uint8_t>& elf);
    void LoadElf(int pid, const std::string& filename);
    std::vector<uint64_t> ScanProcess(int pid, ScanCompareType compareType, const std::variant<bool, int8_t, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t, float, double, std::string, std::vector<uint8_t>>& value, 
                                     const std::optional<std::variant<bool, int8_t, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t, float, double>>& extraValue = std::nullopt);
    void ChangeProtection(int pid, uint64_t address, uint32_t length, VM_PROTECTIONS newProt);
    ProcessInfo GetProcessInfo(int pid);
    uint64_t AllocateMemory(int pid, int length);
    void FreeMemory(int pid, uint64_t address, int length);

    template<typename T>
    T ReadMemory(int pid, uint64_t address);
    
    template<typename T>
    void WriteMemory(int pid, uint64_t address, const T& value);

    bool IsConnected() const { return isConnected; }
    bool IsDebugging() const { return isDebugging; }

private:
    static std::string ConvertASCII(const std::vector<uint8_t>& data, int offset);
    static std::vector<uint8_t> SubArray(const std::vector<uint8_t>& data, int offset, int length);
    static std::vector<uint8_t> GetBytesFromObject(const void* obj, size_t size);
    template<typename T>
    static T GetObjectFromBytes(const std::vector<uint8_t>& buffer);
    static sockaddr_in GetBroadcastAddress(const sockaddr_in& address, const sockaddr_in& subnetMask);

    void SendCMDPacket(CMDS cmd, int length, const std::vector<std::variant<char, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t, float, double, std::string, std::vector<uint8_t>>>& fields = {});
    void SendData(const std::vector<uint8_t>& data, int length);
    std::vector<uint8_t> ReceiveData(int length);
    CMD_STATUS ReceiveStatus();
    void CheckStatus();
    void CheckConnected();
    void CheckDebugging();

    void DebuggerThread(const DebuggerInterruptCallback& callback);

    SOCKET sock;
    sockaddr_in enp;
    std::atomic<bool> isConnected{false};
    std::atomic<bool> isDebugging{false};
    std::unique_ptr<std::thread> debugThread;
    std::mutex debugMutex;

    std::shared_ptr<Logger> logger;
};

}