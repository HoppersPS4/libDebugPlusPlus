#include "PS4Debug.h"
#include <cstring>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <mstcpip.h>

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

namespace PS4Debug {

    Process::Process(const std::string& name, int pid) : name(name), pid(pid) {}

    std::string Process::ToString() const {
        return "[" + std::to_string(pid) + "] " + name;
    }

    ProcessList::ProcessList(int number, const std::vector<std::string>& names, const std::vector<int>& pids) {
        processes.reserve(number);
        for (int i = 0; i < number; i++) {
            processes.push_back(std::make_shared<Process>(names[i], pids[i]));
        }
    }

    std::shared_ptr<Process> ProcessList::FindProcess(const std::string& name, bool contains) const {
        for (const auto& process : processes) {
            if (contains) {
                if (process->name.find(name) != std::string::npos) {
                    return process;
                }
            }
            else {
                if (process->name == name) {
                    return process;
                }
            }
        }
        return nullptr;
    }

    ProcessMap::ProcessMap(int pid, const std::vector<std::shared_ptr<MemoryEntry>>& entries)
        : pid(pid), entries(entries) {
    }

    std::shared_ptr<MemoryEntry> ProcessMap::FindEntry(const std::string& name, bool contains) const {
        for (const auto& entry : entries) {
            if (contains) {
                if (entry->name.find(name) != std::string::npos) {
                    return entry;
                }
            }
            else {
                if (entry->name == name) {
                    return entry;
                }
            }
        }
        return nullptr;
    }

    std::shared_ptr<MemoryEntry> ProcessMap::FindEntry(uint64_t size) const {
        for (const auto& entry : entries) {
            if (entry->start - entry->end == size) {
                return entry;
            }
        }
        return nullptr;
    }

    PS4DBG::PS4DBG(const std::string& ip) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("Failed to initialize WinSock");
        }

        logger = std::make_shared<Logger>();
        logger->info("PS4DBG initialized with IP: " + ip);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PS4DBG_PORT);

        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
            logger->error("Invalid IP address format: " + ip);
            WSACleanup();
            throw std::runtime_error("Invalid IP address format: " + ip);
        }

        enp = addr;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            logger->error("Failed to create socket: " + std::to_string(WSAGetLastError()));
            WSACleanup();
            throw std::runtime_error("Failed to create socket");
        }
    }

    PS4DBG::PS4DBG(const sockaddr_in& addr) : enp(addr) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("Failed to initialize WinSock");
        }

        logger = std::make_shared<Logger>();

        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ipStr, INET_ADDRSTRLEN);
        logger->info("PS4DBG initialized with IP: " + std::string(ipStr));

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            logger->error("Failed to create socket: " + std::to_string(WSAGetLastError()));
            WSACleanup();
            throw std::runtime_error("Failed to create socket");
        }
    }

    PS4DBG::~PS4DBG() {
        if (isConnected) {
            try {
                Disconnect();
            }
            catch (const std::exception& e) {
                logger->error("Error during disconnect in destructor: " + std::string(e.what()));
            }
        }

        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }

        WSACleanup();
        logger->info("PS4DBG destroyed");
    }

    std::string PS4DBG::FindPlayStation() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("Failed to initialize WinSock for broadcast");
        }

        SOCKET udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udpSock == INVALID_SOCKET) {
            WSACleanup();
            throw std::runtime_error("Failed to create UDP socket");
        }

        BOOL bOptVal = TRUE;
        if (setsockopt(udpSock, SOL_SOCKET, SO_BROADCAST, (char*)&bOptVal, sizeof(BOOL)) == SOCKET_ERROR) {
            closesocket(udpSock);
            WSACleanup();
            throw std::runtime_error("Failed to set socket options");
        }

        DWORD timeout = 4000; // 4 seconds
        if (setsockopt(udpSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(DWORD)) == SOCKET_ERROR) {
            closesocket(udpSock);
            WSACleanup();
            throw std::runtime_error("Failed to set receive timeout");
        }

        char hostName[256];
        if (gethostname(hostName, sizeof(hostName)) == SOCKET_ERROR) {
            closesocket(udpSock);
            WSACleanup();
            throw std::runtime_error("Failed to get host name");
        }

        struct addrinfo* result = nullptr;
        struct addrinfo hints {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(hostName, nullptr, &hints, &result) != 0) {
            closesocket(udpSock);
            WSACleanup();
            throw std::runtime_error("Failed to get host address info");
        }

        sockaddr_in* localAddr = nullptr;
        for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                localAddr = (sockaddr_in*)ptr->ai_addr;
                break;
            }
        }

        if (!localAddr) {
            freeaddrinfo(result);
            closesocket(udpSock);
            WSACleanup();
            throw std::runtime_error("Could not get host IP");
        }

        sockaddr_in broadcastAddr{};
        broadcastAddr.sin_family = AF_INET;
        broadcastAddr.sin_port = htons(BROADCAST_PORT);

        sockaddr_in subnetMask{};
        subnetMask.sin_family = AF_INET;

        const char* subnetMaskStr = "255.255.255.0";
        if (inet_pton(AF_INET, subnetMaskStr, &subnetMask.sin_addr) != 1) {
            freeaddrinfo(result); 
            closesocket(udpSock);
            WSACleanup();
            throw std::runtime_error("Invalid subnet mask format: " + std::string(subnetMaskStr));
        }

        sockaddr_in bcastAddr = GetBroadcastAddress(*localAddr, subnetMask);
        broadcastAddr.sin_addr = bcastAddr.sin_addr;

        uint32_t magic = BROADCAST_MAGIC;
        if (sendto(udpSock, (char*)&magic, sizeof(magic), 0, (sockaddr*)&broadcastAddr, sizeof(broadcastAddr)) == SOCKET_ERROR) {
            freeaddrinfo(result);
            closesocket(udpSock);
            WSACleanup();
            throw std::runtime_error("Failed to send broadcast packet");
        }

        sockaddr_in fromAddr{};
        int fromLen = sizeof(fromAddr);
        uint32_t response;

        if (recvfrom(udpSock, (char*)&response, sizeof(response), 0, (sockaddr*)&fromAddr, &fromLen) == SOCKET_ERROR) {
            freeaddrinfo(result);
            closesocket(udpSock);
            WSACleanup();
            throw std::runtime_error("Failed to receive broadcast response");
        }

        if (response != BROADCAST_MAGIC) {
            freeaddrinfo(result);
            closesocket(udpSock);
            WSACleanup();
            throw std::runtime_error("Wrong magic on UDP server response");
        }

        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &fromAddr.sin_addr, ipStr, INET_ADDRSTRLEN);

        freeaddrinfo(result);
        closesocket(udpSock);
        WSACleanup();

        return std::string(ipStr);
    }

    void PS4DBG::Connect() {
        int maxRetries = 3;
        if (!isConnected) {
            logger->info("Connecting to PS4...");

            BOOL optval = TRUE;
            if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&optval, sizeof(BOOL)) == SOCKET_ERROR) {
                logger->error("Failed to set TCP_NODELAY: " + std::to_string(WSAGetLastError()));
                throw std::runtime_error("Failed to set TCP_NODELAY");
            }

            int bufSize = NET_MAX_LENGTH;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&bufSize, sizeof(int)) == SOCKET_ERROR) {
                logger->error("Failed to set SO_RCVBUF: " + std::to_string(WSAGetLastError()));
                throw std::runtime_error("Failed to set receive buffer size");
            }

            if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&bufSize, sizeof(int)) == SOCKET_ERROR) {
                logger->error("Failed to set SO_SNDBUF: " + std::to_string(WSAGetLastError()));
                throw std::runtime_error("Failed to set send buffer size");
            }

            DWORD timeout = 30000; 
            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(DWORD)) == SOCKET_ERROR) {
                logger->error("Failed to set SO_RCVTIMEO: " + std::to_string(WSAGetLastError()));
                throw std::runtime_error("Failed to set receive timeout");
            }

            BOOL keepAlive = TRUE;
            if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepAlive, sizeof(BOOL)) == SOCKET_ERROR) {
                logger->warning("Failed to set SO_KEEPALIVE: " + std::to_string(WSAGetLastError()));
            }

            tcp_keepalive keepAliveParams;
            keepAliveParams.onoff = 1;
            keepAliveParams.keepalivetime = 30000; // 30 seconds
            keepAliveParams.keepaliveinterval = 5000; // 5 seconds
            DWORD bytesReturned = 0;
            if (WSAIoctl(sock, SIO_KEEPALIVE_VALS, &keepAliveParams, sizeof(keepAliveParams),
                NULL, 0, &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
                logger->warning("Failed to set keep-alive values: " + std::to_string(WSAGetLastError()));
            }

            int retries = 0;
            bool connected = false;

            while (!connected && retries < maxRetries) {
                try {
                    logger->info("Connection attempt " + std::to_string(retries + 1) +
                        " of " + std::to_string(maxRetries) + "...");

                    if (connect(sock, (sockaddr*)&enp, sizeof(enp)) == SOCKET_ERROR) {
                        int error = WSAGetLastError();
                        if (error == WSAETIMEDOUT && retries < maxRetries - 1) {
                            logger->warning("Connection attempt timed out, retrying... (" +
                                std::to_string(retries + 1) + "/" +
                                std::to_string(maxRetries) + ")");
                            retries++;
                            std::this_thread::sleep_for(std::chrono::seconds(1));
                            continue;
                        }
                        logger->error("Failed to connect: " + std::to_string(error));
                        throw std::runtime_error("Failed to connect to PS4");
                    }
                    connected = true;
                }
                catch (const std::exception& e) {
                    if (retries < maxRetries - 1) {
                        logger->warning(std::string(e.what()) + ", retrying...");
                        retries++;
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                    }
                    else {
                        throw;
                    }
                }
            }

            isConnected = true;
            logger->info("Connected to PS4 successfully");
        }
    }

    void PS4DBG::Disconnect() {
        if (isConnected) {
            logger->info("Disconnecting from PS4...");

            try {
                SendCMDPacket(CMDS::CMD_CONSOLE_END, 0);
            }
            catch (const std::exception& e) {
                logger->warning("Error sending disconnect command: " + std::string(e.what()));
            }

            shutdown(sock, SD_BOTH);
            closesocket(sock);
            sock = INVALID_SOCKET;

            isConnected = false;
            logger->info("Disconnected from PS4");
        }
    }

    std::string PS4DBG::GetLibraryDebugVersion() const {
        return "1.2 - C++ Port by hoppers";
    }

    std::string PS4DBG::GetConsoleDebugVersion() {
        CheckConnected();
        logger->info("Getting console debug version");

        SendCMDPacket(CMDS::CMD_VERSION, 0);

        uint32_t length;
        if (recv(sock, (char*)&length, 4, 0) != 4) {
            logger->error("Failed to receive version length");
            throw std::runtime_error("Failed to receive version length");
        }

        std::vector<uint8_t> buffer(length);
        if (recv(sock, (char*)buffer.data(), length, 0) != length) {
            logger->error("Failed to receive version string");
            throw std::runtime_error("Failed to receive version string");
        }

        std::string version = ConvertASCII(buffer, 0);
        logger->info("Console debug version: " + version);
        return version;
    }

    void PS4DBG::Reboot() {
        CheckConnected();
        logger->info("Rebooting PS4");

        SendCMDPacket(CMDS::CMD_CONSOLE_REBOOT, 0);
        isConnected = false;
    }

    void PS4DBG::Print(const std::string& str) {
        CheckConnected();
        logger->info("Sending print message: " + str);

        std::string nullTerminated = str + '\0';
        SendCMDPacket(CMDS::CMD_CONSOLE_PRINT, 4, { {(int32_t)nullTerminated.length()} });
        SendData(std::vector<uint8_t>(nullTerminated.begin(), nullTerminated.end()), nullTerminated.length());
        CheckStatus();
    }

    void PS4DBG::Notify(int messageType, const std::string& message) {
        CheckConnected();
        logger->info("Sending notification - Type: " + std::to_string(messageType) + ", Message: " + message);

        std::string nullTerminated = message + '\0';
        SendCMDPacket(CMDS::CMD_CONSOLE_NOTIFY, 8, { {messageType, (int32_t)nullTerminated.length()} });
        SendData(std::vector<uint8_t>(nullTerminated.begin(), nullTerminated.end()), nullTerminated.length());
        CheckStatus();
    }

    void PS4DBG::GetConsoleInformation() {
        CheckConnected();
        logger->info("Getting console information");

        SendCMDPacket(CMDS::CMD_CONSOLE_INFO, 0);
        CheckStatus();
    }

    uint64_t PS4DBG::KernelBase() {
        CheckConnected();
        logger->info("Getting kernel base address");

        SendCMDPacket(CMDS::CMD_KERN_BASE, 0);
        CheckStatus();

        std::vector<uint8_t> data = ReceiveData(8);
        uint64_t base = *(uint64_t*)data.data();

        logger->info("Kernel base address: 0x" + std::to_string(base));
        return base;
    }

    std::vector<uint8_t> PS4DBG::KernelReadMemory(uint64_t address, int length) {
        CheckConnected();
        logger->info("Reading kernel memory - Address: 0x" + std::to_string(address) + ", Length: " + std::to_string(length));

        SendCMDPacket(CMDS::CMD_KERN_READ, 12, { {address, (int32_t)length} });
        CheckStatus();

        return ReceiveData(length);
    }

    void PS4DBG::KernelWriteMemory(uint64_t address, const std::vector<uint8_t>& data) {
        CheckConnected();
        logger->info("Writing kernel memory - Address: 0x" + std::to_string(address) + ", Length: " + std::to_string(data.size()));

        SendCMDPacket(CMDS::CMD_KERN_WRITE, 12, { {address, (int32_t)data.size()} });
        CheckStatus();

        SendData(data, data.size());
        CheckStatus();
    }

    void PS4DBG::DebuggerThread(const DebuggerInterruptCallback& callback) {
        logger->info("Starting debugger thread");

        SOCKET debugSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (debugSock == INVALID_SOCKET) {
            logger->error("Failed to create debug socket: " + std::to_string(WSAGetLastError()));
            isDebugging = false;
            return;
        }

        sockaddr_in localAddr{};
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = htons(PS4DBG_DEBUG_PORT);

        if (bind(debugSock, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
            logger->error("Failed to bind debug socket: " + std::to_string(WSAGetLastError()));
            closesocket(debugSock);
            isDebugging = false;
            return;
        }

        if (listen(debugSock, 1) == SOCKET_ERROR) {
            logger->error("Failed to listen on debug socket: " + std::to_string(WSAGetLastError()));
            closesocket(debugSock);
            isDebugging = false;
            return;
        }

        isDebugging = true;
        logger->info("Debugger thread listening for connections");

        // Accept connection from PS4
        SOCKET clientSock = accept(debugSock, nullptr, nullptr);
        if (clientSock == INVALID_SOCKET) {
            logger->error("Failed to accept debug connection: " + std::to_string(WSAGetLastError()));
            closesocket(debugSock);
            isDebugging = false;
            return;
        }

        logger->info("Debug connection established");

        // Set socket options
        BOOL optval = TRUE;
        if (setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, (char*)&optval, sizeof(BOOL)) == SOCKET_ERROR) {
            logger->warning("Failed to set TCP_NODELAY on debug socket: " + std::to_string(WSAGetLastError()));
        }

        // Set non-blocking mode
        u_long mode = 1;
        if (ioctlsocket(clientSock, FIONBIO, &mode) == SOCKET_ERROR) {
            logger->warning("Failed to set non-blocking mode on debug socket: " + std::to_string(WSAGetLastError()));
        }

        // Main debug loop
        while (isDebugging) {
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(clientSock, &readSet);

            // Use select with timeout to check for data
            timeval tv{ 0, 100000 }; // 100ms timeout
            int result = select(0, &readSet, nullptr, nullptr, &tv);

            if (result > 0 && FD_ISSET(clientSock, &readSet)) {
                // Check if we have a complete packet
                u_long available = 0;
                if (ioctlsocket(clientSock, FIONREAD, &available) == SOCKET_ERROR) {
                    logger->error("Failed to get available data: " + std::to_string(WSAGetLastError()));
                    break;
                }

                if (available >= sizeof(DebuggerInterruptPacket)) {
                    DebuggerInterruptPacket packet;
                    int received = recv(clientSock, (char*)&packet, sizeof(packet), 0);

                    if (received == sizeof(packet)) {
                        logger->info("Received debug interrupt - LWPID: " + std::to_string(packet.lwpid) +
                            ", Status: " + std::to_string(packet.status));

                        // Call the callback with the interrupt data
                        callback(packet.lwpid, packet.status, packet.tdname,
                            packet.reg64, packet.savefpu, packet.dbreg64);
                    }
                }
            }

            // Check if we should exit
            if (!isDebugging) {
                break;
            }

            // Small sleep to prevent CPU hogging
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // Clean up
        closesocket(clientSock);
        closesocket(debugSock);
        logger->info("Debugger thread terminated");
    }

    void PS4DBG::AttachDebugger(int pid, const DebuggerInterruptCallback& callback) {
        CheckConnected();

        if (isDebugging || debugThread) {
            logger->error("Debugger already running");
            throw std::runtime_error("Debugger already running");
        }

        logger->info("Attaching debugger to process " + std::to_string(pid));

        isDebugging = false;
        debugThread = std::make_unique<std::thread>(&PS4DBG::DebuggerThread, this, callback);

        while (!isDebugging) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        SendCMDPacket(CMDS::CMD_DEBUG_ATTACH, 4, { {pid} });
        CheckStatus();

        logger->info("Debugger attached successfully");
    }

    void PS4DBG::DetachDebugger() {
        CheckConnected();
        logger->info("Detaching debugger");

        SendCMDPacket(CMDS::CMD_DEBUG_DETACH, 0);
        CheckStatus();

        if (isDebugging && debugThread) {
            isDebugging = false;
            debugThread->join();
            debugThread.reset();
        }

        logger->info("Debugger detached successfully");
    }

    void PS4DBG::ProcessStop() {
        CheckConnected();
        CheckDebugging();
        logger->info("Stopping process");

        SendCMDPacket(CMDS::CMD_DEBUG_STOPGO, 4, { {1} });
        CheckStatus();
    }

    void PS4DBG::ProcessKill() {
        CheckConnected();
        CheckDebugging();
        logger->info("Killing process");

        SendCMDPacket(CMDS::CMD_DEBUG_STOPGO, 4, { {2} });
        CheckStatus();
    }

    void PS4DBG::ProcessResume() {
        CheckConnected();
        CheckDebugging();
        logger->info("Resuming process");

        SendCMDPacket(CMDS::CMD_DEBUG_STOPGO, 4, { {0} });
        CheckStatus();
    }

    void PS4DBG::ChangeBreakpoint(int index, bool enabled, uint64_t address) {
        CheckConnected();
        CheckDebugging();

        if (index >= MAX_BREAKPOINTS) {
            logger->error("Breakpoint index out of range: " + std::to_string(index));
            throw std::runtime_error("Breakpoint index out of range");
        }

        logger->info("Changing breakpoint - Index: " + std::to_string(index) +
            ", Enabled: " + std::to_string(enabled) +
            ", Address: 0x" + std::to_string(address));

        SendCMDPacket(CMDS::CMD_DEBUG_BREAKPT, 16, { {index, (int32_t)enabled, address} });
        CheckStatus();
    }

    void PS4DBG::ChangeWatchpoint(int index, bool enabled, WATCHPT_LENGTH length, WATCHPT_BREAKTYPE breaktype, uint64_t address) {
        CheckConnected();
        CheckDebugging();

        if (index >= MAX_WATCHPOINTS) {
            logger->error("Watchpoint index out of range: " + std::to_string(index));
            throw std::runtime_error("Watchpoint index out of range");
        }

        logger->info("Changing watchpoint - Index: " + std::to_string(index) +
            ", Enabled: " + std::to_string(enabled) +
            ", Length: " + std::to_string((uint32_t)length) +
            ", Type: " + std::to_string((uint32_t)breaktype) +
            ", Address: 0x" + std::to_string(address));

        SendCMDPacket(CMDS::CMD_DEBUG_WATCHPT, 24, { {index, (int32_t)enabled, (uint32_t)length, (uint32_t)breaktype, address} });
        CheckStatus();
    }

    std::vector<uint32_t> PS4DBG::GetThreadList() {
        CheckConnected();
        CheckDebugging();
        logger->info("Getting thread list");

        SendCMDPacket(CMDS::CMD_DEBUG_THREADS, 0);
        CheckStatus();

        uint32_t count;
        if (recv(sock, (char*)&count, 4, 0) != 4) {
            logger->error("Failed to receive thread count");
            throw std::runtime_error("Failed to receive thread count");
        }

        std::vector<uint8_t> data = ReceiveData(count * 4);
        std::vector<uint32_t> threads(count);

        for (uint32_t i = 0; i < count; i++) {
            threads[i] = *(uint32_t*)(data.data() + (i * 4));
        }

        logger->info("Retrieved " + std::to_string(count) + " threads");
        return threads;
    }

    ThreadInfo PS4DBG::GetThreadInfo(uint32_t lwpid) {
        CheckConnected();
        CheckDebugging();
        logger->info("Getting thread info for LWPID: " + std::to_string(lwpid));

        SendCMDPacket(CMDS::CMD_DEBUG_THRINFO, 4, { {lwpid} });
        CheckStatus();

        std::vector<uint8_t> data = ReceiveData(sizeof(ThreadInfo));
        ThreadInfo info = *(ThreadInfo*)data.data();

        logger->info("Thread info - PID: " + std::to_string(info.pid) +
            ", Priority: " + std::to_string(info.priority) +
            ", Name: " + std::string(info.name));

        return info;
    }

    void PS4DBG::StopThread(uint32_t lwpid) {
        CheckConnected();
        CheckDebugging();
        logger->info("Stopping thread LWPID: " + std::to_string(lwpid));

        SendCMDPacket(CMDS::CMD_DEBUG_STOPTHR, 4, { {lwpid} });
        CheckStatus();
    }

    void PS4DBG::ResumeThread(uint32_t lwpid) {
        CheckConnected();
        CheckDebugging();
        logger->info("Resuming thread LWPID: " + std::to_string(lwpid));

        SendCMDPacket(CMDS::CMD_DEBUG_RESUMETHR, 4, { {lwpid} });
        CheckStatus();
    }

    regs PS4DBG::GetRegisters(uint32_t lwpid) {
        CheckConnected();
        CheckDebugging();
        logger->info("Getting registers for thread LWPID: " + std::to_string(lwpid));

        SendCMDPacket(CMDS::CMD_DEBUG_GETREGS, 4, { {lwpid} });
        CheckStatus();

        std::vector<uint8_t> data = ReceiveData(sizeof(regs));
        return *(regs*)data.data();
    }

    void PS4DBG::SetRegisters(uint32_t lwpid, const regs& regs) {
        CheckConnected();
        CheckDebugging();
        logger->info("Setting registers for thread LWPID: " + std::to_string(lwpid));

        SendCMDPacket(CMDS::CMD_DEBUG_SETREGS, 8, { {lwpid, (int32_t)sizeof(struct regs)} });
        CheckStatus();

        SendData(GetBytesFromObject(&regs, sizeof(regs)), sizeof(regs));
        CheckStatus();
    }

    fpregs PS4DBG::GetFloatRegisters(uint32_t lwpid) {
        CheckConnected();
        CheckDebugging();
        logger->info("Getting float registers for thread LWPID: " + std::to_string(lwpid));

        SendCMDPacket(CMDS::CMD_DEBUG_GETFPREGS, 4, { {lwpid} });
        CheckStatus();

        std::vector<uint8_t> data = ReceiveData(sizeof(fpregs));
        return *(fpregs*)data.data();
    }

    void PS4DBG::SetFloatRegisters(uint32_t lwpid, const fpregs& fpregs) {
        CheckConnected();
        CheckDebugging();
        logger->info("Setting float registers for thread LWPID: " + std::to_string(lwpid));

        SendCMDPacket(CMDS::CMD_DEBUG_SETFPREGS, 8, { {lwpid, (int32_t)sizeof(struct fpregs)} });
        CheckStatus();

        SendData(GetBytesFromObject(&fpregs, sizeof(fpregs)), sizeof(fpregs));
        CheckStatus();
    }

    dbregs PS4DBG::GetDebugRegisters(uint32_t lwpid) {
        CheckConnected();
        CheckDebugging();
        logger->info("Getting debug registers for thread LWPID: " + std::to_string(lwpid));

        SendCMDPacket(CMDS::CMD_DEBUG_GETDBGREGS, 4, { {lwpid} });
        CheckStatus();

        std::vector<uint8_t> data = ReceiveData(sizeof(dbregs));
        return *(dbregs*)data.data();
    }

    void PS4DBG::SetDebugRegisters(uint32_t lwpid, const dbregs& dbregs) {
        CheckConnected();
        CheckDebugging();
        logger->info("Setting debug registers for thread LWPID: " + std::to_string(lwpid));

        SendCMDPacket(CMDS::CMD_DEBUG_SETDBGREGS, 8, { {lwpid, (int32_t)sizeof(struct dbregs)} });
        CheckStatus();

        SendData(GetBytesFromObject(&dbregs, sizeof(dbregs)), sizeof(dbregs));
        CheckStatus();
    }

    void PS4DBG::SingleStep() {
        CheckConnected();
        CheckDebugging();
        logger->info("Executing single step");

        SendCMDPacket(CMDS::CMD_DEBUG_SINGLESTEP, 0);
        CheckStatus();
    }

    ProcessList PS4DBG::GetProcessList() {
        CheckConnected();
        logger->info("Getting process list");

        SendCMDPacket(CMDS::CMD_PROC_LIST, 0);
        CheckStatus();

        uint32_t count;
        if (recv(sock, (char*)&count, 4, 0) != 4) {
            logger->error("Failed to receive process count");
            throw std::runtime_error("Failed to receive process count");
        }

        std::vector<uint8_t> data = ReceiveData(count * 36);
        std::vector<std::string> names;
        std::vector<int> pids;

        for (uint32_t i = 0; i < count; i++) {
            int offset = i * 36;
            std::string name = ConvertASCII(data, offset);
            int pid = *(int32_t*)(data.data() + offset + 32);

            names.push_back(name);
            pids.push_back(pid);
        }

        logger->info("Retrieved " + std::to_string(count) + " processes");
        return ProcessList(count, names, pids);
    }

    std::vector<uint8_t> PS4DBG::ReadMemory(int pid, uint64_t address, int length) {
        CheckConnected();
        logger->info("Reading memory - PID: " + std::to_string(pid) +
            ", Address: 0x" + std::to_string(address) +
            ", Length: " + std::to_string(length));

        SendCMDPacket(CMDS::CMD_PROC_READ, 16, { {pid, address, length} });
        CheckStatus();

        return ReceiveData(length);
    }

    void PS4DBG::WriteMemory(int pid, uint64_t address, const std::vector<uint8_t>& data) {
        CheckConnected();
        logger->info("Writing memory - PID: " + std::to_string(pid) +
            ", Address: 0x" + std::to_string(address) +
            ", Length: " + std::to_string(data.size()));

        SendCMDPacket(CMDS::CMD_PROC_WRITE, 16, { {pid, address, (int32_t)data.size()} });
        CheckStatus();

        SendData(data, data.size());
        CheckStatus();
    }

    ProcessMap PS4DBG::GetProcessMaps(int pid) {
        CheckConnected();
        logger->info("Getting process maps for PID: " + std::to_string(pid));

        SendCMDPacket(CMDS::CMD_PROC_MAPS, 4, { {pid} });
        CheckStatus();

        uint32_t count;
        if (recv(sock, (char*)&count, 4, 0) != 4) {
            logger->error("Failed to receive map entry count");
            throw std::runtime_error("Failed to receive map entry count");
        }

        std::vector<uint8_t> data = ReceiveData(count * 58);
        std::vector<std::shared_ptr<MemoryEntry>> entries;

        for (uint32_t i = 0; i < count; i++) {
            int offset = i * 58;
            auto entry = std::make_shared<MemoryEntry>();

            entry->name = ConvertASCII(data, offset);
            entry->start = *(uint64_t*)(data.data() + offset + 32);
            entry->end = *(uint64_t*)(data.data() + offset + 40);
            entry->offset = *(uint64_t*)(data.data() + offset + 48);
            entry->prot = *(uint16_t*)(data.data() + offset + 56);

            entries.push_back(entry);
        }

        logger->info("Retrieved " + std::to_string(count) + " memory map entries");
        return ProcessMap(pid, entries);
    }

    uint64_t PS4DBG::InstallRPC(int pid) {
        CheckConnected();
        logger->info("Installing RPC for PID: " + std::to_string(pid));

        SendCMDPacket(CMDS::CMD_PROC_INTALL, 4, { {pid} });
        CheckStatus();

        std::vector<uint8_t> data = ReceiveData(8);
        uint64_t stub = *(uint64_t*)data.data();

        logger->info("RPC stub installed at: 0x" + std::to_string(stub));
        return stub;
    }

    uint64_t PS4DBG::Call(int pid, uint64_t rpcstub, uint64_t address, const std::vector<std::variant<char, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t, float, double>>& args) {
        CheckConnected();
        logger->info("Calling function - PID: " + std::to_string(pid) +
            ", RPC Stub: 0x" + std::to_string(rpcstub) +
            ", Address: 0x" + std::to_string(address));

        if (args.size() > 6) {
            logger->error("Too many arguments: " + std::to_string(args.size()));
            throw std::runtime_error("Too many arguments (max 6)");
        }

        CMDPacket packet;
        packet.magic = CMD_PACKET_MAGIC;
        packet.cmd = (uint32_t)CMDS::CMD_PROC_CALL;
        packet.datalen = 68;

        SendData(GetBytesFromObject(&packet, sizeof(packet)), sizeof(packet));

        std::vector<uint8_t> callData(68, 0);

        *(int32_t*)callData.data() = pid;
        *(uint64_t*)(callData.data() + 4) = rpcstub;
        *(uint64_t*)(callData.data() + 12) = address;

        for (size_t i = 0; i < args.size(); i++) {
            uint8_t* argPtr = callData.data() + 20 + (i * 8);

            std::visit([argPtr](auto&& arg) {
                using T = std::decay_t<decltype(arg)>;

                if constexpr (std::is_same_v<T, char>) {
                    *(uint16_t*)argPtr = arg;
                }
                else if constexpr (std::is_same_v<T, uint8_t>) {
                    *(uint8_t*)argPtr = arg;
                }
                else if constexpr (std::is_same_v<T, int16_t>) {
                    *(int16_t*)argPtr = arg;
                }
                else if constexpr (std::is_same_v<T, uint16_t>) {
                    *(uint16_t*)argPtr = arg;
                }
                else if constexpr (std::is_same_v<T, int32_t>) {
                    *(int32_t*)argPtr = arg;
                }
                else if constexpr (std::is_same_v<T, uint32_t>) {
                    *(uint32_t*)argPtr = arg;
                }
                else if constexpr (std::is_same_v<T, int64_t>) {
                    *(int64_t*)argPtr = arg;
                }
                else if constexpr (std::is_same_v<T, uint64_t>) {
                    *(uint64_t*)argPtr = arg;
                }
                else if constexpr (std::is_same_v<T, float>) {
                    *(float*)argPtr = arg;
                }
                else if constexpr (std::is_same_v<T, double>) {
                    *(double*)argPtr = arg;
                }
                }, args[i]);
        }

        SendData(callData, callData.size());
        CheckStatus();

        std::vector<uint8_t> result = ReceiveData(12);
        uint64_t retval = *(uint64_t*)(result.data() + 4);

        logger->info("Function call returned: 0x" + std::to_string(retval));
        return retval;
    }

    void PS4DBG::LoadElf(int pid, const std::vector<uint8_t>& elf) {
        CheckConnected();
        logger->info("Loading ELF - PID: " + std::to_string(pid) +
            ", Size: " + std::to_string(elf.size()));

        SendCMDPacket(CMDS::CMD_PROC_ELF, 8, { {pid, (uint32_t)elf.size()} });
        CheckStatus();

        SendData(elf, elf.size());
        CheckStatus();
    }

    void PS4DBG::LoadElf(int pid, const std::string& filename) {
        logger->info("Loading ELF from file: " + filename);

        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            logger->error("Failed to open ELF file: " + filename);
            throw std::runtime_error("Failed to open ELF file");
        }

        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> elfData(size);
        if (!file.read((char*)elfData.data(), size)) {
            logger->error("Failed to read ELF file: " + filename);
            throw std::runtime_error("Failed to read ELF file");
        }

        LoadElf(pid, elfData);
    }

    void PS4DBG::ChangeProtection(int pid, uint64_t address, uint32_t length, VM_PROTECTIONS newProt) {
        CheckConnected();
        logger->info("Changing memory protection - PID: " + std::to_string(pid) +
            ", Address: 0x" + std::to_string(address) +
            ", Length: " + std::to_string(length) +
            ", Protection: " + std::to_string((uint32_t)newProt));

        SendCMDPacket(CMDS::CMD_PROC_PROTECT, 20, { {pid, address, length, (uint32_t)newProt} });
        CheckStatus();
    }

    ProcessInfo PS4DBG::GetProcessInfo(int pid) {
        CheckConnected();
        logger->info("Getting process info for PID: " + std::to_string(pid));

        SendCMDPacket(CMDS::CMD_PROC_INFO, 4, { {pid} });
        CheckStatus();

        std::vector<uint8_t> data = ReceiveData(sizeof(ProcessInfo));
        ProcessInfo info = *(ProcessInfo*)data.data();

        logger->info("Process info - Name: " + std::string(info.name) +
            ", Path: " + std::string(info.path) +
            ", TitleID: " + std::string(info.titleid));

        return info;
    }

    uint64_t PS4DBG::AllocateMemory(int pid, int length) {
        CheckConnected();
        logger->info("Allocating memory - PID: " + std::to_string(pid) +
            ", Length: " + std::to_string(length));

        SendCMDPacket(CMDS::CMD_PROC_ALLOC, 8, { {pid, length} });
        CheckStatus();

        std::vector<uint8_t> data = ReceiveData(8);
        uint64_t address = *(uint64_t*)data.data();

        logger->info("Memory allocated at: 0x" + std::to_string(address));
        return address;
    }

    void PS4DBG::FreeMemory(int pid, uint64_t address, int length) {
        CheckConnected();
        logger->info("Freeing memory - PID: " + std::to_string(pid) +
            ", Address: 0x" + std::to_string(address) +
            ", Length: " + std::to_string(length));

        SendCMDPacket(CMDS::CMD_PROC_FREE, 16, { {pid, address, length} });
        CheckStatus();
    }

    std::string PS4DBG::ConvertASCII(const std::vector<uint8_t>& data, int offset) {
        int nullPos = offset;
        while (nullPos < data.size() && data[nullPos] != 0) {
            nullPos++;
        }

        int length = nullPos - offset;
        return std::string(reinterpret_cast<const char*>(data.data() + offset), length);
    }

    std::vector<uint8_t> PS4DBG::SubArray(const std::vector<uint8_t>& data, int offset, int length) {
        return std::vector<uint8_t>(data.begin() + offset, data.begin() + offset + length);
    }

    std::vector<uint8_t> PS4DBG::GetBytesFromObject(const void* obj, size_t size) {
        std::vector<uint8_t> result(size);
        memcpy(result.data(), obj, size);
        return result;
    }

    template<typename T>
    T PS4DBG::GetObjectFromBytes(const std::vector<uint8_t>& buffer) {
        T result;
        memcpy(&result, buffer.data(), sizeof(T));
        return result;
    }

    sockaddr_in PS4DBG::GetBroadcastAddress(const sockaddr_in& address, const sockaddr_in& subnetMask) {
        sockaddr_in result{};
        result.sin_family = AF_INET;
        result.sin_addr.s_addr = address.sin_addr.s_addr | ~subnetMask.sin_addr.s_addr;
        return result;
    }

    void PS4DBG::SendCMDPacket(CMDS cmd, int length, const std::vector<std::variant<char, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t, float, double, std::string, std::vector<uint8_t>>>& fields) {
        CMDPacket packet;
        packet.magic = CMD_PACKET_MAGIC;
        packet.cmd = (uint32_t)cmd;
        packet.datalen = length;

        std::vector<uint8_t> data;

        if (length > 0) {
            for (const auto& field : fields) {
                std::visit([&data](auto&& arg) {
                    using T = std::decay_t<decltype(arg)>;

                    if constexpr (std::is_same_v<T, char>) {
                        uint16_t value = arg;
                        data.insert(data.end(), (uint8_t*)&value, (uint8_t*)&value + sizeof(value));
                    }
                    else if constexpr (std::is_same_v<T, uint8_t>) {
                        uint16_t value = arg;
                        data.insert(data.end(), (uint8_t*)&value, (uint8_t*)&value + sizeof(value));
                    }
                    else if constexpr (std::is_same_v<T, int16_t>) {
                        data.insert(data.end(), (uint8_t*)&arg, (uint8_t*)&arg + sizeof(arg));
                    }
                    else if constexpr (std::is_same_v<T, uint16_t>) {
                        data.insert(data.end(), (uint8_t*)&arg, (uint8_t*)&arg + sizeof(arg));
                    }
                    else if constexpr (std::is_same_v<T, int32_t>) {
                        data.insert(data.end(), (uint8_t*)&arg, (uint8_t*)&arg + sizeof(arg));
                    }
                    else if constexpr (std::is_same_v<T, uint32_t>) {
                        data.insert(data.end(), (uint8_t*)&arg, (uint8_t*)&arg + sizeof(arg));
                    }
                    else if constexpr (std::is_same_v<T, int64_t>) {
                        data.insert(data.end(), (uint8_t*)&arg, (uint8_t*)&arg + sizeof(arg));
                    }
                    else if constexpr (std::is_same_v<T, uint64_t>) {
                        data.insert(data.end(), (uint8_t*)&arg, (uint8_t*)&arg + sizeof(arg));
                    }
                    else if constexpr (std::is_same_v<T, float>) {
                        data.insert(data.end(), (uint8_t*)&arg, (uint8_t*)&arg + sizeof(arg));
                    }
                    else if constexpr (std::is_same_v<T, double>) {
                        data.insert(data.end(), (uint8_t*)&arg, (uint8_t*)&arg + sizeof(arg));
                    }
                    else if constexpr (std::is_same_v<T, std::string>) {
                        data.insert(data.end(), arg.begin(), arg.end());
                    }
                    else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
                        data.insert(data.end(), arg.begin(), arg.end());
                    }
                    }, field);
            }
        }

        logger->debug("Sending command packet - Magic: 0x" + std::to_string(packet.magic) +
            ", Command: 0x" + std::to_string(packet.cmd) +
            ", Data Length: " + std::to_string(packet.datalen));

        SendData(GetBytesFromObject(&packet, sizeof(packet)), sizeof(packet));

        if (length > 0) {
            logger->debug("Sending command data, " + std::to_string(data.size()) + " bytes");
            SendData(data, length);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        logger->debug("Command packet sent: cmd=0x" + std::to_string((uint32_t)cmd) +
            ", length=" + std::to_string(length));
    }

    void PS4DBG::SendData(const std::vector<uint8_t>& data, int length) {
        int remaining = length;
        int offset = 0;

        while (remaining > 0) {
            int chunkSize = std::min(remaining, NET_MAX_LENGTH);
            std::vector<uint8_t> chunk = SubArray(data, offset, chunkSize);

            int sent = send(sock, (char*)chunk.data(), chunkSize, 0);
            if (sent == SOCKET_ERROR) {
                logger->error("Send failed: " + std::to_string(WSAGetLastError()));
                throw std::runtime_error("Failed to send data");
            }

            offset += sent;
            remaining -= sent;
        }
    }

    std::vector<uint8_t> PS4DBG::ReceiveData(int length) {
        std::vector<uint8_t> result;
        result.reserve(length);

        int remaining = length;

        while (remaining > 0) {
            std::vector<uint8_t> buffer(std::min(remaining, NET_MAX_LENGTH));

            int received = recv(sock, (char*)buffer.data(), buffer.size(), 0);
            if (received == SOCKET_ERROR) {
                logger->error("Receive failed: " + std::to_string(WSAGetLastError()));
                throw std::runtime_error("Failed to receive data");
            }

            result.insert(result.end(), buffer.begin(), buffer.begin() + received);
            remaining -= received;
        }

        return result;
    }

    std::string PS4DBG::GetWSAErrorString(int error) {
        switch (error) {
        case WSAETIMEDOUT:
            return "Connection timed out";
        case WSAECONNRESET:
            return "Connection reset by peer";
        case WSAENETDOWN:
            return "Network is down";
        case WSAENETUNREACH:
            return "Network is unreachable";
        case WSAECONNABORTED:
            return "Connection aborted";
        case WSAEWOULDBLOCK:
            return "Resource temporarily unavailable";
        default: return "Unknown error";
        }
    }

    std::string PS4DBG::GetStatusString(CMD_STATUS status) {
        switch (status) {
        case CMD_STATUS::CMD_SUCCESS:
            return "Success";
        case CMD_STATUS::CMD_ERROR:
            return "Error";
        case CMD_STATUS::CMD_TOO_MUCH_DATA:
            return "Too much data";
        case CMD_STATUS::CMD_DATA_NULL:
            return "Data null";
        case CMD_STATUS::CMD_ALREADY_DEBUG:
            return "Already debugging";
        case CMD_STATUS::CMD_INVALID_INDEX:
            return "Invalid index";
        default: return "Unknown status";
        }
    }

    CMD_STATUS PS4DBG::ReceiveStatus() {
        uint32_t status = 0;
        int received = 0;
        int attempts = 0;
        const int MAX_ATTEMPTS = 10;

        logger->info("Attempting to receive status...");

        while (received < 4 && attempts < MAX_ATTEMPTS) {
            logger->debug("Receive attempt #" + std::to_string(attempts + 1) +
                ", received " + std::to_string(received) + " bytes so far");

            int result = recv(sock, ((char*)&status) + received, 4 - received, 0);

            if (result > 0) {
                logger->debug("Received " + std::to_string(result) + " bytes");
                received += result;

                if (received < 4) {
                    logger->debug("Partial status: 0x" +
                        std::to_string(status & ((1 << (received * 8)) - 1)));
                }
            }
            else if (result == 0) {
                logger->error("Connection closed by PS4 during status receive");
                throw std::runtime_error("Connection closed by PS4");
            }
            else {
                int error = WSAGetLastError();
                logger->error("Receive error: " + std::to_string(error) +
                    " (" + GetWSAErrorString(error) + ")");

                if (error == WSAETIMEDOUT) {
                    logger->warning("Receive timed out, retrying...");
                    attempts++;
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }

                throw std::runtime_error("Failed to receive status: " +
                    std::to_string(error) +
                    " (" + GetWSAErrorString(error) + ")");
            }
        }

        if (received < 4) {
            logger->error("Failed to receive complete status after " +
                std::to_string(attempts) + " attempts. Only received " +
                std::to_string(received) + " bytes");
            throw std::runtime_error("Failed to receive complete status after multiple attempts");
        }

        logger->info("Successfully received status: 0x" +
            std::to_string((uint32_t)status) +
            " (" + GetStatusString((CMD_STATUS)status) + ")");

        return (CMD_STATUS)status;
    }

    void PS4DBG::CheckStatus() {
        CMD_STATUS status = ReceiveStatus();
        if (status != CMD_STATUS::CMD_SUCCESS) {
            logger->error("Command failed with status: 0x" + std::to_string((uint32_t)status));
            throw std::runtime_error("libdbg status " + std::to_string((uint32_t)status));
        }
    }

    void PS4DBG::CheckConnected() {
        if (!isConnected) {
            logger->error("Not connected to PS4");
            throw std::runtime_error("libdbg: not connected");
        }
    }

    void PS4DBG::CheckDebugging() {
        if (!isDebugging) {
            logger->error("Not debugging any process");
            throw std::runtime_error("libdbg: not debugging");
        }
    }

    template<typename T>
    T PS4DBG::ReadMemory(int pid, uint64_t address) {
        if constexpr (std::is_same_v<T, std::string>) {
            std::string result;
            uint64_t offset = 0;

            while (true) {
                uint8_t byte = ReadMemory(pid, address + offset, 1)[0];
                if (byte == 0) {
                    break;
                }

                result += (char)byte;
                offset++;
            }

            return result;
        }
        else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
            throw std::runtime_error("Byte arrays are not supported, use ReadMemory(int pid, uint64_t address, int size)");
        }
        else {
            std::vector<uint8_t> data = ReadMemory(pid, address, sizeof(T));
            return *(T*)data.data();
        }
    }

    template<typename T>
    void PS4DBG::WriteMemory(int pid, uint64_t address, const T& value) {
        if constexpr (std::is_same_v<T, std::string>) {
            std::string nullTerminated = value + '\0';
            WriteMemory(pid, address, std::vector<uint8_t>(nullTerminated.begin(), nullTerminated.end()));
        }
        else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
            WriteMemory(pid, address, value);
        }
        else {
            std::vector<uint8_t> data(sizeof(T));
            memcpy(data.data(), &value, sizeof(T));
            WriteMemory(pid, address, data);
        }
    }

    template bool PS4DBG::ReadMemory<bool>(int pid, uint64_t address);
    template int8_t PS4DBG::ReadMemory<int8_t>(int pid, uint64_t address);
    template uint8_t PS4DBG::ReadMemory<uint8_t>(int pid, uint64_t address);
    template int16_t PS4DBG::ReadMemory<int16_t>(int pid, uint64_t address);
    template uint16_t PS4DBG::ReadMemory<uint16_t>(int pid, uint64_t address);
    template int32_t PS4DBG::ReadMemory<int32_t>(int pid, uint64_t address);
    template uint32_t PS4DBG::ReadMemory<uint32_t>(int pid, uint64_t address);
    template int64_t PS4DBG::ReadMemory<int64_t>(int pid, uint64_t address);
    template uint64_t PS4DBG::ReadMemory<uint64_t>(int pid, uint64_t address);
    template float PS4DBG::ReadMemory<float>(int pid, uint64_t address);
    template double PS4DBG::ReadMemory<double>(int pid, uint64_t address);
    template std::string PS4DBG::ReadMemory<std::string>(int pid, uint64_t address);

    template void PS4DBG::WriteMemory<bool>(int pid, uint64_t address, const bool& value);
    template void PS4DBG::WriteMemory<int8_t>(int pid, uint64_t address, const int8_t& value);
    template void PS4DBG::WriteMemory<uint8_t>(int pid, uint64_t address, const uint8_t& value);
    template void PS4DBG::WriteMemory<int16_t>(int pid, uint64_t address, const int16_t& value);
    template void PS4DBG::WriteMemory<uint16_t>(int pid, uint64_t address, const uint16_t& value);
    template void PS4DBG::WriteMemory<int32_t>(int pid, uint64_t address, const int32_t& value);
    template void PS4DBG::WriteMemory<uint32_t>(int pid, uint64_t address, const uint32_t& value);
    template void PS4DBG::WriteMemory<int64_t>(int pid, uint64_t address, const int64_t& value);
    template void PS4DBG::WriteMemory<uint64_t>(int pid, uint64_t address, const uint64_t& value);
    template void PS4DBG::WriteMemory<float>(int pid, uint64_t address, const float& value);
    template void PS4DBG::WriteMemory<double>(int pid, uint64_t address, const double& value);
    template void PS4DBG::WriteMemory<std::string>(int pid, uint64_t address, const std::string& value);

}