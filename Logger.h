#include <string>
#include <fstream>
#include <iostream>
#include <chrono>
#include <mutex>
#include <filesystem>

namespace PS4Debug {

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERR0R,
    CRITICAL
};

class Logger {
public:
    Logger(const std::string& logFilePath = "ps4debug.log", LogLevel minLevel = LogLevel::INFO) 
        : logFile(logFilePath, std::ios::app), minLogLevel(minLevel) {
        if (!logFile.is_open()) {
            std::cerr << "Failed to open log file: " << logFilePath << std::endl;
        }
    }

    ~Logger() {
        if (logFile.is_open()) {
            logFile.close();
        }
    }

    void setLogLevel(LogLevel level) {
        minLogLevel = level;
    }

    void debug(const std::string& message) {
        log(LogLevel::DEBUG, message);
    }

    void info(const std::string& message) {
        log(LogLevel::INFO, message);
    }

    void warning(const std::string& message) {
        log(LogLevel::WARNING, message);
    }

    void error(const std::string& message) {
        log(LogLevel::ERR0R, message);
    }

    void critical(const std::string& message) {
        log(LogLevel::CRITICAL, message);
    }

private:
    void log(LogLevel level, const std::string& message) {
        if (level < minLogLevel) {
            return;
        }

        std::lock_guard<std::mutex> lock(logMutex);
        
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        std::string levelStr;
        switch (level) {
            case LogLevel::DEBUG:    levelStr = "DEBUG"; break;
            case LogLevel::INFO:     levelStr = "INFO"; break;
            case LogLevel::WARNING:  levelStr = "WARNING"; break;
            case LogLevel::ERR0R:    levelStr = "ERROR"; break;
            case LogLevel::CRITICAL: levelStr = "CRITICAL"; break;
        }
        
        std::time_t time111 = std::time(nullptr);
        std::tm tm{};
        localtime_s(&tm, &time111);

        logFile << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
            << "] [" << levelStr << "] " << message << std::endl;

        if (level >= LogLevel::ERR0R) {
            std::cerr << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
                << "] [" << levelStr << "] " << message << std::endl;
        }
    }

    std::ofstream logFile;
    LogLevel minLogLevel;
    std::mutex logMutex;
};

}