#pragma once

#include <atomic>
#include <chrono>
#include <iostream>

class TimeTracker {
public:
    TimeTracker() : total_time_(0), is_timing_(false) {}

    void start() {
        if (is_timing_) {
            std::cerr << "Timer is already running.\n";
            return;
        }
        auto now = std::chrono::high_resolution_clock::now();
        start_time_ = now;
        is_timing_ = true;
    }

    void stop() {
        if (!is_timing_) {
            std::cerr << "Timer is not running.\n";
            return;
        }
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_).count();
        total_time_ += elapsed;
        is_timing_ = false;
    }

    void reset() {
        total_time_ = 0;
        is_timing_ = false;
    }

    double getTotalTimeInSecond() const {
        return static_cast<double>(total_time_) / 1e3; // to seconds
    }

private:
    std::chrono::high_resolution_clock::time_point start_time_;
    std::atomic<long long> total_time_;
    std::atomic<bool> is_timing_;
};

