#pragma once

#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>

class TimeTracker {
public:
  static TimeTracker &getInstance() {
    static TimeTracker instance;
    return instance;
  }

  void start(const std::string &category) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (isTiming_[category]) {
      std::cerr << "Timer for category " << category
                << " is already running.\n";
      return;
    }
    startTimes_[category] = std::chrono::high_resolution_clock::now();
    isTiming_[category] = true;
  }

  void stop(const std::string &category) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!isTiming_[category]) {
      std::cerr << "Timer for category " << category << " is not running.\n";
      return;
    }
    auto now = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now - startTimes_[category])
                       .count();
    totalTime_[category] += elapsed;
    isTiming_[category] = false;
  }

  void reset(const std::string &category) {
    std::lock_guard<std::mutex> lock(mutex_);
    totalTime_[category] = 0;
    isTiming_[category] = false;
  }

  double getCategoryTimeInSeconds(const std::string &category) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = totalTime_.find(category);
    if (it != totalTime_.end()) {
      return static_cast<double>(it->second) / 1e3; // to seconds
    }
    return 0.0;
  }

  double getTotalTimeInSeconds() const { // ! don't use this
    std::lock_guard<std::mutex> lock(mutex_);
    long long total = 0;
    for (const auto &pair : totalTime_) {
      total += pair.second;
    }
    return static_cast<double>(total) / 1e3; // to seconds
  }

private:
  TimeTracker() {}
  TimeTracker(const TimeTracker &) = delete;
  TimeTracker &operator=(const TimeTracker &) = delete;

  mutable std::mutex mutex_;
  std::unordered_map<std::string,
                     std::chrono::high_resolution_clock::time_point>
      startTimes_;
  std::unordered_map<std::string, long long> totalTime_;
  std::unordered_map<std::string, bool> isTiming_;
};
