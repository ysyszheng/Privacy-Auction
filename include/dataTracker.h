#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>

class DataTracker {
public:
  static DataTracker &getInstance() {
    static DataTracker instance;
    return instance;
  }

  void addData(const std::string &category, size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    totalDataSize_ += size;
    categoryDataSizes_[category] += size;
  }

  size_t getTotalDataSize() const { return totalDataSize_; }

  size_t getCategoryDataSize(const std::string &category) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = categoryDataSizes_.find(category);
    if (it != categoryDataSizes_.end()) {
      return it->second;
    }
    return 0;
  }

private:
  DataTracker() : totalDataSize_(0) {}
  DataTracker(const DataTracker &) = delete;
  DataTracker &operator=(const DataTracker &) = delete;

  std::atomic<size_t> totalDataSize_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, size_t> categoryDataSizes_;
};
