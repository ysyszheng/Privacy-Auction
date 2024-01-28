#pragma once

#include <atomic>

class DataTracker {
public:
  static DataTracker& getInstance() {
    static DataTracker instance;
    return instance;
  }

  void addData(size_t size) {
    totalDataSize_ += size;
  }

  size_t getTotalDataSize() const {
    return totalDataSize_;
  }

private:
  DataTracker() : totalDataSize_(0) {}
  std::atomic<size_t> totalDataSize_;
};
