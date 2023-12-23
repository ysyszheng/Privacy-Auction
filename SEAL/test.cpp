#include "bidder.h"
#include "params.h"
#include <iostream>
#include <random>
#include <vector>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    PRINT_ERROR("Usage: " << argv[0] << " <#totalTests>");
    return 1;
  }

  size_t totalTests = std::stoul(argv[1]);

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<size_t> dist_n(1, 100);
  std::uniform_int_distribution<size_t> dist_c(1, C_MAX);

  for (size_t test = 0; test < totalTests; ++test) {
    size_t n = dist_n(gen);
    size_t c = dist_c(gen);
    std::vector<Bidder> bidders;
    std::vector<size_t> bids;
    std::vector<RoundOnePub> roundOnePubs;
    std::vector<RoundTwoPub> roundTwoPubs;

    PRINT_MESSAGE("Test #" << test + 1 << "\n"
                           << "n = " << n << ", c = " << c);

    for (size_t i = 0; i < n; ++i) {
      bidders.push_back(Bidder(i, c));
      bids.push_back(bidders[i].getBid());
    }

    size_t maxBid = *std::max_element(bids.begin(), bids.end());

    for (size_t i = 0; i < c; ++i) {
      roundOnePubs.clear();
      roundTwoPubs.clear();

      for (size_t j = 0; j < n; ++j) {
        roundOnePubs.push_back(bidders[j].roundOne(i));
      }

      for (size_t j = 0; j < n; ++j) {
        roundTwoPubs.push_back(bidders[j].roundTwo(roundOnePubs, i));
      }

      for (size_t j = 0; j < n; ++j) {
        bidders[j].roundThree(roundTwoPubs, i);
      }
    }

    for (size_t i = 0; i < n; ++i) {
      if (bidders[i].getMaxBid() != maxBid) {
        PRINT_ERROR("Test #" << test + 1 << " failed!");
        return 1;
      }
    }
  }

  std::cout << "All tests passed!" << std::endl;
  return 0;
}
