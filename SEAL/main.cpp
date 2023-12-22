#include "bidder.h"
#include "params.h"
#include <cstdlib>
#include <iostream>
#include <vector>

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << DIVIDER << "Usage: " << argv[0] << " <n> <c>" << DIVIDER
              << std::endl;
    return 1;
  }

  size_t n = std::stoul(argv[1]);
  size_t c = std::stoul(argv[2]);
  size_t bit = 0;
  std::vector<Bidder> bidders;
  std::vector<RoundOnePub> roundOnePubs;
  std::vector<RoundTwoPub> roundTwoPubs;

  PRINT_MESSAGE("#bidders: n = " << n << ", bit length of bids: c = " << c);

  for (size_t i = 0; i < n; ++i) {
    bidders.push_back(Bidder(i, c));
  }

  PRINT_MESSAGE("Finished initialization.");

  //   for (size_t j = 0; j < n; ++j) {
  //     bidders[j].commitBid();
  //   }

  //   PRINT_MESSAGE("Finished Commit phase.");

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
      bit = bidders[j].roundThree(roundTwoPubs, i);
    }
    PRINT_MESSAGE("Finished Step " << i << " phase.\n"
                                   << i << "th bit of max bids: " << bit);
  }

  PRINT_MESSAGE("Finished auction.");

  PRINT_MESSAGE("Max bid: " << bidders[0].getMaxBid());

  return 0;
}