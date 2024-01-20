#include "bidder.h"
#include "params.h"
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <vector>

int main(int argc, char *argv[]) {
  if (argc != 3) {
    PRINT_ERROR("Usage: " << argv[0] << " <n> <c>");
    return 1;
  }

  size_t n = std::stoul(argv[1]);
  size_t c = std::stoul(argv[2]);
  std::vector<size_t> bids;
  std::vector<Bidder> bidders;
  std::vector<CommitmentPub> commitments;
  std::vector<RoundOnePub> roundOnePubs;
  std::vector<RoundTwoPub> roundTwoPubs;

  PRINT_MESSAGE("#bidders: n = " << n << ", bit length of bids: c = " << c);

  // Initialization phase
  for (size_t i = 0; i < n; ++i) {
    bidders.push_back(Bidder(i, c, n));
    bids.push_back(bidders[i].getBid());
  }

  auto maxBid = *std::max_element(bids.begin(), bids.end());

  PRINT_MESSAGE("Finished initialization.\nMax bid: "
                << maxBid << ", Max bid (in binary): "
                << std::bitset<C_MAX>(maxBid).to_string().substr(C_MAX - c));

  // TODO: use communication channel to send bids to auctioneer
  // Commit phase
  for (size_t j = 0; j < n; ++j) {
    commitments.push_back(bidders[j].commitBid());
  }

  PRINT_MESSAGE("Finished commitment.");

  // Verify commitments
  for (size_t j = 0; j < n; ++j) {
    if (!bidders[j].verifyCommitment(commitments)) {
      PRINT_ERROR("Bidder " << j << " failed to verify commitments.");
    }
  }

  PRINT_MESSAGE("Finished verification of commitments.");

  // Auction phase
  for (size_t i = 0; i < c; ++i) {
    roundOnePubs.clear();
    roundTwoPubs.clear();

    for (size_t j = 0; j < n; ++j) {
      roundOnePubs.push_back(bidders[j].roundOne(i));
    }

    for (size_t j = 0; j < n; ++j) {
      if (!bidders[j].verifyRoundOne(roundOnePubs)) {
        PRINT_ERROR("Bidder " << j << " failed to verify round one in step "
                              << i << ".");
      }
    }

    for (size_t j = 0; j < n; ++j) {
      roundTwoPubs.push_back(bidders[j].roundTwo(roundOnePubs, i));
    }

    for (size_t j = 0; j < n; ++j) {
      if (!bidders[j].verifyRoundTwo(roundTwoPubs, i)) {
        PRINT_ERROR("Bidder " << j << " failed to verify round two in step "
                              << i << ".");
      }
    }

    for (size_t j = 0; j < n; ++j) {
      bidders[j].roundThree(roundTwoPubs, i);
    }

    PRINT_MESSAGE("Finished step " << i << ".");
  }

  // test
  for (size_t i = 0; i < n; ++i) {
    if (bidders[i].getMaxBid() != maxBid) {
      PRINT_ERROR("Bidder " << i << " failed to calculate max bid.");
    }
  }
  PRINT_MESSAGE("Finished auction, max bid: " << maxBid);

  return 0;
}