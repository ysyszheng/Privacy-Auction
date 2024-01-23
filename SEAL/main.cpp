#include "bidder.h"
#include "bulletinBoard.h"
#include "params.h"
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <vector>

int main(int argc, char *argv[]) {
  if (argc != 3) {
    PRINT_ERROR("Usage: " << argv[0] << " <#bidders> <bit length of bids>");
    exit(1);
  }

  size_t n = std::stoul(argv[1]);
  size_t c = std::stoul(argv[2]);
  std::vector<size_t> bids;
  std::vector<Bidder> bidders;
  BulletinBoard bb(n, c);

  PRINT_MESSAGE("#bidders: n = " << n << ", bit length of bids: c = " << c);

  // Initialization phase
  for (size_t i = 0; i < n; ++i) {
    bidders.push_back(Bidder(i, n, c));
    bids.push_back(bidders[i].getBid());
  }

  auto maxBid = *std::max_element(bids.begin(), bids.end());

  PRINT_MESSAGE("Finished initialization.\nMax bid: "
                << maxBid << ", Max bid (in binary): "
                << std::bitset<C_MAX>(maxBid).to_string().substr(C_MAX - c));

  auto start_time = std::chrono::high_resolution_clock::now();

  // Commit phase
  for (size_t j = 0; j < n; ++j) {
    bb.addCommitmentMsg(bidders[j].commitBid(), j);
  }

  // PRINT_MESSAGE("Finished commitment.");

  // Verify commitments
  for (size_t j = 0; j < n; ++j) {
    if (!bidders[j].verifyCommitment(bb.getCommitments())) {
      PRINT_ERROR("Bidder " << j << " failed to verify commitments.");
      exit(1);
    }
  }

  // PRINT_MESSAGE("Finished verification of commitments.");

  // Auction phase, i is the step, j is the bidder id
  for (size_t i = 0; i < c; ++i) {
    for (size_t j = 0; j < n; ++j) {
      bb.addRoundOneMsg(bidders[j].roundOne(i), j);
    }

    // PRINT_MESSAGE("Finished round one in step " << i << ".");

    for (size_t j = 0; j < n; ++j) {
      if (!bidders[j].verifyRoundOne(bb.getRoundOnePubs())) {
        PRINT_ERROR("Bidder " << j << " failed to verify round one in step "
                              << i << ".");
        exit(1);
      }
    }

    // PRINT_MESSAGE("Finished verification of round one in step " << i << ".");

    for (size_t j = 0; j < n; ++j) {
      bb.addRoundTwoMsg(bidders[j].roundTwo(bb.getRoundOnePubs(), i), j);
    }

    // PRINT_MESSAGE("Finished round two in step " << i << ".");

    for (size_t j = 0; j < n; ++j) {
      if (!bidders[j].verifyRoundTwo(bb.getRoundTwoPubs(), i)) {
        PRINT_ERROR("Bidder " << j << " failed to verify round two in step "
                              << i << ".");
        exit(1);
      }
    }

    // PRINT_MESSAGE("Finished verification of round two in step " << i << ".");

    for (size_t j = 0; j < n; ++j) {
      bidders[j].roundThree(bb.getRoundTwoPubs(), i);
    }

    // PRINT_MESSAGE("Finished step " << i << ".");
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
      end_time - start_time);
  double seconds = duration.count() / 1e6;
  PRINT_MESSAGE("Time: " << seconds << "s.");

  // test correctness
  for (size_t i = 0; i < n; ++i) {
    if (bidders[i].getMaxBid() != maxBid) {
      PRINT_ERROR("Bidder " << i << " failed to calculate max bid.");
    }
  }
  PRINT_MESSAGE("Finished auction, all bidder calculated max bid.\nMax bid: "
                << maxBid << ", Max bid (in binary): "
                << std::bitset<C_MAX>(maxBid).to_string().substr(C_MAX - c));

  return 0;
}
