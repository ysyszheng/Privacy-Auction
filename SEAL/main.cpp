#include "bidder.h"
#include "bulletinBoard.h"
#include "dataTracker.h"
#include "params.h"
#include "print.h"
#include "timeTracker.h"
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
  bool flag = true;

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

  TimeTracker bidderTimeTracker;       // Consider the total running time of all
                                       // bidders and divide it by #bidders
  TimeTracker verificationTimeTracker; // Only consider the verification time of
                                       // one verifier

  // Commit phase
  bidderTimeTracker.start();
  for (size_t j = 0; j < n; ++j) {
    bb.addCommitmentMsg(bidders[j].commitBid(), j);
  }
  bidderTimeTracker.stop();

  // PRINT_MESSAGE("Finished commitment.");

#ifdef ENABLE_VERIFICATION
  // Verify commitments
  verificationTimeTracker.start();
  for (size_t j = 0; j < n; ++j) {
    if (!bidders[j].verifyCommitment(bb.getCommitments())) {
      PRINT_ERROR("Bidder " << j << " failed to verify commitments.");
      exit(1);
    }
  }
  verificationTimeTracker.stop();
#endif

  // PRINT_MESSAGE("Finished verification of commitments.");

  // Auction phase, i is the step, j is the bidder id
  for (size_t i = 0; i < c; ++i) {
    bidderTimeTracker.start();
    for (size_t j = 0; j < n; ++j) {
      bb.addRoundOneMsg(bidders[j].roundOne(i), j);
    }
    bidderTimeTracker.stop();

    // PRINT_MESSAGE("Finished round one in step " << i << ".");

#ifdef ENABLE_VERIFICATION
    verificationTimeTracker.start();
    for (size_t j = 0; j < n; ++j) {
      if (!bidders[j].verifyRoundOne(bb.getRoundOnePubs())) {
        PRINT_ERROR("Bidder " << j << " failed to verify round one in step "
                              << i << ".");
        exit(1);
      }
    }
    verificationTimeTracker.stop();
#endif

    // PRINT_MESSAGE("Finished verification of round one in step " << i << ".");

    bidderTimeTracker.start();
    for (size_t j = 0; j < n; ++j) {
      bb.addRoundTwoMsg(bidders[j].roundTwo(bb.getRoundOneXs(), i), j);
    }
    bidderTimeTracker.stop();

    // PRINT_MESSAGE("Finished round two in step " << i << ".");

#ifdef ENABLE_VERIFICATION
    verificationTimeTracker.start();
    for (size_t j = 0; j < n; ++j) {
      if (!bidders[j].verifyRoundTwo(bb.getRoundTwoPubs(), i)) {
        PRINT_ERROR("Bidder " << j << " failed to verify round two in step "
                              << i << ".");
        exit(1);
      }
    }
    verificationTimeTracker.stop();
#endif

    // PRINT_MESSAGE("Finished verification of round two in step " << i << ".");

    bidderTimeTracker.start();
    for (size_t j = 0; j < n; ++j) {
      bidders[j].roundThree(bb.getRoundTwoBs(), i);
    }
    bidderTimeTracker.stop();

    // PRINT_MESSAGE("Finished step " << i << ".");
  }

  PRINT_INFO(
      "Time (one bidder): "
      << bidderTimeTracker.getTotalTimeInSecond() / n << " s." << std::endl
      << "Time (one verifier): "
      << verificationTimeTracker.getTotalTimeInSecond() / n << " s."
      << std::endl
      << "Data (one bidder): "
      << static_cast<double>(
             DataTracker::getInstance().getCategoryDataSize(BIDDER_CATEGORY)) /
             (1024 * 1024) / n
      << " MB" << std::endl
      << "Data (one verifier): "
      << static_cast<double>(DataTracker::getInstance().getCategoryDataSize(
             VERIFIER_CATEGORY)) /
             (1024 * 1024) / n
      << " MB");

  // test correctness
  for (size_t i = 0; i < n; ++i) {
    if (bidders[i].getMaxBid() != maxBid) {
      flag = false;
      PRINT_ERROR("Bidder " << i << " failed to calculate max bid.");
    }
  }
  if (flag) {
    PRINT_MESSAGE("Finished auction, all bidder calculated max bid.\nMax bid: "
                  << maxBid << ", Max bid (in binary): "
                  << std::bitset<C_MAX>(maxBid).to_string().substr(C_MAX - c));
  }
  return 0;
}
