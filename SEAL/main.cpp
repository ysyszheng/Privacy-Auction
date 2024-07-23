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

  // ================================================= //
  // =============== Initialization phase ============ //
  // ================================================= //
  for (size_t i = 0; i < n; ++i) {
    bidders.push_back(Bidder(i, n, c));
    bids.push_back(bidders[i].getBid());
  }

  auto maxBid = *std::max_element(bids.begin(), bids.end());

  PRINT_MESSAGE("Finished initialization.\nMax bid: "
                << maxBid << ", Max bid (in binary): "
                << std::bitset<C_MAX>(maxBid).to_string().substr(C_MAX - c));

  // ================================================= //
  // =============== Commit phase ==================== //
  // ================================================= //
  for (size_t j = 0; j < n; ++j) {
    bb.addCommitmentMsg(bidders[j].commitBid(), j);
  }

#ifdef ENABLE_VERIFICATION
  // ================================================= //
  // =============== Verify commitments ============== //
  // ================================================= //
  for (size_t j = 0; j < n; ++j) {
    if (!bidders[j].verifyCommitment(bb.getCommitments())) {
      PRINT_ERROR("Bidder " << j << " failed to verify commitments.");
      exit(1);
    }
  }
#endif

  // ============================================================ //
  // ===== Auction phase, i is the step, j is the bidder id ===== //
  // ============================================================ //
  for (size_t i = 0; i < c; ++i) {
    // ================================================= //
    // =============== Start step i ==================== //
    // ================================================= //

    // ================================================= //
    // =============== Round One ======================= //
    // ================================================= //
    for (size_t j = 0; j < n; ++j) {
      bb.addRoundOneMsg(bidders[j].roundOne(i), j);
    }

#ifdef ENABLE_VERIFICATION
    // ================================================= //
    // =============== Verify Round One ================ //
    // ================================================= //
    for (size_t j = 0; j < n; ++j) {
      if (!bidders[j].verifyRoundOne(bb.getRoundOnePubs())) {
        PRINT_ERROR("Bidder " << j << " failed to verify round one in step "
                              << i << ".");
        exit(1);
      }
    }
#endif

    // ================================================= //
    // =============== Round Two ======================= //
    // ================================================= //
    for (size_t j = 0; j < n; ++j) {
      bb.addRoundTwoMsg(bidders[j].roundTwo(bb.getRoundOneXs(), i), j);
    }

#ifdef ENABLE_VERIFICATION
    // ================================================= //
    // =============== Verify Round Two ================ //
    // ================================================= //
    for (size_t j = 0; j < n; ++j) {
      if (!bidders[j].verifyRoundTwo(bb.getRoundTwoPubs(), i)) {
        PRINT_ERROR("Bidder " << j << " failed to verify round two in step "
                              << i << ".");
        exit(1);
      }
    }
#endif

    // ================================================= //
    // =============== Round Three ===================== //
    // ================================================= //
    for (size_t j = 0; j < n; ++j) {
      bidders[j].roundThree(bb.getRoundTwoBs(), i);
    }

    // ================================================= //
    // =============== Finish Step i =================== //
    // ================================================= //
  }

  // ================================================= //
  // =======  TODO: Reveal winner ==================== //
  // ================================================= //

  // ================================================= //
  // =============== Print info ====================== //
  // ================================================= //
  PRINT_INFO(
      "#bidders: n = "
      << n << ", bit length of bids: c = " << c << std::endl
      << "Time (one bidder): "
      << TimeTracker::getInstance().getCategoryTimeInSeconds(BIDDER_CATEGORY) /
             n
      << " s." << std::endl
      << "Time (one verifier): "
      << TimeTracker::getInstance().getCategoryTimeInSeconds(
             VERIFIER_CATEGORY) /
             n
      << " s." << std::endl
      << "Data (one bidder): "
      << DataTracker::getInstance().getCategoryDataSizeInMB(BIDDER_CATEGORY) / n
      << " MB" << std::endl
      << "Data (one verifier): "
      << DataTracker::getInstance().getCategoryDataSizeInMB(VERIFIER_CATEGORY) /
             n
      << " MB" << std::endl
      << "Data (total communication, #bidders=" << n << " ,#verifiers=" << n
      << "): " << DataTracker::getInstance().getTotalDataSizeInMB() << " MB");

  // ================================================= //
  // ============== Test Correctness ================= //
  // ================================================= //
  for (size_t i = 0; i < n; ++i) {
    if (bidders[i].getMaxBid() != maxBid) {
      flag = false;
      PRINT_ERROR("Bidder " << i << " failed to calculate max bid.");
    }
  }
  if (!flag) {
    exit(1);
  }
  PRINT_MESSAGE("Finished auction, all bidder calculated max bid.\nMax bid: "
                << maxBid << ", Max bid (in binary): "
                << std::bitset<C_MAX>(maxBid).to_string().substr(C_MAX - c));
  return 0;
}
