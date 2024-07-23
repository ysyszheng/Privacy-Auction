#include "bidder.h"
#include "bulletinBoard.h"
#include "dataTracker.h"
#include "evaluator.h"
#include "params.h"
#include "print.h"
#include "timeTracker.h"
#include "types.h"
#include <cassert>
#include <cstddef>
#include <iostream>
#include <random>

using namespace std;

int main(int argc, char *argv[]) {
  if (argc != 3) {
    PRINT_ERROR("Usage: " << argv[0] << " <#bidders> <bit length of bids>");
    exit(1);
  }

  size_t n = std::stoul(argv[1]);
  size_t c = std::stoul(argv[2]);
  size_t evaluatorId = 0;
  bool flag = true;

  std::vector<size_t> bids(n); // size of bids is n
  std::vector<Bidder> bidders; // size of bidders (exclude evaluator) is n - 1
  BulletinBoard bb(n, c);

  // ================================================= //
  // =============== Initialization phase ============ //
  // ================================================= //
  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<size_t> dist(0, n - 1);
  evaluatorId = dist(gen);

  auto pos = [evaluatorId](size_t i) {
    assert(i != evaluatorId);
    return i < evaluatorId ? i : i - 1;
  };

  PRINT_MESSAGE("#bidders: n = " << n << ", bit length of bids: c = " << c
                                 << "\n"
                                    "Evaluator: "
                                 << evaluatorId);

  Evaluator evaluator(
      evaluatorId, n, c,
      bb.getPubParams()); // Directly call `bb.getPubParams()` to simulate the
                          // communication process and record the communication
                          // overhead
  for (size_t i = 0; i < n; ++i) {
    if (i == evaluatorId) {
      bids.push_back(evaluator.getBid());
    } else {
      bidders.push_back(Bidder(i, n, c, bb.getPubParams()));
      bids.push_back(bidders[pos(i)].getBid());
    }
  }

  auto maxBid = *std::max_element(bids.begin(), bids.end());

  PRINT_MESSAGE("Finished initialization.\nMax bid: "
                << maxBid << ", Max bid (in binary): "
                << std::bitset<C_MAX>(maxBid).to_string().substr(C_MAX - c));

  // ================================================= //
  // =============== Steup Phase ===================== //
  // ================================================= //
  for (size_t i = 0; i < n; ++i) {
    if (i == evaluatorId) {
      evaluator.setup();
      bb.addCommitmentMsg(i, evaluator.getCommitments());
      bb.addPublicKeyMsg(i, evaluator.getPubKeys());
    } else {
      bidders[pos(i)].setup();
      bb.addCommitmentMsg(i, bidders[pos(i)].getCommitments());
      bb.addPublicKeyMsg(i, bidders[pos(i)].getPubKeys());
    }
  }

  // ================================================= //
  // =============== Computation Phase =============== //
  // ================================================= //
  for (size_t step = 0; step < c; ++step) {
    // ================================================= //
    // ============ Start step-th step ================= //
    // ================================================= //

    // ================================================= //
    // ============== BESEncode ======================== //
    // ================================================= //
    for (size_t i = 0; i < n; ++i) {
      if (i == evaluatorId) {
        evaluator.BESEncode(bb.getPublicKeysByStep(step), step);
      } else {
        bidders[pos(i)].BESEncode(bb.getPublicKeysByStep(step), step);
      }
    }

    // ================================================= //
    // ============== OT Receive 1 ===================== //
    // ================================================= //
    bb.addOTR1Vec(evaluator.OTReceive1(step));

    // ================================================= //
    // ================== OT Send ====================== //
    // ================================================= //
    for (size_t i = 0; i < n; ++i) {
      if (i != evaluatorId) {
        bb.addOTS(pos(i), bidders[pos(i)].OTSend(step, bb.getOTR1(pos(i))));
      }
    }

    // ================================================= //
    // ============== OT Receive 2 ===================== //
    // ================================================= //
    bb.addd(evaluator.OTReceive2(step, bb.getOTSVec()));

    for (size_t i = 0; i < n; ++i) {
      if (i != evaluatorId) {
        bidders[pos(i)].checkIfEnterDeciderRound(step, bb.getd());
      }
    }
    // ================================================= //
    // ============ End step-th step =================== //
    // ================================================= //
  }

  // ================================================= //
  // =======  TODO: Verification Phase =============== //
  // ================================================= //

  // ================================================= //
  // ============== Print info ======================= //
  // ================================================= //

  PRINT_INFO(
      "#bidders: n = "
      << n << ", bit length of bids: c = " << c << std::endl
      << "Time (one bidder): "
      << TimeTracker::getInstance().getCategoryTimeInSeconds(BIDDER_CATEGORY) /
             (n - 1) // n-1 common bidder
      << " s." << std::endl
      << "Time (one evaluator): "
      << TimeTracker::getInstance().getCategoryTimeInSeconds(
             EVALUATOR_CATEGORY) // only 1 evaluator
      << " s." << std::endl
      << "Data (one bidder): "
      << DataTracker::getInstance().getCategoryDataSizeInMB(BIDDER_CATEGORY) /
                 (n - 1) +
             DataTracker::getInstance().getCategoryDataSizeInMB(
                 BIDDER_AND_EVALUATOR_CATEGORY) /
                 n
      << " MB" << std::endl
      << "Data (one evaluator): "
      << DataTracker::getInstance().getCategoryDataSizeInMB(
             EVALUATOR_CATEGORY) +
             DataTracker::getInstance().getCategoryDataSizeInMB(
                 BIDDER_AND_EVALUATOR_CATEGORY) /
                 n
      << " MB" << std::endl
      << "Data (total communication, #bidders=" << n - 1
      << " ,#evaluators=" << 1
      << "): " << DataTracker::getInstance().getTotalDataSizeInMB() << " MB");
  // TODO: time for verifier + data

  // ================================================= //
  // ============== Test Correctness ================= //
  // ================================================= //
  for (size_t i = 0; i < n; ++i) {
    if (i == evaluatorId) {
      if (evaluator.getMaxBid() != maxBid) {
        flag = false;
        PRINT_ERROR("Evaluator " << i << " failed to calculate max bid.\n"
                                 << std::bitset<C_MAX>(evaluator.getMaxBid())
                                        .to_string()
                                        .substr(C_MAX - c));
      }
    } else {
      if (bidders[pos(i)].getMaxBid() != maxBid) {
        flag = false;
        PRINT_ERROR("Bidder " << i << " failed to calculate max bid.\n"
                              << std::bitset<C_MAX>(bidders[pos(i)].getMaxBid())
                                     .to_string()
                                     .substr(C_MAX - c));
      }
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
