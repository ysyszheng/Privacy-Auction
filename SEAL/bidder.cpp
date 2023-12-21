#include "bidder.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
#include <iostream>
#include <random>

using namespace std;
using namespace CryptoPP;

Bidder::Bidder(string name, int c) : name_(name), c_(c) {
  // Generate random bid between 0 and 2^c - 1
  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<int> dist(0, (1 << c) - 1);
  bid_ = dist(gen);
}

int Bidder::bid() { return bid_; }

void Bidder::commitBid() {
  // Initialize Random Number Generator
  AutoSeededRandomPool rng;

  // Convert bid_ to binary representation
  string binaryBid = bitset<32>(bid_).to_string().substr(32 - c_);

  cout << "Bidder: " << name_ << "\nOriginal Bid (in binary): " << binaryBid
       << endl;

  // Commitment for each bit of bid_
  for (int i = 0; i < c_; ++i) {
    // Random alpha and beta
    Integer alpha(rng, Integer::One(), Integer::Zero(), Integer::One() - 1);
    Integer beta(rng, Integer::One(), Integer::Zero(), Integer::One() - 1);

    // Convert bits to Integer
    Integer pi(binaryBid[i] - '0');

    // Calculate commitment values
    Integer g = Integer("your_g_value_here"); // Replace "your_g_value_here"
                                              // with the actual value of g
    Integer commitment = PowerMod(g, pi, p) * PowerMod(g, alpha * beta, p);
    Integer commitmentAlpha = PowerMod(g, alpha, p);
    Integer commitmentBeta = PowerMod(g, beta, p);

    // Display commitment for this bit
    cout << "Bit " << i + 1 << " commitment: "
         << commitment.Encode(ByteQueue(), commitment.ByteCount()) << endl;
    cout << "Bit " << i + 1 << " alpha: "
         << commitmentAlpha.Encode(ByteQueue(), commitmentAlpha.ByteCount())
         << endl;
    cout << "Bit " << i + 1 << " beta: "
         << commitmentBeta.Encode(ByteQueue(), commitmentBeta.ByteCount())
         << endl;
  }
}