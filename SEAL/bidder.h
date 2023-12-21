#ifndef BIDDER_H
#define BIDDER_H

#include <string>
#include <iostream>
#include <cryptopp/integer.h>

class Bidder {
public:
    Bidder(std::string name, int c);
    int bid();
    void commitBid();

private:
    std::string name_;
    int bid_;
    int c_;
};

#endif /* BIDDER_H */
