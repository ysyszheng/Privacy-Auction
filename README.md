Privacy Auction
=====

Privacy-preserving auction mechanism implemented using FHE/MPC.

Dependencies
-----

| Name | Version |
| --- | --- |
| [cmake](https://cmake.org/) | >= 3.14 |
| [vcpkg](https://github.com/microsoft/vcpkg) | >= 2023.12.12 |
| [OpenSSL](https://www.openssl.org/) | 3.2.0 |
| [Crypto++](https://www.cryptopp.com/) | 8.9.0 |

Build and Run
-----

```bash
# build
cd <DIR> # SEAL or CCS22 or TFHE
mkdir build
cd build
cmake ..
cmake --build .
# run
./<APP_NAME> <PARAMS> # i.e. ./SEAL 10 20 when <APP_NAME> is SEAL and <PARAMS> are 10 and 20
```

References
-----

* SEAL: Sealed-Bid Auction without Auctioneers [[iacr]](https://eprint.iacr.org/2019/1332)
* Secure Auctions in the Presence of Rational Adversaries [[iacr]](https://eprint.iacr.org/2022/1541)
* A 2-Round Anonymous Veto Protocol [[springer]](https://link.springer.com/chapter/10.1007/978-3-642-04904-0_28)
* [https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography](https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography)
