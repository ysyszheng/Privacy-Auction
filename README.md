Privacy Auction
=====

Privacy-preserving auction mechanism implemented using FHE/MPC.

Dependencies
-----

| Name | Version |
| --- | --- |
| [cmake](https://cmake.org/) | >= 3.14 |
| [vcpkg](https://github.com/microsoft/vcpkg) | latest |
| [OpenSSL](https://www.openssl.org/) | 3.2.0 |
| [Crypto++](https://www.cryptopp.com/) | 8.9.0 |

Build and Run
-----

Install vcpkg and thrird-party libraries.

```bash
# install vcpkg
$ cd <YOUR_FAVORITE_DIR> # i.e. cd ~/opt
$ git clone https://github.com/microsoft/vcpkg
$ ./vcpkg/bootstrap-vcpkg.sh
# install third-party libraries
$ ./vcpkg/vcpkg install cryptopp
$ ./vcpkg/vcpkg install openssl
```

Change `set(VCPKG_ROOT "/Users/yusen/opt/vcpkg")` in `CMakeLists.txt` to your vcpkg path.

```bash
# build
$ cd <DIR> # SEAL or CCS22 or TFHE
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build .
# run
$ ./<APP_NAME> <PARAMS> # i.e. ./SEAL 10 20 when <APP_NAME> is SEAL and <PARAMS> are 10 and 20
```

Test
-----

```bash
# After build, in build directory
$ python3 ../tests/genTests.py --tests=100 --bidders_max=50 --bitslen_max=32 # install argparse if needed
$ ctest -V # -V for verbose
```

References
-----

* SEAL: Sealed-Bid Auction without Auctioneers [[iacr]](https://eprint.iacr.org/2019/1332)
* Secure Auctions in the Presence of Rational Adversaries [[iacr]](https://eprint.iacr.org/2022/1541)
* A 2-Round Anonymous Veto Protocol [[springer]](https://link.springer.com/chapter/10.1007/978-3-642-04904-0_28)
* [https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography](https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography)
