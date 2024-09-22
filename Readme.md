# MDNSCPP
[![CMake on multiple platforms](https://github.com/nachooya/mdnscpp/actions/workflows/cmake-multi-platform.yml/badge.svg)](https://github.com/nachooya/mdnscpp/actions/workflows/cmake-multi-platform.yml)
[![CircleCI](https://circleci.com/gh/nachooya/mdnscpp.svg?style=shield)](https://circleci.com/gh/nachooya/mdnscpp)
[![Build Status](https://travis-ci.org/nachooya/mdnscpp.svg?branch=master)](https://travis-ci.org/nachooya/mdnscpp)

Third party
===========
* uuid library from: https://github.com/rtlayzell/uuid

References
============
* Chromium mDNS implementation: https://chromium.googlesource.com/chromium/src/+/master/net/dns

Quick usage
===========
```
git clone https://github.com/nachooya/mdnscpp
cd mdnscpp
mkdir build && cd build && cmake .. -DBUILD_TESTS=ON -DBUILD_UTILS=ON -DCMAKE_BUILD_TYPE=Debug
cd utils && ./nhlookup
```

Build
=====
```
cmake .. -DBUILD_TESTS=ON -DBUILD_UTILS=ON -DCMAKE_BUILD_TYPE=Debug
```
