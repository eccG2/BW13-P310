### Algorithms

Based on the famous [RELIC cryptographic toolkit](https://github.com/relic-toolkit/relic) we implemented all building blocks related to pairing-based protocols on BW13-P310, including

 * pairing computation.
*  hashing to  $\mathbb{G}_1$ and $\mathbb{G}_2$.
*  group expontiations in  $\mathbb{G}_1$, $\mathbb{G}_2$ and  $\mathbb{G}_T$.
* subgroup membership testings for  $\mathbb{G}_1$, $\mathbb{G}_2$ and  $\mathbb{G}_T$.
### Requirements

The build process requires the [CMake](https://cmake.org/) cross-platform build system. The [GMP](https://gmplib.org/) library is also needed in our benchmarks.

### Build instructions

Instructions for building the library can be found in the [Wiki](https://github.com/relic-toolkit/relic/wiki/Building).


### Source code
  
The main source code of our algorithms are distributed in different folders.  The main functions are:

* ep13_map(ep13_t p, const uint8_t *msg, int len) :Maps a byte array to a point of BW13-P310.
* ep13_cof_fuentes(ep13_t r, ep13_t p) : Given a random point p , hashing p to $\mathbb{G}_2$ using Method I.
* ep13_cof(ep13_t r, ep13_t p):Given a random point p , hashing p to $\mathbb{G}_2$ using Method II.

 hashing to $\mathbb{G}_2$  can be accomplished by perfroming ep13_map()+ep13_cof_fuentes() or  ep13_map()+ep13_cof.

 ### Tests and Benckmarks
The functions for tests are presented in [test_hash.c](https://github.com/eccdaiy39/hashing/tree/master/hashing-relic/test/test_hash.c).
 The functions for benckmarking are presented in [bench_hash.c](https://github.com/eccdaiy39/hashing/tree/master/hashing-relic/bench/bench_hash.c)
 Testing and Timing results can be obtained by performing the following commands：
  

  1. mkdir build && cd build 
  2. ../preset/x64-pbc-bw310.sh ../
  3. make
  4. cd bin 
  5. ./test_hash
  6. ./bench_hash
  


