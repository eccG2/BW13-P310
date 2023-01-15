### Algorithms

Based on the famous [RELIC cryptographic toolkit](https://github.com/relic-toolkit/relic) we implemented all building blocks related to pairing-based protocols on BW13-P310, including

 * pairing computation.
*  hashing to  $\mathbb{G}_1$ and $\mathbb{G}_2$.
*  group expontiations in  $\mathbb{G}_1$, $\mathbb{G}_2$ and  $\mathbb{G}_T$.
*  membership testings for  $\mathbb{G}_1$, $\mathbb{G}_2$ and  $\mathbb{G}_T$.
### Requirements

The build process requires the [CMake](https://cmake.org/) cross-platform build system. The [GMP](https://gmplib.org/) library is also needed in our benchmarks.

### Build instructions

Instructions for building the library can be found in the [Wiki](https://github.com/relic-toolkit/relic/wiki/Building).


### Source code
  
The main source code of our algorithms are distributed in different folders.  The main functions are:
* pp_map_sup_oatep_k13(fp13_t r, ep_t p, ep13_t q): given $p\in  \mathbb{G}_1$ and $q\in \mathbb{G}_2$,  computing $r=e(p,q)$ 
* ep_map(ep_t p, const uint8_t *msg, int len) : hashing to $\mathbb{G}_1$
* ep13_map(ep13_t p, const uint8_t *msg, int len) : hashing to $\mathbb{G}_2$
* ep_mul(ep_t q, ep_t p, bn_t k) : given a random point $p\in \mathbb{G}_1$ and a random scalar $k$, computing $q=[k]p$
* ep13_mul(ep13_t q, ep13_t p, bn_t k) : given a random point $p\in \mathbb{G}_2$ and a random scalar $k$, computing $q=[k]p$
* fp13_exp_gt(fp13_t h1, fp13_t h0,  bn_t k) : given a random point $h0\in \mathbb{G}_T$ and a random exp $k$, computing $h1={h0}^k$
* g1_is_valid_bw13(ep_t p): Checking whether $p$ is a point of $\mathbb{G}_1$ or not.
* g2_is_valid_bw13(ep13_t q): Checking whether $q$ is a point of $\mathbb{G}_2$ or not.
* gt_is_valid_bw13(fp13_t h0):Checking whether $h0$ is a element of $\mathbb{G}_T$ or not.

### Testings, benckmarks and comparisons
* Testings and benckmarks: Function testings and benckmarking can be done by performing the following commands：

    1. mkdir build && cd build 
    2. ../preset/x64-pbc-bw310.sh ../
    3. make
    4. cd bin 
    5. ./test_bw13  (This is to check that our implementation is corrret)
    5. ./bench_pc_bw13.c (This is to obtain clock cycles of involved operations on BW13-P310)
  
 * Comparisons: With the development of NFS, the parameters of curves have to upated to really reach the 128-bit security level. BW13-P310 is 128-bit secure curve that provides fast multiplication in  $\mathbb{G}_1$. BN-P446 and BLS12-P446 are two mainstream curves in BN and BLS12 families the 128-bit security level, respectievly. See [1](https://link.springer.com/chapter/10.1007/978-3-030-45388-6_19), [2](https://link.springer.com/article/10.1007/s00145-018-9280-5), [3](https://eprint.iacr.org/2019/485.pdf) for details. BLS24-P315 is another interesting curve at this security level that provides fast group exponentiation in $\mathbb{G}_1$. [RELIC cryptographic toolkit](https://github.com/relic-toolkit/relic) has provided high speed implementations for all building blocks related to pairing protocols on these curves. Timing results can be obtained by performing the following commands：
 
   1. mkdir build && cd build 
   2. ../preset/ < preset >.sh ../
   3. make
   4. cd bin 
   5. ./bench_pc.c
  
 
