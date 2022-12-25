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
* pp_map_sup_oatep_k13(fp13_t r, ep_t p, ep13_t q): given $p\in  \mathbb{G}_1 and $q\in \mathbb{G}_2$,  computing $r=e(p,q)$
* ep_map(ep_t p, const uint8_t *msg, int len) : hashing to $\mathbb{G}_1$
* ep13_map(ep13_t p, const uint8_t *msg, int len) : hashing to $\mathbb{G}_2$
*ep_mul(ep_t q, ep_t p, bn_t k) : given a random point $p\in \mathbb{G}_1$ and a random scalar $k$, computing $q=[k]p$
* ep13_mul(ep13_t q, ep13_t p, bn_t k) : given a random point $p\in \mathbb{G}_2$ and a random scalar $k$, computing $q=[k]p$
* fp13_exp_gt(fp13_t h1, fp13_t h0,  bn_t k) : given a random point $h0\in \mathbb{G}_T$ and a random exp$k$, computing $h1=h0^k$
* g1_is_valid_bw13(ep_t p): Checking whether $p$ is a point of $\G_1$.
* g2_is_valid_bw13(ep13_t q): Checking whether $q$ is a point of $\G_2$.
* gt_is_valid_bw13(fp13_t h0):Checking whether $h0$ is a point of $\G_T$.

 ###Benckmarks
Timing results can be obtained by performing the following comggnds：
  

  1. mkdir build && cd build 
  2. ../preset/x64-pbc-bw310.sh ../
  3. make
  4. cd bin 
  5. ./bench_pc_bw13.c

  


