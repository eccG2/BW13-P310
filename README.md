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
* ep_mul(ep_t q, ep_t p, bn_t k) : given a random point $p\in \mathbb{G}_1$ and a random scalar $k$, computing $q=[k]p$
* ep13_mul(ep13_t q, ep13_t p, bn_t k) : given a random point $p\in \mathbb{G}_2$ and a random scalar $k$, computing $q=[k]p$
* fp13_exp_gt(fp13_t h1, fp13_t h0,  bn_t k) : given a random point $h0\in \mathbb{G}_T$ and a random exp $k$, computing $h1={h0}^k$
* g1_is_valid_bw13(ep_t p): Checking whether $p$ is a point of $\mathbb{G}_1$.
* g2_is_valid_bw13(ep13_t q): Checking whether $q$ is a point of $\mathbb{G}_2$.
* gt_is_valid_bw13(fp13_t h0):Checking whether $h0$ is a point of $\mathbb{G}_T$.

### Benckmarks and comparisons
* Benckmarks: Timing results can be obtained by performing the following commands：
![image](https://github.com/eccG2/BW13-P310/blob/master/IMG/A.png)
  

  1. mkdir build && cd build 
  2. ../preset/x64-pbc-bw310.sh ../
  3. make
  4. cd bin 
  5. ./bench_pc_bw13.c
 * Comparisons: With the development of NFS, the parameters of curves have to upated to really reach the 128-bit security level. BW13-P310 is 128-bit secure curve that provides fast multiplication in $\mathbb{G}_1$. BN-P446 and BLS12-P446 are two mainstream curves in BN and BLS12 families the 128-bit security level, respectievly. See [1](https://link.springer.com/chapter/10.1007/978-3-030-45388-6_19),[2](https://link.springer.com/article/10.1007/s00145-018-9280-5), [3](https://eprint.iacr.org/2019/485.pdf) for details.[RELIC cryptographic toolkit](https://github.com/relic-toolkit/relic)  has provided high speed implementations for all building blocks related to pairing protocols on these curves. Timing results can be obtained by performing the following commands：
 
  1. mkdir build && cd build 
  2. ../preset/<preset>.sh ../
  3. make
  4. cd bin 
  5. ./bench_pc.c
  
  Another 128-bit secure curve that provides fast multiplication in $\mathbb{G}_1$ is BLS24-P315, which was implemented in the latest  [RELIC cryptographic toolkit](https://github.com/relic-toolkit/relic) 
  
  
 Running as follows, we can compare BW13-P310 to BN-P446, BLS12-P446 and BLS24-P315 for the performance of pairing computation, hashing to $\mathbb{G}_1$ and $\mathbb{G}_2$, group expontiations in  $\mathbb{G}_1$, $\mathbb{G}_2$ and  $\mathbb{G}_T$, and subgroup membership testings for  $\mathbb{G}_1$, $\mathbb{G}_2$ and  $\mathbb{G}_T$. We benchmakred on a 64-
bit Intel Core i9-12900K @2.3GHz processor running Ubuntu 22.04.1 LTS with
TurboBoost and hyper-threading features disabled. Clock cycles are obtain averaged over 10,000 executions. 
  
  
  
  
  


