Algorithms
Based on the famous RELIC cryptographic toolkit we implemented:

hashing to  on the BW13-P310 curve with two methods. The first method (Method I) is seen as a generlized Fuentes et al method. The second one (Method II) is a further optimiation based on the first one. The preset file can be found in folder in the name of x64-pbc-bw310.sh

Requirements
The build process requires the CMake cross-platform build system. The GMP library is also needed in our benchmarks.

Build instructions
Instructions for building the library can be found in the Wiki.

Source code
The main source code of our algorithms are distributed in different folders. The main functions are:

ep13_map(ep13_t p, const uint8_t *msg, int len) :Maps a byte array to a point of BW13-P310.
ep13_cof_fuentes(ep13_t r, ep13_t p) : Given a random point p , hashing p to  using Method I.
ep13_cof(ep13_t r, ep13_t p):Given a random point p , hashing p to  using Method II.
hashing to  can be accomplished by perfroming ep13_map()+ep13_cof_fuentes() or ep13_map()+ep13_cof.

Tests and Benckmarks
The functions for tests are presented in test_hash.c. The functions for benckmarking are presented in bench_hash.c Testing and Timing results can be obtained by performing the following commands：

mkdir build && cd build
../preset/x64-pbc-bw310.sh ../
make
cd bin
./test_hash
./bench_hash
