/*header for UCK protocols*/

#include "relic_conf.h"
#include "relic_types.h"
#include "relic_util.h"
#include "relic_bn.h"
#include "relic_ec.h"
#include "relic_pc.h"
#include "relic_mpc.h"

#define KEX_SECRETKEYBYTES 32
#define KEX_PUBLICKEYBYTES 1008
#define KEX_SECRETKEYBYTES_ALICE 78
#define KEX_SECRETKEYBYTES_BOB 1008
#define KEX_BYTES 504
#define KEX_ALGNAME “Unbalanced Chen-Kudla (UCK)”

/**
 * Generate a master key for TA and computes secret keys of Alice and Bob on BW13-P310 curve.
 *
 * @param[out] pk   - the public key.
 * @param[out] master_sk    - the master key.
 * @param[out] sk_a - the secret key for Alice.
 * @param[in] id   - the id of Alice.
 * @param[out] sk_b	- the secret key for Bob.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
int kex_keygen_k13(ep13_t pk, bn_t master_sk, g1_t sk_a, const char *id, ep13_t sk_b);

/**
 * Precompute the pairing e(sk_a,pk) and the value of hash id of Alice to G_1 on BW13-P310 curve.
 *
 * @param[out] pair	- the value of e(sk_a,pk).
 * @param[in] sk_a	- the secret key for Alice.
 * @param[out] sa   - the value of hash id of Alice to G_1
 * @param[in] id	- the id of Alice.
 * @param[in] pk   - the public key.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
int uck_pre_k13(fp13_t pair, g1_t sk_a, g1_t sa, const char *id, ep13_t pk);

/**
 * Compute the shared key on BW13-P310 curve.
 *
 * @param[out] ss	- the shared key.
 * @param[in] pk   - the public key.
 * @param[in] sa   - the value of hash id of Alice to G_1
 * @param[in] id	- the id of Alice.
 * @param[in] sk_a	- the secret key for Alice.
 * @param[in] sk_b	- the secret key for Bob.
 * @param[in] pair	- the value of e(sk_a,pk).
 * @return RLC_OK if no errors occurred and the shared key is correct, RLC_ERR otherwise.
 */
int kex_kdf_k13(fp13_t ss,  ep13_t pk, g1_t sa, const char *id, g1_t sk_a, ep13_t sk_b, const fp13_t pair);

/**
 * Random a 256-bit integer and compute a scalar multiplication in G_1 on BW13-P310 curve.
 *
 * @param[out] R1   - [r1]sk_a
 * @param[in] sk_a - the secret key for Alice.
 * @param[out] r1  - a 256-bit integer.
 */
void round_alice_1(g1_t R1,const g1_t sk_a,bn_t r1);

#if FP_PRIME == 310

/**
 * Random a 256-bit integer and compute a pairing e([r3]R1,pk) on BW13-P310 curve.
 *
 * @param[out] g   - e([r3]R1,pk).
 * @param[out] A - the value of hash id of Alice to G_1.
 * @param[in] R1 - R1=[r1]sk_a.
 * @param[in] pk   - the public key.
 * @param[in] id	- the id of Alice.
 * @param[out] r3  - a 256-bit integer.
 */
void round_bob_1(fp13_t g,g1_t A, g1_t R1, ep13_t pk, const char *id,bn_t r3);

/**
 * Complete the rest computations and obain the shared key for Alice on BW13-P310 curve.
 *
 * @param[out] ss_a   - the shared key computed by Alice.
 * @param[out] R2 - R2 = [r2]A.
 * @param[in] g - e([r3]R1,pk).
 * @param[in] sa   - the value of hash id of Alice to G_1.
 * @param[in] pair	- the value of e(sk_a,pk).
 * @param[in] r1  - a 256-bit integer.
 * @param[in] r2  - a 256-bit integer.
 */
int round_alice_2(fp13_t ss_a,g1_t R2, fp13_t g,g1_t sa, const fp13_t pair,bn_t r1,bn_t r2);

/**
 * Complete the rest computations and obain the shared key for Bob on BW13-P310 curve.
 *
 * @param[out] ss_b   - the shared key computed by Bob.
 * @param[in] R2 - R2 = [r2]A.
 * @param[in] A - the value of hash id of Alice to G_1.
 * @param[in] r3  - a 256-bit integer.
 * @param[in] sk_b	- the secret key for Bob.
 */
void round_bob_2(fp13_t ss_b,g1_t R2,g1_t A,bn_t r3, ep13_t sk_b);
#elif FP_PRIME == 446

/**
 * Random a 256-bit integer and compute a pairing e([r3]R1,pk) on BLS12-P446 and BN-P446 curves.
 *
 * @param[out] g   - e([r3]R1,pk).
 * @param[out] A - the value of hash id of Alice to G_1.
 * @param[in] R1 - R1=[r1]sk_a.
 * @param[in] pk   - the public key.
 * @param[in] id	- the id of Alice.
 * @param[out] r3  - a 256-bit integer.
 */
void round_bob_1(fp12_t g,g1_t A, g1_t R1, ep2_t pk, const char *id,bn_t r3);

/**
 * Complete the rest computations and obain the shared key for Alice on BLS12-P446 and BN-P446 curves.
 *
 * @param[out] ss_a   - the shared key computed by Alice.
 * @param[out] R2 - R2 = [r2]A.
 * @param[in] g - e([r3]R1,pk).
 * @param[in] sa   - the value of hash id of Alice to G_1.
 * @param[in] pair	- the value of e(sk_a,pk).
 * @param[in] r1  - a 256-bit integer.
 * @param[in] r2  - a 256-bit integer.
 */
int round_alice_2(fp12_t ss_a,g1_t R2, fp12_t g,g1_t sa, const fp12_t pair,bn_t r1,bn_t r2);

/**
 * Complete the rest computations and obain the shared key for Bob on BLS12-P446 and BN-P446 curves.
 *
 * @param[out] ss_b   - the shared key computed by Bob.
 * @param[in] R2 - R2 = [r2]A.
 * @param[in] A - the value of hash id of Alice to G_1.
 * @param[in] r3  - a 256-bit integer.
 * @param[in] sk_b	- the secret key for Bob.
 */
void round_bob_2(fp12_t ss_b,g1_t R2,g1_t A,bn_t r3, ep2_t sk_b);
#endif

/**
 * Generate a master key for TA and computes secret keys of Alice and Bob on BLS12-P446 and BN-P446 curves.
 * @param[out] pk   - the public key.
 * @param[out] master_sk    - the master key.
 * @param[out] sk_a - the secret key for Alice.
 * @param[in] id   - the id of Alice.
 * @param[out] sk_b	- the secret key for Bob.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
int kex_keygen_k12(ep2_t pk, bn_t master_sk, g1_t sk_a, const char *id, ep2_t sk_b);

/**
 * Precompute the pairing e(sk_a,pk) and the value of hash id of Alice to G_1 on BLS12-P446 and BN-P446 curves.
 *
 * @param[out] pair	- the value of e(sk_a,pk).
 * @param[in] sk_a	- the secret key for Alice.
 * @param[out] sa   - the value of hash id of Alice to G_1
 * @param[in] id	- the id of Alice.
 * @param[in] pk   - the public key.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
int uck_pre_k12(fp12_t pair, g1_t sk_a, g1_t sa,const char *id, ep2_t pk);

/**
 * Compute the shared key on BLS12-P446 and BN-P446 curves.
 *
 * @param[out] ss	- the shared key.
 * @param[in] pk   - the public key.
 * @param[in] sa   - the value of hash id of Alice to G_1
 * @param[in] id	- the id of Alice.
 * @param[in] sk_a	- the secret key for Alice.
 * @param[in] sk_b	- the secret key for Bob.
 * @param[in] pair	- the value of e(sk_a,pk).
 * @return RLC_OK if no errors occurred and the shared key is correct, RLC_ERR otherwise.
 */
int kex_kdf_k12(fp12_t ss, ep2_t pk, g1_t sa, const char *id, g1_t sk_a, ep2_t sk_b, const fp12_t pair);
