//Benchmarks for uck protocol
#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

#if FP_PRIME == 310
static void uck(void) {
	ep13_t pk,sk_b;
	bn_t master_sk,r1,r2,r3;
	g1_t sk_a,sa,R1,A,R2;
	char *id = "Alice";
	fp13_t pair,ss,ss_a,ss_b,g;
	int res=RLC_OK,res1=RLC_OK,res2=RLC_OK;

    bn_null(master_sk);
    bn_null(r1);
    bn_null(r2);
    bn_null(r3);
    g1_null(sk_a);
    g1_null(sa);
    g1_null(R1);
    g1_null(A);
    g1_null(R2);
    fp13_null(pair);
    fp13_null(ss);
    fp13_null(ss_a);
    fp13_null(ss_b);
    fp13_null(g);
    ep13_null(pk);
    ep13_null(sk_b);

    bn_new(master_sk);
    bn_new(r1);
    bn_new(r2);
    bn_new(r3);
    g1_new(sk_a);
    g1_new(sa);
    g1_new(R1);
    g1_new(A);
    g1_new(R2);
    fp13_new(pair);
    fp13_new(ss);
    fp13_new(ss_a);
    fp13_new(ss_b);
    fp13_new(g);
    ep13_new(pk);
    ep13_new(sk_b);

    ep_param_set_any_pairf();
    ep_param_print();

	ep_curve_get_ord(r1);
	ep13_rand(sk_b);

    BENCH_RUN("Hash to G1") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep_map(sa, msg, 5));
	}
	BENCH_END;

    BENCH_RUN("Operation in G1") {
        bn_rand_mod(r2,r1);
		ep_rand(sk_a);
		BENCH_ADD(ep_mul(sa,sk_a,r2));
	}
	BENCH_END;

	BENCH_RUN("Operation in GT") {
		ep13_rand(pk);
		ep_rand(sk_a);
        pp_map_sup_oatep_k13(pair,sk_a,pk);
		bn_rand(r2, RLC_POS, RLC_FP_BITS);
		BENCH_ADD(fp13_exp_gt(ss, pair, r2));
	}
	BENCH_END;

    BENCH_RUN("GT subgroup membership testing") {
		ep13_rand(pk);
		ep_rand(sk_a);
        pp_map_sup_oatep_k13(pair,sk_a,pk);
		BENCH_ADD(gt_is_valid_bw13(pair));
	}
	BENCH_END;

	BENCH_RUN("pp_map_sup_oatep_k13") {
		ep13_rand(pk);
		ep_rand(sk_a);
		BENCH_ADD(pp_map_sup_oatep_k13(pair,sk_a,pk));
	}
	BENCH_END;

	BENCH_RUN("uck_key_generation") {
		BENCH_ADD(kex_keygen_k13(pk, master_sk, sk_a, id, sk_b));
	}
	BENCH_END;

	BENCH_RUN("uck_precomputation") {
		BENCH_ADD(uck_pre_k13(pair, sk_a, sa, id, pk));
	}
	BENCH_END;

	BENCH_RUN("uck protocol") {
        res1=kex_keygen_k13(pk, master_sk, sk_a, id, sk_b);
        res1=uck_pre_k13(pair, sk_a, sa, id, pk);
        if(res1==RLC_OK||res2==RLC_OK){
            BENCH_ADD(kex_kdf_k13(ss, pk, sa, id, sk_a, sk_b, pair));
        }
        else{
            res = RLC_ERR;
            printf("ERROR!\n");
        }
	}
	BENCH_END;

    BENCH_RUN("uck protocol----Alice") {
        res1=kex_keygen_k13(pk, master_sk, sk_a, id, sk_b);
        res1=uck_pre_k13(pair, sk_a, sa, id, pk);
        if(res1==RLC_OK||res2==RLC_OK){
            BENCH_ADD(round_alice_1(R1,sk_a,r1));
            round_bob_1(g,A,R1,pk,id,r3);
            BENCH_ADD(round_alice_2(ss_a,R2,g,sa,pair,r1,r2));
        }
        else{
            res = RLC_ERR;
            printf("ERROR!\n");
        }
	}
	BENCH_END;

    BENCH_RUN("uck protocol----Bob") {
        res1=kex_keygen_k13(pk, master_sk, sk_a, id, sk_b);
        res1=uck_pre_k13(pair, sk_a, sa, id, pk);
        if(res1==RLC_OK||res2==RLC_OK){
            round_alice_1(R1,sk_a,r1);
            BENCH_ADD(round_bob_1(g,A,R1,pk,id,r3));
            round_alice_2(ss_a,R2,g,sa,pair,r1,r2);
            BENCH_ADD(round_bob_2(ss_b,R2,A,r3,sk_b));
        }
        else{
            res = RLC_ERR;
            printf("ERROR!\n");
        }
	}
	BENCH_END;

	bn_free(master_sk);
    bn_free(r1);
    bn_free(r2);
    bn_free(r3);
    g1_free(sk_a);
    g1_free(sa);
    g1_free(R1);
    g1_free(A);
    g1_free(R2);
    fp13_free(pair);
    fp13_free(ss);
    fp13_free(ss_a);
    fp13_free(ss_b);
    fp13_free(g);
    ep13_free(pk);
    ep13_free(sk_b);
}
#elif FP_PRIME == 446
#ifdef FP_QNRES
static int gt_is_valid_test(fp12_t pair){
    return gt_is_valid(pair);
}
#else
static int gt_is_valid_test(fp12_t pair){
    return gt_is_valid_bn(pair);
}
#endif
static void uck(void) {
	ep2_t pk,sk_b;
	bn_t master_sk,r1,r2,r3;
	g1_t sk_a,sa,R1,A,R2;
	char *id = "Alice";
	fp12_t pair,ss,ss_a,ss_b,g;
	int res=RLC_OK,res1=RLC_OK,res2=RLC_OK;

    bn_null(master_sk);
    bn_null(r1);
    bn_null(r2);
    bn_null(r3);
    g1_null(sk_a);
    g1_null(sa);
    g1_null(R1);
    g1_null(A);
    g1_null(R2);
    fp12_null(pair);
    fp12_null(ss);
    fp12_null(ss_a);
    fp12_null(ss_b);
    fp12_null(g);
    ep2_null(pk);
    ep2_null(sk_b);

    bn_new(master_sk);
    bn_new(r1);
    bn_new(r2);
    bn_new(r3);
    g1_new(sk_a);
    g1_new(sa);
    g1_new(R1);
    g1_new(A);
    g1_new(R2);
    fp12_new(pair);
    fp12_new(ss);
    fp12_new(ss_a);
    fp12_new(ss_b);
    fp12_new(g);
    ep2_new(pk);
    ep2_new(sk_b);

    ep_param_set_any_pairf();
    ep_param_print();
    ep_curve_get_ord(r1);

    BENCH_RUN("Hash to G1") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep_map(sa, msg, 5));
	}
	BENCH_END;

    BENCH_RUN("Operation in G1") {
        bn_rand_mod(r2,r1);
		ep_rand(sk_a);
		BENCH_ADD(ep_mul(sa,sk_a,r2));
	}
	BENCH_END;

	BENCH_RUN("Operation in GT") {
		fp12_rand(pair);
		fp12_conv_cyc(pair, pair);
		bn_rand(r2, RLC_POS, RLC_FP_BITS);
		BENCH_ADD(fp12_exp(ss, pair, r2));
	}
	BENCH_END;

    BENCH_RUN("GT subgroup membership testing") {
		ep2_rand(pk);
		ep_rand(sk_a);
        pp_map_oatep_k12(pair,sk_a,pk);
		BENCH_ADD(gt_is_valid_test(pair));
	}
	BENCH_END;

	BENCH_RUN("pp_map_oatep_k12") {
		ep2_rand(pk);
		ep_rand(sk_a);
		BENCH_ADD(pp_map_oatep_k12(pair,sk_a,pk));
	}
	BENCH_END;

	BENCH_RUN("uck_key_generation") {
		BENCH_ADD(kex_keygen_k12(pk, master_sk, sk_a, id, sk_b));
	}
	BENCH_END;

	BENCH_RUN("uck_precomputation") {
		BENCH_ADD(uck_pre_k12(pair, sk_a, sa, id, pk));
	}
	BENCH_END;

	BENCH_RUN("uck protocol") {
        res1=kex_keygen_k12(pk, master_sk, sk_a, id, sk_b);
        res1=uck_pre_k12(pair, sk_a, sa, id, pk);
        if(res1==RLC_OK||res2==RLC_OK){
            BENCH_ADD(kex_kdf_k12(ss, pk, sa, id, sk_a, sk_b, pair));
        }
        else{
            res = RLC_ERR;
            printf("ERROR!\n");
        }
	}
	BENCH_END;

    BENCH_RUN("uck protocol----Alice") {
        res1=kex_keygen_k12(pk, master_sk, sk_a, id, sk_b);
        res1=uck_pre_k12(pair, sk_a, sa, id, pk);
        if(res1==RLC_OK||res2==RLC_OK){
            BENCH_ADD(round_alice_1(R1,sk_a,r1));
            round_bob_1(g,A,R1,pk,id,r3);
            BENCH_ADD(round_alice_2(ss_a,R2,g,sa,pair,r1,r2));
        }
        else{
            res = RLC_ERR;
            printf("ERROR!\n");
        }
	}
	BENCH_END;

    BENCH_RUN("uck protocol----Bob") {
        res1=kex_keygen_k12(pk, master_sk, sk_a, id, sk_b);
        res1=uck_pre_k12(pair, sk_a, sa, id, pk);
        if(res1==RLC_OK||res2==RLC_OK){
            round_alice_1(R1,sk_a,r1);
            BENCH_ADD(round_bob_1(g,A,R1,pk,id,r3));
            round_alice_2(ss_a,R2,g,sa,pair,r1,r2);
            BENCH_ADD(round_bob_2(ss_b,R2,A,r3,sk_b));
        }
        else{
            res = RLC_ERR;
            printf("ERROR!\n");
        }
	}
	BENCH_END;

	bn_free(master_sk);
    bn_free(r1);
    bn_free(r2);
    bn_free(r3);
    g1_free(sk_a);
    g1_free(sa);
    g1_free(R1);
    g1_free(A);
    g1_free(R2);
    fp12_free(pair);
    fp12_free(ss);
    fp12_free(ss_a);
    fp12_free(ss_b);
    fp12_free(g);
    ep2_free(pk);
    ep2_free(sk_b);
}
#endif

int main(){
    if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
    conf_print();
    util_banner("Benchmarks for the UCK module:", 0);

    uck();
    core_clean();
	return 0;
}
