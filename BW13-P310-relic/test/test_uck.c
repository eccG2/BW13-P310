//Test for uck protocol
#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

#if FP_PRIME == 310
static int uck_test(void) {
	ep13_t pk,sk_b;
	bn_t master_sk,r1,r2,r3;
	g1_t sk_a,sa;
	char *id = "Alice";
	fp13_t pair,ss;
	int res=RLC_ERR;

    bn_null(master_sk);
    bn_null(r1);
    bn_null(r2);
    bn_null(r3);
    g1_null(sk_a);
    g1_null(sa);
    fp13_null(pair);
    fp13_null(ss);
    ep13_null(pk);
    ep13_null(sk_b);

    RLC_TRY {
        bn_new(master_sk);
        bn_new(r1);
        bn_new(r2);
        bn_new(r3);
        g1_new(sk_a);
        g1_new(sa);
        fp13_new(pair);
        fp13_new(ss);
        ep13_new(pk);
        ep13_new(sk_b);

        ep_param_set_any_pairf();
        ep_param_print();
        ep_curve_get_ord(r3);

        TEST_CASE("UCK protocol is correct") {
            TEST_ASSERT(kex_keygen_k13(pk, master_sk, sk_a, id, sk_b) == RLC_OK, end);
            TEST_ASSERT(uck_pre_k13(pair, sk_a, sa, id, pk) == RLC_OK, end);//pair=e(sk_a,pk)
            TEST_ASSERT(kex_kdf_k13(ss, pk, sa, id, sk_a, sk_b, pair) == RLC_OK, end);
        } TEST_END;

    } RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	res = RLC_OK;

    end:

        bn_free(master_sk);
        bn_free(r1);
        bn_free(r2);
        bn_free(r3);
        g1_free(sk_a);
        g1_free(sa);
        fp13_free(pair);
        fp13_free(ss);
        ep13_free(pk);
        ep13_free(sk_b);

        return res;
}
#elif FP_PRIME == 446
static int uck_test(void) {
	ep2_t pk,sk_b;
	bn_t master_sk,r1,r2,r3;
	g1_t sk_a,sa;
	char *id = "Alice";
	fp12_t pair,ss;
	int res=RLC_ERR;

    bn_null(master_sk);
    bn_null(r1);
    bn_null(r2);
    bn_null(r3);
    g1_null(sk_a);
    g1_null(sa);
    fp12_null(pair);
    fp12_null(ss);
    ep2_null(pk);
    ep2_null(sk_b);
    RLC_TRY {

        bn_new(master_sk);
        bn_new(r1);
        bn_new(r2);
        bn_new(r3);
        g1_new(sk_a);
        g1_new(sa);
        fp12_new(pair);
        fp12_new(ss);
        ep2_new(pk);
        ep2_new(sk_b);

        ep_param_set_any_pairf();
        ep_param_print();

        TEST_CASE("UCK protocol is correct") {
            TEST_ASSERT(kex_keygen_k12(pk, master_sk, sk_a, id, sk_b) == RLC_OK, end);
            TEST_ASSERT(uck_pre_k12(pair, sk_a, sa, id, pk) == RLC_OK, end);
            TEST_ASSERT(kex_kdf_k12(ss, pk, sa, id, sk_a, sk_b, pair) == RLC_OK, end);
        } TEST_END;

    } RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	res = RLC_OK;

    end:
        bn_free(master_sk);
        bn_free(r1);
        bn_free(r2);
        bn_free(r3);
        g1_free(sk_a);
        g1_free(sa);
        fp12_free(pair);
        fp12_free(ss);
        ep2_free(pk);
        ep2_free(sk_b);

        return res;
}
#endif

int main(){
    if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
    conf_print();

    util_banner("Testing for UCK Protocols:\n", 0);
    if (uck_test() != RLC_OK) {
		core_clean();
		return 1;
	}

    util_banner("All tests have passed.\n", 0);
    core_clean();
	return 0;
}