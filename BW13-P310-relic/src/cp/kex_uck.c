#include "relic.h"

int kex_keygen_k12(ep2_t pk, bn_t master_sk, g1_t sk_a, const char *id, ep2_t sk_b){
	int result = RLC_OK;
    g1_t sa;
	RLC_TRY {
        g1_new(sa);

		bn_rand(master_sk, RLC_POS, 256);

		/* Public key Q in G2. */
        ep2_rand(pk);
        /* Private key Sa=s*H1(ID_a) in G1. */
        //g1_map(sa,id,strlen(id));
        ep_map(sa, (uint8_t*)id, strlen(id));
        ep_mul(sk_a,sa,master_sk);
        /* Private key Sb=s*Q in G2. */
        ep2_mul(sk_b,pk,master_sk);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
        g1_free(sa);
	}
	return result;
}

int uck_pre_k12(fp12_t pair, g1_t sk_a, g1_t sa,const char *id, ep2_t pk){
    ep_map(sa, (uint8_t*)id, strlen(id));
    pp_map_oatep_k12(pair, sk_a, pk);

	return RLC_OK;
}

int kex_keygen_k13(ep13_t pk, bn_t master_sk, g1_t sk_a, const char *id, ep13_t sk_b){
	int result = RLC_OK;
    g1_t sa;
	RLC_TRY {
        g1_new(sa);

		bn_rand(master_sk, RLC_POS, 256);

		/* Public key Q in G2. */
        ep13_curve_get_gen(pk);
        /* Private key Sa=s*H1(ID_a) in G1. */
        //g1_map(sa,id,strlen(id));
        ep_map(sa, (uint8_t*)id, strlen(id));
        ep_mul(sk_a,sa,master_sk);
        /* Private key Sb=s*Q in G2. */
        ep13_mul(sk_b,pk,master_sk);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
        g1_free(sa);
	}
	return result;
}

int uck_pre_k13(fp13_t pair, g1_t sk_a, g1_t sa,const char *id, ep13_t pk){
    ep_map(sa, (uint8_t*)id, strlen(id));
    pp_map_sup_oatep_k13(pair,sk_a,pk);
	return RLC_OK;
}

#if FP_PRIME == 310
void round_alice_1(g1_t R1,const g1_t sk_a,bn_t r1){
    bn_rand(r1, RLC_POS, 256);
    ep_mul(R1,sk_a,r1);
}

void round_bob_1(fp13_t g,g1_t A, g1_t R1, ep13_t pk,const char *id,bn_t r3){
    int result = RLC_OK;
    g1_t R3;
	RLC_TRY {
        g1_new(R3);

        bn_rand(r3, RLC_POS, 256);
        ep_map(A, (uint8_t*)id, strlen(id));
        ep_mul(R3,R1,r3);//R3=[r3]R
        pp_map_sup_oatep_k13(g,R3,pk);//e([r3]R,Q)
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
        g1_free(R3);
	}
}
int round_alice_2(fp13_t ss_a,g1_t R2, fp13_t g,g1_t sa, const fp13_t pair,bn_t r1,bn_t r2){
    int result = RLC_OK;
    bn_t q;
    fp13_t s;
	RLC_TRY {
        bn_new(q);
        fp13_new(s);
        if(gt_is_valid_bw13(g)!=1){
            result = RLC_ERR;
            return result;
        }
        bn_rand(r2, RLC_POS, 256);
        ep_mul(R2,sa,r2);//R2=[x]A
        fp13_exp_gt(ss_a,pair,r2);
        ep_curve_get_ord(q);
        bn_mod_inv(r2,r1,q);
        fp13_exp_gt(s,g,r2);
        fp13_mul(ss_a,ss_a,s);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
        bn_free(q);
        fp13_free(s);
	}
    return result;
}
void round_bob_2(fp13_t ss_b,g1_t R2,g1_t A,bn_t r3, ep13_t sk_b){
    int result = RLC_OK;
    g1_t P;
	RLC_TRY {
        g1_new(P);

        ep_mul(P,A,r3);
        ep_add(P,P,R2);
        ep_norm(P,P);
        pp_map_sup_oatep_k13(ss_b,P,sk_b);//e(R2+yA,Sk_b)
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
        g1_free(P);
	}
}
#elif FP_PRIME == 446
void round_alice_1(g1_t R1,const g1_t sk_a,bn_t r1){
    bn_rand(r1, RLC_POS, 256);
    ep_mul(R1,sk_a,r1);
}

void round_bob_1(fp12_t g,g1_t A, g1_t R1, ep2_t pk,const char *id,bn_t r3){
    int result = RLC_OK;
    g1_t R3;
	RLC_TRY {
        g1_new(R3);

        bn_rand(r3, RLC_POS, 256);
        ep_map(A, (uint8_t*)id, strlen(id));
        ep_mul(R3,R1,r3);//R3=[r3]R
        pp_map_oatep_k12(g, R3, pk);//e([r3]R,Q)
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
        g1_free(R3);
	}
}
#ifdef FP_QNRES
int round_alice_2(fp12_t ss_a,g1_t R2, fp12_t g,g1_t sa, const fp12_t pair,bn_t r1,bn_t r2){
    int result = RLC_OK;
    bn_t q;
    fp12_t s;
	RLC_TRY {
        bn_new(q);
        fp12_new(s);
        if(gt_is_valid(g)==0){
            result = RLC_ERR;
            return result;
        }
        bn_rand(r2, RLC_POS, 256);
        ep_mul(R2,sa,r2);//R2=[x]A
        fp12_exp_cyc(ss_a,pair,r2);
        ep_curve_get_ord(q);
        bn_mod_inv(r2,r1,q);
        fp12_exp_cyc(s,g,r2);
        fp12_mul(ss_a,ss_a,s);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
        bn_free(q);
        fp12_free(s);
	}
    return result;
}
#else
int round_alice_2(fp12_t ss_a,g1_t R2, fp12_t g,g1_t sa, const fp12_t pair,bn_t r1,bn_t r2){
    int result = RLC_OK;
    bn_t q;
    fp12_t s;
	RLC_TRY {
        bn_new(q);
        fp12_new(s);
        if(gt_is_valid_bn(g)==1){
            result = RLC_ERR;
            return result;
        }
        bn_rand(r2, RLC_POS, 256);
        ep_mul(R2,sa,r2);//R2=[x]A
        fp12_exp_cyc(ss_a,pair,r2);
        ep_curve_get_ord(q);
        bn_mod_inv(r2,r1,q);
        fp12_exp_cyc(s,g,r2);
        fp12_mul(ss_a,ss_a,s);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
        bn_free(q);
        fp12_free(s);
	}
    return result;
}
#endif

void round_bob_2(fp12_t ss_b,g1_t R2,g1_t A,bn_t r3, ep2_t sk_b){
    int result = RLC_OK;
    g1_t P;
	RLC_TRY {
        g1_new(P);

        ep_mul(P,A,r3);
        ep_add(P,P,R2);
        ep_norm(P,P);
        pp_map_oatep_k12(ss_b, P, sk_b);//e(R2+yA,Sk_b)
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
        g1_free(P);
	}
}
#endif

int kex_kdf_k13(fp13_t ss, ep13_t pk, g1_t sa, const char *id, g1_t sk_a, ep13_t sk_b, const fp13_t pair){
    int result = RLC_OK;
    bn_t r1,r2,r3;
    g1_t A,R1,R2;
    fp13_t g,ss_a,ss_b;

	RLC_TRY {
        bn_new(r1);
        bn_new(r2);
        bn_new(r3);
        g1_new(A);
        g1_new(R1);
        g1_new(R2);
        fp13_new(g);
        fp13_new(ss_a);
        fp13_new(ss_b);

        round_alice_1(R1,sk_a,r1);
        round_bob_1(g,A,R1,pk,id,r3);
        result=round_alice_2(ss_a,R2,g,sa,pair,r1,r2);
        if(result==RLC_OK){
            round_bob_2(ss_b,R2,A,r3,sk_b);
        }
        else{
            printf("Pairing is invalid!\n");
            return result;
        }
        if(fp13_cmp(ss_a,ss_b) == RLC_EQ){
            //printf("Agreement is successful!\n");
            //printf(" The shared secret is \n");
            fp13_copy(ss,ss_b);
            //fp13_print(ss);
        }
        else{
            printf("The shared secret is invalid!\n");
            result = RLC_ERR;
        }
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
        bn_free(r1);
        bn_free(r2);
        bn_free(r3);
        g1_free(A);
        g1_free(R);
        g1_free(R2);
        fp13_free(g);
        fp13_free(ss_a);
        fp13_free(ss_b);
	}
	return result;
}

int kex_kdf_k12(fp12_t ss, ep2_t pk, g1_t sa, const char *id, g1_t sk_a, ep2_t sk_b, const fp12_t pair){
    int result = RLC_OK;
    bn_t r1,r2,r3;
    g1_t A,R1,R2;
    fp12_t g,ss_a,ss_b;

	RLC_TRY {
        bn_new(r1);
        bn_new(r2);
        bn_new(r3);
        g1_new(A);
        g1_new(R1);
        g1_new(R2);
        fp12_new(g);
        fp12_new(ss_a);
        fp12_new(ss_b);

        round_alice_1(R1,sk_a,r1);
        round_bob_1(g,A,R1,pk,id,r3);
        result=round_alice_2(ss_a,R2,g,sa,pair,r1,r2);
        if(result==RLC_OK){
            round_bob_2(ss_b,R2,A,r3,sk_b);
        }
        else{
            printf("Pairing is invalid!\n");
            return result;
        }
        if(fp12_cmp(ss_a,ss_b) == RLC_EQ){
            //printf("Agreement is successful!\n");
            //printf(" The shared secret is \n");
            fp12_copy(ss,ss_b);
            //fp13_print(ss);
        }
        else{
            printf("The shared secret is invalid!\n");
            result = RLC_ERR;
        }
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
        bn_free(r1);
        bn_free(r2);
        bn_free(r3);
        g1_free(A);
        g1_free(R);
        g1_free(R2);
        fp12_free(g);
        fp12_free(ss_a);
        fp12_free(ss_b);
	}
	return result;
}