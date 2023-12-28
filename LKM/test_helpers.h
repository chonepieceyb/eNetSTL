#ifndef __TEST_HELPERS_H
#define __TEST_HELPERS_H

#include <linux/printk.h>

#define lkm_assert_eq(expected, actual, name)   \
({                               				                                                                                            \
	typeof(actual) ___act = (actual);				                                                                                    \
	typeof(expected) ___exp = (expected);				                                                                                    \
	bool ___ok = ___act == ___exp;					                                                                                    \
        if (unlikely(!___ok))  {                                                                                                                            \
                pr_err("[xdp assert failed]: unexpected %s: actual %lld != expected %lld\n", name, (long long)___act, (long long)___exp);                  \
                goto lkm_test_error;                                                                                                                             \
        };                                                                                                                                                  \
}) 

#define lkm_assert_neq(noexpected, actual, name)   \
({                               				                                                                                            \
	typeof(actual) ___act = (actual);				                                                                                    \
	typeof(noexpected) ___noexp = (noexpected);				                                                                                    \
	bool ___ok = ___act != ___noexp;					                                                                                    \
        if (unlikely(!___ok))  {                                                                                                                            \
                pr_err("[xdp assert failed]: unexpected %s: actual %lld == non expected %lld\n", name, (long long)___act, (long long)___noexp);                  \
                goto lkm_test_error;                                                                                                                             \
        };                                                                                                                                                  \
}) 
#endif 