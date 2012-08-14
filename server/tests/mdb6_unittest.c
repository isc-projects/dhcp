/*
 * Copyright (C) 2007-2012 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"

#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>

#include <stdarg.h>
#include "dhcpd.h"
#include "omapip/omapip.h"
#include "omapip/hash.h"
#include <dst/md5.h>

#include <atf-c.h>

#include <stdlib.h>

void build_prefix6(struct in6_addr *pref, const struct in6_addr *net_start_pref,
                   int pool_bits, int pref_bits,
                   const struct data_string *input);

ATF_TC(iaaddr_basic);
ATF_TC_HEAD(iaaddr_basic, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case checks that basic "
                      "IAADDR manipulation is possible.");
}
ATF_TC_BODY(iaaddr_basic, tc)
{
    struct iasubopt *iaaddr;
    struct iasubopt *iaaddr_copy;
    /*
     * Test 0: Basic iaaddr manipulation.
     */
    iaaddr = NULL;
    if (iasubopt_allocate(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_allocate() %s:%d", MDL);
    }
    if (iaaddr->state != FTS_FREE) {
        atf_tc_fail("ERROR: bad state %s:%d", MDL);
    }
    if (iaaddr->heap_index != -1) {
        atf_tc_fail("ERROR: bad heap_index %s:%d", MDL);
    }
    iaaddr_copy = NULL;
    if (iasubopt_reference(&iaaddr_copy, iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_reference() %s:%d", MDL);
    }
    if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_reference() %s:%d", MDL);
    }
    if (iasubopt_dereference(&iaaddr_copy, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_reference() %s:%d", MDL);
    }
}


ATF_TC(iaaddr_negative);
ATF_TC_HEAD(iaaddr_negative, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case checks that IAADDR "
                      "option code can handle various negative scenarios.");
}
ATF_TC_BODY(iaaddr_negative, tc)
{
    struct iasubopt *iaaddr;
    struct iasubopt *iaaddr_copy;

    /* bogus allocate arguments */
    if (iasubopt_allocate(NULL, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: iasubopt_allocate() %s:%d", MDL);
    }
    iaaddr = (struct iasubopt *)1;
    if (iasubopt_allocate(&iaaddr, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: iasubopt_allocate() %s:%d", MDL);
    }

    /* bogus reference arguments */
    iaaddr = NULL;
    if (iasubopt_allocate(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_allocate() %s:%d", MDL);
    }
    if (iasubopt_reference(NULL, iaaddr, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: iasubopt_reference() %s:%d", MDL);
    }
    iaaddr_copy = (struct iasubopt *)1;
    if (iasubopt_reference(&iaaddr_copy, iaaddr,
                           MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: iasubopt_reference() %s:%d", MDL);
    }
    iaaddr_copy = NULL;
    if (iasubopt_reference(&iaaddr_copy, NULL, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: iasubopt_reference() %s:%d", MDL);
    }
    if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_reference() %s:%d", MDL);
    }

    /* bogus dereference arguments */
    if (iasubopt_dereference(NULL, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: iasubopt_dereference() %s:%d", MDL);
    }
    iaaddr = NULL;
    if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: iasubopt_dereference() %s:%d", MDL);
    }
}


ATF_TC(ia_na_basic);
ATF_TC_HEAD(ia_na_basic, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case checks that IA_NA code can "
                      "handle various basic scenarios.");
}
ATF_TC_BODY(ia_na_basic, tc)
{
    uint32_t iaid;
    struct ia_xx *ia_na;
    struct ia_xx *ia_na_copy;
    struct iasubopt *iaaddr;

    /*
     * Test 2: Basic ia_na manipulation.
     */
    iaid = 666;
    ia_na = NULL;
    if (ia_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_allocate() %s:%d\n", MDL);
    }
    if (memcmp(ia_na->iaid_duid.data, &iaid, sizeof(iaid)) != 0) {
        atf_tc_fail("ERROR: bad IAID_DUID %s:%d\n", MDL);
    }
    if (memcmp(ia_na->iaid_duid.data+sizeof(iaid), "TestDUID", 8) != 0) {
        atf_tc_fail("ERROR: bad IAID_DUID %s:%d\n", MDL);
    }
    if (ia_na->num_iasubopt != 0) {
        atf_tc_fail("ERROR: bad num_iasubopt %s:%d\n", MDL);
    }
    ia_na_copy = NULL;
    if (ia_reference(&ia_na_copy, ia_na, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_reference() %s:%d\n", MDL);
    }
    iaaddr = NULL;
    if (iasubopt_allocate(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_allocate() %s:%d\n", MDL);
    }
    if (ia_add_iasubopt(ia_na, iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_add_iasubopt() %s:%d\n", MDL);
    }
    ia_remove_iasubopt(ia_na, iaaddr, MDL);
    if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_reference() %s:%d\n", MDL);
    }
    if (ia_dereference(&ia_na, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_dereference() %s:%d\n", MDL);
    }
    if (ia_dereference(&ia_na_copy, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_dereference() %s:%d\n", MDL);
    }
}


ATF_TC(ia_na_manyaddrs);
ATF_TC_HEAD(ia_na_manyaddrs, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case checks that IA_NA can "
                      "handle lots of addresses.");
}
ATF_TC_BODY(ia_na_manyaddrs, tc)
{
    uint32_t iaid;
    struct ia_xx *ia_na;
    struct iasubopt *iaaddr;
    int i;
    /*
     * Test 3: lots of iaaddr in our ia_na
     */

    /* lots of iaaddr that we delete */
    iaid = 666;
    ia_na = NULL;
    if (ia_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_allocate() %s:%d\n", MDL);
    }
    for (i=0; i<100; i++) {
        iaaddr = NULL;
        if (iasubopt_allocate(&iaaddr, MDL) != ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: iasubopt_allocate() %s:%d\n", MDL);
        }
        if (ia_add_iasubopt(ia_na, iaaddr, MDL) != ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: ia_add_iasubopt() %s:%d\n", MDL);
        }
        if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: iasubopt_reference() %s:%d\n", MDL);
        }
    }

#if 0
    for (i=0; i<100; i++) {
        iaaddr = ia_na->iasubopt[random() % ia_na->num_iasubopt];
        ia_remove_iasubopt(ia_na, iaaddr, MDL);
        /* TODO: valgrind reports problem here: Invalid read of size 8
         * Address 0x51e6258 is 56 bytes inside a block of size 88 free'd */
    }
#endif
    if (ia_dereference(&ia_na, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_dereference() %s:%d\n", MDL);
    }

    /* lots of iaaddr, let dereference cleanup */
    iaid = 666;
    ia_na = NULL;
    if (ia_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_allocate() %s:%d\n", MDL);
    }
    for (i=0; i<100; i++) {
        iaaddr = NULL;
        if (iasubopt_allocate(&iaaddr, MDL) != ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: iasubopt_allocate() %s:%d\n", MDL);
        }
        if (ia_add_iasubopt(ia_na, iaaddr, MDL) != ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: ia_add_iasubopt() %s:%d\n", MDL);
        }
        if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: iasubopt_reference() %s:%d\n", MDL);
        }
    }
    if (ia_dereference(&ia_na, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_dereference() %s:%d\n", MDL);
    }
}

ATF_TC(ia_na_negative);
ATF_TC_HEAD(ia_na_negative, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case checks that IA_NA option "
                      "code can handle various negative scenarios.");
}
ATF_TC_BODY(ia_na_negative, tc)
{
    uint32_t iaid;
    struct ia_xx *ia_na;
    struct ia_xx *ia_na_copy;
    /*
     * Test 4: Errors in ia_na.
     */
    /* bogus allocate arguments */
    if (ia_allocate(NULL, 123, "", 0, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ia_allocate() %s:%d\n", MDL);
    }
    ia_na = (struct ia_xx *)1;
    if (ia_allocate(&ia_na, 456, "", 0, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ia_allocate() %s:%d\n", MDL);
    }

    /* bogus reference arguments */
    iaid = 666;
    ia_na = NULL;
    if (ia_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_allocate() %s:%d\n", MDL);
    }
    if (ia_reference(NULL, ia_na, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ia_reference() %s:%d\n", MDL);
    }
    ia_na_copy = (struct ia_xx *)1;
    if (ia_reference(&ia_na_copy, ia_na, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ia_reference() %s:%d\n", MDL);
    }
    ia_na_copy = NULL;
    if (ia_reference(&ia_na_copy, NULL, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ia_reference() %s:%d\n", MDL);
    }
    if (ia_dereference(&ia_na, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_dereference() %s:%d\n", MDL);
    }

    /* bogus dereference arguments */
    if (ia_dereference(NULL, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ia_dereference() %s:%d\n", MDL);
    }

    /* bogus remove */
    iaid = 666;
    ia_na = NULL;
    if (ia_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_allocate() %s:%d\n", MDL);
    }
    ia_remove_iasubopt(ia_na, NULL, MDL);
    if (ia_dereference(&ia_na, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_dereference() %s:%d\n", MDL);
    }
}

ATF_TC(ipv6_pool_basic);
ATF_TC_HEAD(ipv6_pool_basic, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case checks that IPv6 pool "
                      "manipulation is possible.");
}
ATF_TC_BODY(ipv6_pool_basic, tc)
{
    struct iasubopt *iaaddr;
    struct in6_addr addr;
    struct ipv6_pool *pool;
    struct ipv6_pool *pool_copy;
    char addr_buf[INET6_ADDRSTRLEN];
    char *uid;
    struct data_string ds;
    struct iasubopt *expired_iaaddr;
    unsigned int attempts;

    /*
     * Test 5: Basic ipv6_pool manipulation.
     */

    /* allocate, reference */
    inet_pton(AF_INET6, "1:2:3:4::", &addr);
    pool = NULL;
    if (ipv6_pool_allocate(&pool, 0, &addr, 64, 128, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
    }
    if (pool->num_active != 0) {
        atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
    }
    if (pool->bits != 64) {
        atf_tc_fail("ERROR: bad bits %s:%d\n", MDL);
    }
    inet_ntop(AF_INET6, &pool->start_addr, addr_buf, sizeof(addr_buf));
    if (strcmp(inet_ntop(AF_INET6, &pool->start_addr, addr_buf,
                         sizeof(addr_buf)), "1:2:3:4::") != 0) {
        atf_tc_fail("ERROR: bad start_addr %s:%d\n", MDL);
    }
    pool_copy = NULL;
    if (ipv6_pool_reference(&pool_copy, pool, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
    }

    /* create_lease6, renew_lease6, expire_lease6 */
    uid = "client0";
    memset(&ds, 0, sizeof(ds));
    ds.len = strlen(uid);
    if (!buffer_allocate(&ds.buffer, ds.len, MDL)) {
        atf_tc_fail("Out of memory\n");
    }
    ds.data = ds.buffer->data;
    memcpy((char *)ds.data, uid, ds.len);
    if (create_lease6(pool, &iaaddr,
                      &attempts, &ds, 1) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: create_lease6() %s:%d\n", MDL);
    }
    if (pool->num_inactive != 1) {
        atf_tc_fail("ERROR: bad num_inactive %s:%d\n", MDL);
    }
    if (renew_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: renew_lease6() %s:%d\n", MDL);
    }
    if (pool->num_active != 1) {
        atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
    }
    expired_iaaddr = NULL;
    if (expire_lease6(&expired_iaaddr, pool, 0) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: expire_lease6() %s:%d\n", MDL);
    }
    if (expired_iaaddr != NULL) {
        atf_tc_fail("ERROR: should not have expired a lease %s:%d\n", MDL);
    }
    if (pool->num_active != 1) {
        atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
    }
    if (expire_lease6(&expired_iaaddr, pool, 1000) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: expire_lease6() %s:%d\n", MDL);
    }
    if (expired_iaaddr == NULL) {
        atf_tc_fail("ERROR: should have expired a lease %s:%d\n", MDL);
    }
    if (iasubopt_dereference(&expired_iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_dereference() %s:%d\n", MDL);
    }
    if (pool->num_active != 0) {
        atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
    }
    if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_dereference() %s:%d\n", MDL);
    }

    /* release_lease6, decline_lease6 */
    if (create_lease6(pool, &iaaddr, &attempts,
              &ds, 1) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: create_lease6() %s:%d\n", MDL);
    }
    if (renew_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: renew_lease6() %s:%d\n", MDL);
    }
    if (pool->num_active != 1) {
        atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
    }
    if (release_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: decline_lease6() %s:%d\n", MDL);
    }
    if (pool->num_active != 0) {
        atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
    }
    if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_dereference() %s:%d\n", MDL);
    }
    if (create_lease6(pool, &iaaddr, &attempts,
              &ds, 1) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: create_lease6() %s:%d\n", MDL);
    }
    if (renew_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: renew_lease6() %s:%d\n", MDL);
    }
    if (pool->num_active != 1) {
        atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
    }
    if (decline_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: decline_lease6() %s:%d\n", MDL);
    }
    if (pool->num_active != 1) {
        atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
    }
    if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_dereference() %s:%d\n", MDL);
    }

    /* dereference */
    if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
    }
    if (ipv6_pool_dereference(&pool_copy, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
    }
}

ATF_TC(ipv6_pool_negative);
ATF_TC_HEAD(ipv6_pool_negative, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case checks that IPv6 pool "
                      "can handle negative cases.");
}
ATF_TC_BODY(ipv6_pool_negative, tc)
{
    struct in6_addr addr;
    struct ipv6_pool *pool;
    struct ipv6_pool *pool_copy;

    /*
     * Test 6: Error ipv6_pool manipulation
     */
    if (ipv6_pool_allocate(NULL, 0, &addr,
                   64, 128, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
    }
    pool = (struct ipv6_pool *)1;
    if (ipv6_pool_allocate(&pool, 0, &addr,
                   64, 128, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
    }
    if (ipv6_pool_reference(NULL, pool, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
    }
    pool_copy = (struct ipv6_pool *)1;
    if (ipv6_pool_reference(&pool_copy, pool, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
    }
    pool_copy = NULL;
    if (ipv6_pool_reference(&pool_copy, NULL, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
    }
    if (ipv6_pool_dereference(NULL, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
    }
    if (ipv6_pool_dereference(&pool_copy, MDL) != ISC_R_INVALIDARG) {
        atf_tc_fail("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
    }
}

ATF_TC(expire_order);
ATF_TC_HEAD(expire_order, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case checks that order "
                      "of lease expiration is handled properly.");
}
ATF_TC_BODY(expire_order, tc)
{
    struct iasubopt *iaaddr;
    struct ipv6_pool *pool;
    struct in6_addr addr;
        int i;
    struct data_string ds;
    struct iasubopt *expired_iaaddr;
    unsigned int attempts;

    /*
     * Test 7: order of expiration
     */
    pool = NULL;
    if (ipv6_pool_allocate(&pool, 0, &addr, 64, 128, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
    }
    for (i=10; i<100; i+=10) {
        if (create_lease6(pool, &iaaddr, &attempts,
                  &ds, i) != ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: create_lease6() %s:%d\n", MDL);
                }
        if (renew_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: renew_lease6() %s:%d\n", MDL);
                }
        if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: iasubopt_dereference() %s:%d\n", MDL);
                }
        if (pool->num_active != (i / 10)) {
            atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
                }
    }
    if (pool->num_active != 9) {
        atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
    }
    for (i=10; i<100; i+=10) {
        if (expire_lease6(&expired_iaaddr,
                  pool, 1000) != ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: expire_lease6() %s:%d\n", MDL);
                }
        if (expired_iaaddr == NULL) {
            atf_tc_fail("ERROR: should have expired a lease %s:%d\n",
                   MDL);
                }
        if (pool->num_active != (9 - (i / 10))) {
            atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
                }
        if (expired_iaaddr->hard_lifetime_end_time != i) {
            atf_tc_fail("ERROR: bad hard_lifetime_end_time %s:%d\n",
                   MDL);
                }
        if (iasubopt_dereference(&expired_iaaddr, MDL) !=
                ISC_R_SUCCESS) {
            atf_tc_fail("ERROR: iasubopt_dereference() %s:%d\n", MDL);
                }
    }
    if (pool->num_active != 0) {
        atf_tc_fail("ERROR: bad num_active %s:%d\n", MDL);
    }
    expired_iaaddr = NULL;
    if (expire_lease6(&expired_iaaddr, pool, 1000) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: expire_lease6() %s:%d\n", MDL);
    }
    if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
    }
}


ATF_TC(small_pool);
ATF_TC_HEAD(small_pool, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case checks that small pool "
                      "is handled properly.");
}
ATF_TC_BODY(small_pool, tc)
{
    struct in6_addr addr;
    struct ipv6_pool *pool;
    struct iasubopt *iaaddr;
    struct data_string ds;
    unsigned int attempts;

    /*
     * Test 8: small pool
     */
    pool = NULL;
    addr.s6_addr[14] = 0x81;
    if (ipv6_pool_allocate(&pool, 0, &addr, 127, 128, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
    }
    if (create_lease6(pool, &iaaddr, &attempts,
              &ds, 42) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: create_lease6() %s:%d\n", MDL);
    }
    if (renew_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: renew_lease6() %s:%d\n", MDL);
    }
    if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_dereference() %s:%d\n", MDL);
    }
    if (create_lease6(pool, &iaaddr, &attempts,
              &ds, 11) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: create_lease6() %s:%d\n", MDL);
    }
    if (renew_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: renew_lease6() %s:%d\n", MDL);
    }
    if (iasubopt_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: iasubopt_dereference() %s:%d\n", MDL);
    }
    if (create_lease6(pool, &iaaddr, &attempts,
              &ds, 11) != ISC_R_NORESOURCES) {
        atf_tc_fail("ERROR: create_lease6() %s:%d\n", MDL);
    }
    if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
    }
    addr.s6_addr[14] = 0;
}

ATF_TC(many_pools);
ATF_TC_HEAD(many_pools, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case checks that functions "
                      "across all pools are working correctly.");
}
ATF_TC_BODY(many_pools, tc)
{
    struct in6_addr addr;
    struct ipv6_pool *pool;

    /*
     * Test 9: functions across all pools
     */
    pool = NULL;
    if (ipv6_pool_allocate(&pool, 0, &addr, 64, 128, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
    }
    if (add_ipv6_pool(pool) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: add_ipv6_pool() %s:%d\n", MDL);
    }
    if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
    }
    pool = NULL;
    if (find_ipv6_pool(&pool, 0, &addr) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: find_ipv6_pool() %s:%d\n", MDL);
    }
    if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
    }
    inet_pton(AF_INET6, "1:2:3:4:ffff:ffff:ffff:ffff", &addr);
    pool = NULL;
    if (find_ipv6_pool(&pool, 0, &addr) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: find_ipv6_pool() %s:%d\n", MDL);
    }
    if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
    }
    inet_pton(AF_INET6, "1:2:3:5::", &addr);
    pool = NULL;
    if (find_ipv6_pool(&pool, 0, &addr) != ISC_R_NOTFOUND) {
        atf_tc_fail("ERROR: find_ipv6_pool() %s:%d\n", MDL);
    }
    inet_pton(AF_INET6, "1:2:3:3:ffff:ffff:ffff:ffff", &addr);
    pool = NULL;
    if (find_ipv6_pool(&pool, 0, &addr) != ISC_R_NOTFOUND) {
        atf_tc_fail("ERROR: find_ipv6_pool() %s:%d\n", MDL);
    }

/*  iaid = 666;
    ia_na = NULL;
    if (ia_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
        atf_tc_fail("ERROR: ia_allocate() %s:%d\n", MDL);
    }*/

    {
        struct in6_addr r;
        struct data_string ds;
        u_char data[16];
        char buf[64];
        int i, j;

        memset(&ds, 0, sizeof(ds));
        memset(data, 0xaa, sizeof(data));
        ds.len = 16;
        ds.data = data;

        inet_pton(AF_INET6, "3ffe:501:ffff:100::", &addr);
        for (i = 32; i < 42; i++)
            for (j = i + 1; j < 49; j++) {
                memset(&r, 0, sizeof(r));
                memset(buf, 0, 64);
                build_prefix6(&r, &addr, i, j, &ds);
                inet_ntop(AF_INET6, &r, buf, 64);
                printf("%d,%d-> %s/%d\n", i, j, buf, j);
            }
    }
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, iaaddr_basic);
    ATF_TP_ADD_TC(tp, iaaddr_negative);
    ATF_TP_ADD_TC(tp, ia_na_basic);
    ATF_TP_ADD_TC(tp, ia_na_manyaddrs);
    ATF_TP_ADD_TC(tp, ia_na_negative);
    ATF_TP_ADD_TC(tp, ipv6_pool_basic);
    ATF_TP_ADD_TC(tp, ipv6_pool_negative);
    ATF_TP_ADD_TC(tp, expire_order);
    ATF_TP_ADD_TC(tp, small_pool);
    ATF_TP_ADD_TC(tp, many_pools);

    return (atf_no_error());
}
