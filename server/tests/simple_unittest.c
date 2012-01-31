/*
 * Copyright (C) 2012  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

#include <config.h>
#include <atf-c.h>

ATF_TC(simple_test_case);
ATF_TC_HEAD(simple_test_case, tc)
{
    atf_tc_set_md_var(tc, "descr", "This test case is a simple DHCP test.");
}
ATF_TC_BODY(simple_test_case, tc)
{
    //ATF_CHECK(returns_a_boolean()); /* Non-fatal test. */
    //ATF_REQUIRE(returns_a_boolean()); /* Fatal test. */

    //ATF_CHECK_EQ(4, 2 + 2); /* Non-fatal test. */
    //ATF_REQUIRE_EQ(4, 2 + 2); /* Fatal test. */

    //if (!condition)
//        atf_tc_fail("Condition not met!"); /* Explicit failure. */
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, simple_test_case);

    return (atf_no_error());
}

