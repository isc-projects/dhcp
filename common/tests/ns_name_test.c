/*
 * Copyright (c) 2014 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Tests the newly added functions: MRns_name_compress_list and
 * MRns_name_uncompress_list.  These two functions rely on most of
 * the other functions in ns_name.c.  If these tests pass, then the
 * majority of those functions work.
 *
 * This is not exhaustive test of these functions, much more could be
 * done.
 */
#include "config.h"
#include <atf-c.h>
#include "dhcpd.h"

ATF_TC(MRns_name_list_funcs);

ATF_TC_HEAD(MRns_name_list_funcs, tc) {
    atf_tc_set_md_var(tc, "descr", "MRns_name list funcs test, "
                      "compress from text, decompress to text");
}

ATF_TC_BODY(MRns_name_list_funcs, tc) {

    const char text_list[] = "one.two.com,three.two.com,four.two.com";
    unsigned char comp_list[] = {
        0x03,0x6f,0x6e,0x65,0x03,0x74,0x77,0x6f,0x03,0x63,0x6f,
        0x6d,0x00,0x05,0x74,0x68,0x72,0x65,0x65,0xc0,0x04,0x04,
        0x66,0x6f,0x75,0x72,0xc0,0x04};
    unsigned char compbuf[sizeof(comp_list)];
    char textbuf[sizeof(text_list)];
    int ret;

    memset(compbuf, 0x00, sizeof(compbuf));

    /* Compress the reference text list */
    ret = MRns_name_compress_list(text_list, sizeof(text_list),
                                  compbuf, sizeof(compbuf));

    /* Verify compressed length is correct */
    ATF_REQUIRE_MSG((ret == sizeof(compbuf)), "compressed len %d wrong", ret);

    /* Verify compressed content is correct */
    ATF_REQUIRE_MSG((memcmp(comp_list, compbuf, sizeof(compbuf)) == 0),
                    "compressed buffer content wrong");

    /* Decompress the new compressed list */
    ret = MRns_name_uncompress_list(compbuf, ret, textbuf, sizeof(textbuf));

    /* Verify decompressed length is correct */
    ATF_REQUIRE_MSG((ret == strlen(text_list)),
                    "uncompressed len %d wrong", ret);

    /* Verify decompressed content is correct */
    ATF_REQUIRE_MSG((memcmp(textbuf, text_list, sizeof(textbuf)) == 0),
                    "uncompressed buffer content wrong");
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, MRns_name_list_funcs);

    return (atf_no_error());
}
