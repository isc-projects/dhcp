/*
 * Copyright (c) 2012 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   https://www.isc.org/
 *
 */

#include "config.h"
#include <atf-c.h>
#include <omapip/omapip_p.h>
#include "dhcpd.h"

#if 0
/* copied from server/omapi.c:49 */
omapi_object_type_t *dhcp_type_lease;
omapi_object_type_t *dhcp_type_pool;
omapi_object_type_t *dhcp_type_class;
omapi_object_type_t *dhcp_type_subclass;
omapi_object_type_t *dhcp_type_host;

/* copied from server/salloc.c:138 */
OMAPI_OBJECT_ALLOC (lease, struct lease, dhcp_type_lease)
OMAPI_OBJECT_ALLOC (class, struct class, dhcp_type_class)
OMAPI_OBJECT_ALLOC (subclass, struct class, dhcp_type_subclass)
OMAPI_OBJECT_ALLOC (pool, struct pool, dhcp_type_pool)
OMAPI_OBJECT_ALLOC (host, struct host_decl, dhcp_type_host)

/* copied from server/mdb.c:2686 */
HASH_FUNCTIONS(lease_ip, const unsigned char *, struct lease, lease_ip_hash_t,
               lease_reference, lease_dereference, do_ip4_hash)
HASH_FUNCTIONS(lease_id, const unsigned char *, struct lease, lease_id_hash_t,
               lease_reference, lease_dereference, do_id_hash)
HASH_FUNCTIONS (host, const unsigned char *, struct host_decl, host_hash_t,
                host_reference, host_dereference, do_string_hash)
HASH_FUNCTIONS (class, const char *, struct class, class_hash_t,
                class_reference, class_dereference, do_string_hash)

host_hash_t *host_hw_addr_hash;
host_hash_t *host_uid_hash;
host_hash_t *host_name_hash;
lease_id_hash_t *lease_uid_hash;
lease_ip_hash_t *lease_ip_addr_hash;
lease_id_hash_t *lease_hw_addr_hash;
#endif

ATF_TC(lease_hash);

ATF_TC_HEAD(lease_hash, tc) {
    atf_tc_set_md_var(tc, "descr", "Basic hash functions tests");

#if 0
    host_hw_addr_hash = 0;
    host_uid_hash = 0;
    host_name_hash = 0;
    lease_uid_hash = 0;
    lease_ip_addr_hash = 0;
    lease_hw_addr_hash = 0;
#endif
}

ATF_TC_BODY(lease_hash, tc) {

    dhcp_db_objects_setup ();
    dhcp_common_objects_setup ();

    /* check that there is actually zero hosts in the hash */
    // host_hash_for_each(

    struct host_decl *host1 = 0, *host2 = 0;
    ATF_CHECK_MSG(host_allocate(&host1, MDL) == ISC_R_SUCCESS,
                  "Failed to allocate host");
    ATF_CHECK_MSG(host_allocate(&host2, MDL) == ISC_R_SUCCESS,
                  "Failed to allocate host");

    /* check that there is actually two hosts in the hash */
    // host_hash_for_each(...)

    if (!host_new_hash(&host_uid_hash, HOST_HASH_SIZE, MDL)) {
        atf_tc_fail("Unable to create new hash");
    } else {
        printf("#### Hash created\n");
    }

    /* Let's create client-identifier */
    char buf[32];
    memset(buf,0, 32);
    for (int i = 0; i < 32; i++) {
        buf[i] = i;
    }
    int bufLen = 16;

    /* clean-up this mess and set client-identifier in a sane way */
    memset(&host1->client_identifier, 0, sizeof(host1->client_identifier));
    host1->client_identifier.len = bufLen;
    if (!buffer_allocate(&host1->client_identifier.buffer, bufLen, MDL)) {
        atf_tc_fail("Can't allocate uid buffer");
    }
    host1->client_identifier.data = host1->client_identifier.buffer->data;
    memcpy((char *)host1->client_identifier.data, buf, bufLen);

    /* actual test begins. Add hash */
    host_hash_add(host_uid_hash, host1->client_identifier.data,
                  host1->client_identifier.len, host1, MDL);

    /** @todo: do some checks here */

    /* delete host from hash */
    host_hash_delete(host_uid_hash,
                     host1->client_identifier.data,
                     host1->client_identifier.len,
                     MDL);

    /** @todo: do some checks here */

#if defined (DEBUG_MEMORY_LEAKAGE) && defined (DEBUG_MEMORY_LEAKAGE_ON_EXIT)
    /* @todo: Should be called in cleanup */
    free_everything ();
#endif

}

ATF_TP_ADD_TCS(tp) {
    ATF_TP_ADD_TC(tp, lease_hash);

    return (atf_no_error());
}
