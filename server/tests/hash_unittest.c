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

/*
 * The following structures are kept here for reference only. As hash functions
 * are somewhat convoluted, they are copied here for the reference. Original
 * location is specified. Keep in mind that it may change over time:
 *
 * copied from server/omapi.c:49 *
 * omapi_object_type_t *dhcp_type_lease;
 * omapi_object_type_t *dhcp_type_pool;
 * omapi_object_type_t *dhcp_type_class;
 * omapi_object_type_t *dhcp_type_subclass;
 * omapi_object_type_t *dhcp_type_host;
 *
 * copied from server/salloc.c:138
 * OMAPI_OBJECT_ALLOC (lease, struct lease, dhcp_type_lease)
 * OMAPI_OBJECT_ALLOC (class, struct class, dhcp_type_class)
 * OMAPI_OBJECT_ALLOC (subclass, struct class, dhcp_type_subclass)
 * OMAPI_OBJECT_ALLOC (pool, struct pool, dhcp_type_pool)
 * OMAPI_OBJECT_ALLOC (host, struct host_decl, dhcp_type_host)
 *
 * copied from server/mdb.c:2686
 * HASH_FUNCTIONS(lease_ip, const unsigned char *, struct lease, lease_ip_hash_t,
 *                lease_reference, lease_dereference, do_ip4_hash)
 * HASH_FUNCTIONS(lease_id, const unsigned char *, struct lease, lease_id_hash_t,
 *                lease_reference, lease_dereference, do_id_hash)
 * HASH_FUNCTIONS (host, const unsigned char *, struct host_decl, host_hash_t,
 *                 host_reference, host_dereference, do_string_hash)
 * HASH_FUNCTIONS (class, const char *, struct class, class_hash_t,
 *                 class_reference, class_dereference, do_string_hash)
 *
 * copied from server/mdb.c:46
 * host_hash_t *host_hw_addr_hash;
 * host_hash_t *host_uid_hash;
 * host_hash_t *host_name_hash;
 * lease_id_hash_t *lease_uid_hash;
 * lease_ip_hash_t *lease_ip_addr_hash;
 * lease_id_hash_t *lease_hw_addr_hash;
 */

/**
 *  @brief sets client-id field in host declaration
 *
 *  @param host pointer to host declaration
 *  @param uid pointer to client-id data
 *  @param uid_len length of the client-id data
 *
 *  @return 1 if successful, 0 otherwise
 */
int lease_set_clientid(struct host_decl *host, const unsigned char *uid, int uid_len) {
    /* clean-up this mess and set client-identifier in a sane way */
    memset(&host->client_identifier, 0, sizeof(host->client_identifier));
    host->client_identifier.len = uid_len;
    if (!buffer_allocate(&host->client_identifier.buffer, uid_len, MDL)) {
        return 0;
    }
    host->client_identifier.data = host->client_identifier.buffer->data;
    memcpy((char *)host->client_identifier.data, uid, uid_len);

    return 1;
}

ATF_TC(lease_hash_basic);

ATF_TC_HEAD(lease_hash_basic, tc) {
    atf_tc_set_md_var(tc, "descr", "Basic lease hash tests");
    /*
     * The following functions are tested:
     * host_allocate(), host_new_hash(), buffer_allocate(), host_hash_lookup()
     * host_hash_add(), host_hash_delete()
     */
}

ATF_TC_BODY(lease_hash_basic, tc) {

    unsigned char clientid1[] = { 0x1, 0x2, 0x3 };
    unsigned char clientid2[] = { 0xff, 0xfe };

    dhcp_db_objects_setup ();
    dhcp_common_objects_setup ();

    /* check that there is actually zero hosts in the hash */
    /* @todo: host_hash_for_each() */

    struct host_decl *host1 = 0, *host2 = 0;
    struct host_decl *check = 0;

    /* === step 1: allocate hosts === */
    ATF_CHECK_MSG(host_allocate(&host1, MDL) == ISC_R_SUCCESS,
                  "Failed to allocate host");
    ATF_CHECK_MSG(host_allocate(&host2, MDL) == ISC_R_SUCCESS,
                  "Failed to allocate host");

    ATF_CHECK_MSG(host_new_hash(&host_uid_hash, HOST_HASH_SIZE, MDL) != 0,
                  "Unable to create new hash");

    ATF_CHECK_MSG(buffer_allocate(&host1->client_identifier.buffer,
                                  sizeof(clientid1), MDL) != 0,
                  "Can't allocate uid buffer for host1");

    ATF_CHECK_MSG(buffer_allocate(&host2->client_identifier.buffer,
                                  sizeof(clientid2), MDL) != 0,
                  "Can't allocate uid buffer for host2");

    ATF_CHECK_MSG(lease_set_clientid(host1, clientid1, sizeof(clientid1)) != 0,
                  "Failed to set client-id for host1");

    ATF_CHECK_MSG(lease_set_clientid(host2, clientid2, sizeof(clientid2)) != 0,
                  "Failed to set client-id for host2");

    ATF_CHECK_MSG(host1->refcnt == 1, "Invalid refcnt for host1");
    ATF_CHECK_MSG(host2->refcnt == 1, "Invalid refcnt for host2");

    /* verify that our hosts are not in the hash yet */
    ATF_CHECK_MSG(host_hash_lookup(&check, host_uid_hash, clientid1,
                                   sizeof(clientid1), MDL) == 0,
                   "Host1 is not supposed to be in the uid_hash.");

    ATF_CHECK_MSG(!check, "Host1 is not supposed to be in the uid_hash.");

    ATF_CHECK_MSG(host_hash_lookup(&check, host_uid_hash,
                                   (unsigned char *)clientid2,
                                   sizeof(clientid2), MDL) == 0,
                  "Host2 is not supposed to be in the uid_hash.");
    ATF_CHECK_MSG(!check, "Host2 is not supposed to be in the uid_hash.");


    /* === step 2: add first host to the hash === */
    host_hash_add(host_uid_hash, host1->client_identifier.data,
                  host1->client_identifier.len, host1, MDL);

    /* 2 pointers expected: ours (host1) and the one stored in hash */
    ATF_CHECK_MSG(host1->refcnt == 2, "Invalid refcnt for host1");
    /* 1 pointer expected: just ours (host2) */
    ATF_CHECK_MSG(host2->refcnt == 1, "Invalid refcnt for host2");

    /* verify that host1 is really in the hash and the we can find it */
    ATF_CHECK_MSG(host_hash_lookup(&check, host_uid_hash,
                                   (unsigned char *)clientid1,
                                   sizeof(clientid1), MDL),
                  "Host1 was supposed to be in the uid_hash.");
    ATF_CHECK_MSG(check, "Host1 was supposed to be in the uid_hash.");

    /* Hey! That's not the host we were looking for! */
    ATF_CHECK_MSG(check == host1, "Wrong host returned by host_hash_lookup");

    /* 3 pointers: host1, (stored in hash), check */
    ATF_CHECK_MSG(host1->refcnt == 3, "Invalid refcnt for host1");

    /* reference count should be increased because we not have a pointer */

    host_dereference(&check, MDL); /* we don't need it now */

    ATF_CHECK_MSG(check == NULL, "check pointer is supposed to be NULL");

    /* 2 pointers: host1, (stored in hash) */
    ATF_CHECK_MSG(host1->refcnt == 2, "Invalid refcnt for host1");

    /* verify that host2 is not in the hash */
    ATF_CHECK_MSG(host_hash_lookup(&check, host_uid_hash,
                                   (unsigned char *)clientid2,
                                   sizeof(clientid2), MDL) == 0,
                  "Host2 was not supposed to be in the uid_hash[2].");
    ATF_CHECK_MSG(check == NULL, "Host2 was not supposed to be in the hash.");


    /* === step 3: add second hot to the hash === */
    host_hash_add(host_uid_hash, host2->client_identifier.data,
                  host2->client_identifier.len, host2, MDL);

    /* 2 pointers expected: ours (host1) and the one stored in hash */
    ATF_CHECK_MSG(host2->refcnt == 2, "Invalid refcnt for host2");

    ATF_CHECK_MSG(host_hash_lookup(&check, host_uid_hash,
                                   (unsigned char *)clientid2,
                                   sizeof(clientid2), MDL),
                  "Host2 was supposed to be in the uid_hash.");
    ATF_CHECK_MSG(check, "Host2 was supposed to be in the uid_hash.");

    /* Hey! That's not the host we were looking for! */
    ATF_CHECK_MSG(check == host2, "Wrong host returned by host_hash_lookup");

    /* 3 pointers: host1, (stored in hash), check */
    ATF_CHECK_MSG(host2->refcnt == 3, "Invalid refcnt for host1");

    host_dereference(&check, MDL); /* we don't need it now */

    /* now we have 2 hosts in the hash */

    /* verify that host1 is still in the hash and the we can find it */
    ATF_CHECK_MSG(host_hash_lookup(&check, host_uid_hash,
                                   (unsigned char *)clientid1,
                                   sizeof(clientid1), MDL),
                  "Host1 was supposed to be in the uid_hash.");
    ATF_CHECK_MSG(check, "Host1 was supposed to be in the uid_hash.");

    /* Hey! That's not the host we were looking for! */
    ATF_CHECK_MSG(check == host1, "Wrong host returned by host_hash_lookup");

    /* 3 pointers: host1, (stored in hash), check */
    ATF_CHECK_MSG(host1->refcnt == 3, "Invalid refcnt for host1");

    host_dereference(&check, MDL); /* we don't need it now */


    /**
     * @todo check that there is actually two hosts in the hash.
     * Use host_hash_for_each() for that.
     */

    /* === step 4: remove first host from the hash === */

    /* delete host from hash */
    host_hash_delete(host_uid_hash, (unsigned char *) clientid1,
                     sizeof(clientid1), MDL);

    ATF_CHECK_MSG(host1->refcnt == 1, "Invalid refcnt for host1");
    ATF_CHECK_MSG(host2->refcnt == 2, "Invalid refcnt for host2");

    /* verify that host1 is no longer in the hash */
    ATF_CHECK_MSG(host_hash_lookup(&check, host_uid_hash, clientid1,
                                   sizeof(clientid1), MDL) == 0,
                   "Host1 is not supposed to be in the uid_hash.");
    ATF_CHECK_MSG(!check, "Host1 is not supposed to be in the uid_hash.");

    /* host2 should be still there, though */
    ATF_CHECK_MSG(host_hash_lookup(&check, host_uid_hash, clientid2,
                                   sizeof(clientid2), MDL),
                   "Host2 was supposed to still be in the uid_hash.");
    host_dereference(&check, MDL);

    /* === step 5: remove second host from the hash === */
    host_hash_delete(host_uid_hash, (unsigned char *) clientid2,
                     sizeof(clientid2), MDL);

    ATF_CHECK_MSG(host1->refcnt == 1, "Invalid refcnt for host1");
    ATF_CHECK_MSG(host2->refcnt == 1, "Invalid refcnt for host2");

    ATF_CHECK_MSG(host_hash_lookup(&check, host_uid_hash, clientid2,
                                   sizeof(clientid2), MDL) == 0,
                   "Host2 was not supposed to be in the uid_hash anymore.");

    host_dereference(&host1, MDL);
    host_dereference(&host2, MDL);

    /*
     * No easy way to check if the host object were actually released.
     * We could run it in valgrind and check for memory leaks.
     */

#if defined (DEBUG_MEMORY_LEAKAGE) && defined (DEBUG_MEMORY_LEAKAGE_ON_EXIT)
    /* @todo: Should be called in cleanup */
    free_everything ();
#endif

}

ATF_TP_ADD_TCS(tp) {
    ATF_TP_ADD_TC(tp, lease_hash_basic);

    return (atf_no_error());
}
