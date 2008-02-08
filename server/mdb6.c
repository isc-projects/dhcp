/*
 * Copyright (C) 2007-2008 by Internet Systems Consortium, Inc. ("ISC")
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

/* TODO: assert() */
/* TODO: simplify functions, as pool is now in iaaddr */

#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>

#include "isc-dhcp/result.h"

#include <stdarg.h>
#include "dhcpd.h"
#include "omapip/omapip.h"
#include "omapip/hash.h"
#include "dst/md5.h"

HASH_FUNCTIONS(ia_na, unsigned char *, struct ia_na, ia_na_hash_t,
	       ia_na_reference, ia_na_dereference, do_string_hash);

ia_na_hash_t *ia_active;

HASH_FUNCTIONS(iaaddr, struct in6_addr *, struct iaaddr, iaaddr_hash_t,
	       iaaddr_reference, iaaddr_dereference, do_string_hash);

struct ipv6_pool **pools;
int num_pools;

/*
 * Create a new IAADDR structure.
 *
 * - iaaddr must be a pointer to a (struct iaaddr *) pointer previously
 *   initialized to NULL
 */
isc_result_t
iaaddr_allocate(struct iaaddr **iaaddr, const char *file, int line) {
	struct iaaddr *tmp;

	if (iaaddr == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*iaaddr != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = dmalloc(sizeof(*tmp), file, line);
	if (tmp == NULL) {
		return ISC_R_NOMEMORY;
	}

	tmp->refcnt = 1;
	tmp->state = FTS_FREE;
	tmp->heap_index = -1;

	*iaaddr = tmp;
	return ISC_R_SUCCESS;
}

/*
 * Reference an IAADDR structure.
 *
 * - iaaddr must be a pointer to a (struct iaaddr *) pointer previously
 *   initialized to NULL
 */
isc_result_t
iaaddr_reference(struct iaaddr **iaaddr, struct iaaddr *src,
		 const char *file, int line) {
	if (iaaddr == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*iaaddr != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}
	if (src == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	*iaaddr = src;
	src->refcnt++;
	return ISC_R_SUCCESS;
}


/*
 * Dereference an IAADDR structure.
 *
 * If it is the last reference, then the memory for the 
 * structure is freed.
 */
isc_result_t
iaaddr_dereference(struct iaaddr **iaaddr, const char *file, int line) {
	struct iaaddr *tmp;

	if ((iaaddr == NULL) || (*iaaddr == NULL)) {
		log_error("%s(%d): NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = *iaaddr;
	*iaaddr = NULL;

	tmp->refcnt--;
	if (tmp->refcnt < 0) {
		log_error("%s(%d): negative refcnt", file, line);
		tmp->refcnt = 0;
	}
	if (tmp->refcnt == 0) {
		if (tmp->ia_na != NULL) {
			ia_na_dereference(&(tmp->ia_na), file, line);
		}
		if (tmp->ipv6_pool != NULL) {
			ipv6_pool_dereference(&(tmp->ipv6_pool), file, line);
		}
		if (tmp->scope != NULL) {
			binding_scope_dereference(&tmp->scope, file, line);
		}
		dfree(tmp, file, line);
	}

	return ISC_R_SUCCESS;
}

/* 
 * Make the key that we use for IA_NA.
 */
isc_result_t
ia_na_make_key(struct data_string *key, u_int32_t iaid,
	       const char *duid, unsigned int duid_len,
	       const char *file, int line) {

	memset(key, 0, sizeof(*key));
	key->len = duid_len + sizeof(iaid);
	if (!buffer_allocate(&(key->buffer), key->len, file, line)) {
		return ISC_R_NOMEMORY;
	}
	key->data = key->buffer->data;
	memcpy((char *)key->data, &iaid, sizeof(iaid));
	memcpy((char *)key->data + sizeof(iaid), duid, duid_len);

	return ISC_R_SUCCESS;
}

/*
 * Create a new IA_NA structure.
 *
 * - ia_na must be a pointer to a (struct ia_na *) pointer previously
 *   initialized to NULL
 * - iaid and duid are values from the client
 *
 * XXXsk: we don't concern ourself with the byte order of the IAID, 
 *        which might be a problem if we transfer this structure 
 *        between machines of different byte order
 */
isc_result_t
ia_na_allocate(struct ia_na **ia_na, u_int32_t iaid, 
	       const char *duid, unsigned int duid_len,
	       const char *file, int line) {
	struct ia_na *tmp;

	if (ia_na == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*ia_na != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = dmalloc(sizeof(*tmp), file, line);
	if (tmp == NULL) {
		return ISC_R_NOMEMORY;
	}

	if (ia_na_make_key(&tmp->iaid_duid, iaid, 
			   duid, duid_len, file, line) != ISC_R_SUCCESS) {
		dfree(tmp, file, line);
		return ISC_R_NOMEMORY;
	}

	tmp->refcnt = 1;

	*ia_na = tmp;
	return ISC_R_SUCCESS;
}

/*
 * Reference an IA_NA structure.
 *
 * - ia_na must be a pointer to a (struct ia_na *) pointer previously
 *   initialized to NULL
 */
isc_result_t
ia_na_reference(struct ia_na **ia_na, struct ia_na *src,
		const char *file, int line) {
	if (ia_na == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*ia_na != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}
	if (src == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	*ia_na = src;
	src->refcnt++;
	return ISC_R_SUCCESS;
}

/*
 * Dereference an IA_NA structure.
 *
 * If it is the last reference, then the memory for the 
 * structure is freed.
 */
isc_result_t
ia_na_dereference(struct ia_na **ia_na, const char *file, int line) {
	struct ia_na *tmp;
	int i;

	if ((ia_na == NULL) || (*ia_na == NULL)) {
		log_error("%s(%d): NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = *ia_na;
	*ia_na = NULL;

	tmp->refcnt--;
	if (tmp->refcnt < 0) {
		log_error("%s(%d): negative refcnt", file, line);
		tmp->refcnt = 0;
	}
	if (tmp->refcnt == 0) {
		if (tmp->iaaddr != NULL) {
			for (i=0; i<tmp->num_iaaddr; i++) {
				iaaddr_dereference(&(tmp->iaaddr[i]), 
						   file, line);
			}
			dfree(tmp->iaaddr, file, line);
		}
		data_string_forget(&(tmp->iaid_duid), file, line);
		dfree(tmp, file, line);
	}
	return ISC_R_SUCCESS;
}


/*
 * Add an IAADDR entry to an IA_NA structure.
 */
isc_result_t
ia_na_add_iaaddr(struct ia_na *ia_na, struct iaaddr *iaaddr, 
		 const char *file, int line) {
	int max;
	struct iaaddr **new;

	/* 
	 * Grow our array if we need to.
	 * 
	 * Note: we pick 4 as the increment, as that seems a reasonable
	 *       guess as to how many addresses we might expect on an 
	 *       interface.
	 */
	if (ia_na->max_iaaddr <= ia_na->num_iaaddr) {
		max = ia_na->max_iaaddr + 4;
		new = dmalloc(max * sizeof(struct iaaddr *), file, line);
		if (new == NULL) {
			return ISC_R_NOMEMORY;
		}
		memcpy(new, ia_na->iaaddr, 
		       ia_na->num_iaaddr * sizeof(struct iaaddr *));
		ia_na->iaaddr = new;
		ia_na->max_iaaddr = max;
	}

	iaaddr_reference(&(ia_na->iaaddr[ia_na->num_iaaddr]), iaaddr, 
			 file, line);
	ia_na->num_iaaddr++;

	return ISC_R_SUCCESS;
}

/*
 * Remove an IAADDR entry to an IA_NA structure.
 *
 * Note: if an IAADDR appears more than once, then only ONE will be removed.
 */
void
ia_na_remove_iaaddr(struct ia_na *ia_na, struct iaaddr *iaaddr,
		    const char *file, int line) {
	int i, j;

	for (i=0; i<ia_na->num_iaaddr; i++) {
		if (ia_na->iaaddr[i] == iaaddr) {
			/* remove this IAADDR */
			iaaddr_dereference(&(ia_na->iaaddr[i]), file, line);
			/* move remaining IAADDR pointers down one */
			for (j=i+1; j < ia_na->num_iaaddr; j++) {
				ia_na->iaaddr[j-1] = ia_na->iaaddr[j];
			}
			/* decrease our total count */
			/* remove the back-reference in the IAADDR itself */
			ia_na_dereference(&iaaddr->ia_na, file, line);
			ia_na->num_iaaddr--;
			return;
		}
	}
	log_error("%s(%d): IAADDR not in IA_NA", file, line);
}

/*
 * Remove all addresses from an IA_NA.
 */
void
ia_na_remove_all_iaaddr(struct ia_na *ia_na, const char *file, int line) {
	int i;

	for (i=0; i<ia_na->num_iaaddr; i++) {
		ia_na_dereference(&(ia_na->iaaddr[i]->ia_na), file, line);
		iaaddr_dereference(&(ia_na->iaaddr[i]), file, line);
	}
	ia_na->num_iaaddr = 0;
}

/*
 * Compare two IA_NA.
 */
isc_boolean_t
ia_na_equal(const struct ia_na *a, const struct ia_na *b) 
{
	isc_boolean_t found;
	int i, j;

	/*
	 * Handle cases where one or both of the inputs is NULL.
	 */
	if (a == NULL) {
		if (b == NULL) {
			return ISC_TRUE;
		} else {
			return ISC_FALSE;
		}
	}	

	/*
	 * Check the DUID is the same.
	 */
	if (a->iaid_duid.len != b->iaid_duid.len) {
		return ISC_FALSE;
	}
	if (memcmp(a->iaid_duid.data, 
		   b->iaid_duid.data, a->iaid_duid.len) != 0) {
		return ISC_FALSE;
	}

	/*
	 * Make sure we have the same number of addresses in each.
	 */
	if (a->num_iaaddr != b->num_iaaddr) {
		return ISC_FALSE;
	}

	/*
	 * Check that each address is present in both.
	 */
	for (i=0; i<a->num_iaaddr; i++) {
		found = ISC_FALSE;
		for (j=0; j<a->num_iaaddr; j++) {
			if (memcmp(&(a->iaaddr[i]->addr),
			           &(b->iaaddr[j]->addr), 
				   sizeof(struct in6_addr) == 0)) {
				found = ISC_TRUE;
				break;
			}
		}
		if (!found) {
			return ISC_FALSE;
		}
	}

	/*
	 * These are the same in every way we care about.
	 */
	return ISC_TRUE;
}

/*
 * Helper function for lease heaps.
 * Makes the top of the heap the oldest lease.
 */
static isc_boolean_t 
lease_older(void *a, void *b) {
	struct iaaddr *ia = (struct iaaddr *)a;
	struct iaaddr *ib = (struct iaaddr *)b;

	return difftime(ia->valid_lifetime_end_time, 
			ib->valid_lifetime_end_time) < 0;
}

/*
 * Helper function for lease heaps.
 * Callback when an address's position in the heap changes.
 */
static void
lease_address_index_changed(void *iaaddr, unsigned int new_heap_index) {
	((struct iaaddr *)iaaddr)-> heap_index = new_heap_index;
}


/*
 * Create a new IPv6 lease pool structure.
 *
 * - pool must be a pointer to a (struct ipv6_pool *) pointer previously
 *   initialized to NULL
 */
isc_result_t
ipv6_pool_allocate(struct ipv6_pool **pool,
		   const struct in6_addr *start_addr, int bits, 
		   const char *file, int line) {
	struct ipv6_pool *tmp;

	if (pool == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*pool != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = dmalloc(sizeof(*tmp), file, line);
	if (tmp == NULL) {
		return ISC_R_NOMEMORY;
	}

	tmp->refcnt = 1;
	tmp->start_addr = *start_addr;
	tmp->bits = bits;
	if (!iaaddr_new_hash(&tmp->addrs, DEFAULT_HASH_SIZE, file, line)) {
		dfree(tmp, file, line);
		return ISC_R_NOMEMORY;
	}
	if (isc_heap_create(lease_older, lease_address_index_changed,
			    0, &(tmp->active_timeouts)) != ISC_R_SUCCESS) {
		iaaddr_free_hash_table(&(tmp->addrs), file, line);
		dfree(tmp, file, line);
		return ISC_R_NOMEMORY;
	}
	if (isc_heap_create(lease_older, lease_address_index_changed,
			    0, &(tmp->inactive_timeouts)) != ISC_R_SUCCESS) {
		isc_heap_destroy(&(tmp->active_timeouts));
		iaaddr_free_hash_table(&(tmp->addrs), file, line);
		dfree(tmp, file, line);
		return ISC_R_NOMEMORY;
	}

	*pool = tmp;
	return ISC_R_SUCCESS;
}

/*
 * Reference an IPv6 pool structure.
 *
 * - pool must be a pointer to a (struct pool *) pointer previously
 *   initialized to NULL
 */
isc_result_t
ipv6_pool_reference(struct ipv6_pool **pool, struct ipv6_pool *src,
		    const char *file, int line) {
	if (pool == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*pool != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}
	if (src == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	*pool = src;
	src->refcnt++;
	return ISC_R_SUCCESS;
}

/* 
 * Note: Each IAADDR in a pool is referenced by the pool. This is needed
 * to prevent the IAADDR from being garbage collected out from under the
 * pool.
 *
 * The references are made from the hash and from the heap. The following
 * helper functions dereference these when a pool is destroyed.
 */

/*
 * Helper function for pool cleanup.
 * Dereference each of the hash entries in a pool.
 */
static isc_result_t 
dereference_hash_entry(const void *name, unsigned len, void *value) {
	struct iaaddr *iaaddr = (struct iaaddr *)value;

	iaaddr_dereference(&iaaddr, MDL);
	return ISC_R_SUCCESS;
}

/*
 * Helper function for pool cleanup.
 * Dereference each of the heap entries in a pool.
 */
static void
dereference_heap_entry(void *value, void *dummy) {
	struct iaaddr *iaaddr = (struct iaaddr *)value;

	iaaddr_dereference(&iaaddr, MDL);
}


/*
 * Dereference an IPv6 pool structure.
 *
 * If it is the last reference, then the memory for the 
 * structure is freed.
 */
isc_result_t
ipv6_pool_dereference(struct ipv6_pool **pool, const char *file, int line) {
	struct ipv6_pool *tmp;

	if ((pool == NULL) || (*pool == NULL)) {
		log_error("%s(%d): NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = *pool;
	*pool = NULL;

	tmp->refcnt--;
	if (tmp->refcnt < 0) {
		log_error("%s(%d): negative refcnt", file, line);
		tmp->refcnt = 0;
	}
	if (tmp->refcnt == 0) {
		iaaddr_hash_foreach(tmp->addrs, dereference_hash_entry);
		iaaddr_free_hash_table(&(tmp->addrs), file, line);
		isc_heap_foreach(tmp->active_timeouts, 
				 dereference_heap_entry, NULL);
		isc_heap_destroy(&(tmp->active_timeouts));
		isc_heap_foreach(tmp->inactive_timeouts, 
				 dereference_heap_entry, NULL);
		isc_heap_destroy(&(tmp->inactive_timeouts));
		dfree(tmp, file, line);
	}

	return ISC_R_SUCCESS;
}

/* 
 * Create an address by hashing the input, and using that for
 * the non-network part.
 */
static void
create_address(struct in6_addr *addr, 
	       const struct in6_addr *net_start_addr, int net_bits, 
	       const struct data_string *input) {
	MD5_CTX ctx;
	int net_bytes;
	int i;
	char *str;
	const char *net_str;

	/* 
	 * Use MD5 to get a nice 128 bit hash of the input.
	 * Yes, we know MD5 isn't cryptographically sound. 
	 * No, we don't care.
	 */
	MD5_Init(&ctx);
	MD5_Update(&ctx, input->data, input->len);
	MD5_Final((unsigned char *)addr, &ctx);

	/*
	 * Copy the network bits over.
	 */
	str = (char *)addr;
	net_str = (const char *)net_start_addr;
	net_bytes = net_bits / 8;
	for (i=0; i<net_bytes; i++) {
		str[i] = net_str[i];
	}
	switch (net_bits % 8) {
		case 1: str[i] = (str[i] & 0x7F) | (net_str[i] & 0x80); break;
		case 2: str[i] = (str[i] & 0x3F) | (net_str[i] & 0xC0); break;
		case 3: str[i] = (str[i] & 0x1F) | (net_str[i] & 0xE0); break;
		case 4: str[i] = (str[i] & 0x0F) | (net_str[i] & 0xF0); break;
		case 5: str[i] = (str[i] & 0x07) | (net_str[i] & 0xF8); break;
		case 6: str[i] = (str[i] & 0x03) | (net_str[i] & 0xFC); break;
		case 7: str[i] = (str[i] & 0x01) | (net_str[i] & 0xFE); break;
	}
}

/*
 * Create a lease for the given address and client duid.
 *
 * - pool must be a pointer to a (struct pool *) pointer previously
 *   initialized to NULL
 *
 * Right now we simply hash the DUID, and if we get a collision, we hash 
 * again until we find a free address. We try this a fixed number of times,
 * to avoid getting stuck in a loop (this is important on small pools
 * where we can run out of space).
 *
 * We return the number of attempts that it took to find an available
 * lease. This tells callers when a pool is are filling up, as
 * well as an indication of how full the pool is; statistically the 
 * more full a pool is the more attempts must be made before finding
 * a free lease. Realistically this will only happen in very full
 * pools.
 *
 * We probably want different algorithms depending on the network size, in
 * the long term.
 */
isc_result_t
activate_lease6(struct ipv6_pool *pool, struct iaaddr **addr, 
		unsigned int *attempts,
		const struct data_string *uid, time_t valid_lifetime_end_time) {
	struct data_string ds;
	struct in6_addr tmp;
	struct iaaddr *test_iaaddr;
	struct data_string new_ds;
	struct iaaddr *iaaddr;
	isc_result_t result;

	/* 
	 * Use the UID as our initial seed for the hash
	 */
	memset(&ds, 0, sizeof(ds));
	data_string_copy(&ds, (struct data_string *)uid, MDL);

	*attempts = 0;
	for (;;) {
		/*
		 * Give up at some point.
		 */
		if (++(*attempts) > 100) {
			data_string_forget(&ds, MDL);
			return ISC_R_NORESOURCES;
		}

		/* 
		 * Create an address
		 */
		create_address(&tmp, &pool->start_addr, pool->bits, &ds);

		/*
		 * If this address is not in use, we're happy with it
		 */
		test_iaaddr = NULL;
		if (iaaddr_hash_lookup(&test_iaaddr, pool->addrs,
				       &tmp, sizeof(tmp), MDL) == 0) {
			break;
		}
		iaaddr_dereference(&test_iaaddr, MDL);

		/* 
		 * Otherwise, we create a new input, adding the address
		 */
		memset(&new_ds, 0, sizeof(new_ds));
		new_ds.len = ds.len + sizeof(tmp);
		if (!buffer_allocate(&new_ds.buffer, new_ds.len, MDL)) {
			data_string_forget(&ds, MDL);
			return ISC_R_NOMEMORY;
		}
		new_ds.data = new_ds.buffer->data;
		memcpy(new_ds.buffer->data, ds.data, ds.len);
		memcpy(new_ds.buffer->data + ds.len, &tmp, sizeof(tmp));
		data_string_forget(&ds, MDL);
		data_string_copy(&ds, &new_ds, MDL);
		data_string_forget(&new_ds, MDL);
	}

	data_string_forget(&ds, MDL);

	/* 
	 * We're happy with the address, create an IAADDR
	 * to hold it.
	 */
	iaaddr = NULL;
	result = iaaddr_allocate(&iaaddr, MDL);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	memcpy(&iaaddr->addr, &tmp, sizeof(iaaddr->addr));

	/*
	 * Add the lease to the pool.
	 */
	result = add_lease6(pool, iaaddr, valid_lifetime_end_time);
	if (result == ISC_R_SUCCESS) {
		iaaddr_reference(addr, iaaddr, MDL);
	}
	iaaddr_dereference(&iaaddr, MDL);
	return result;
}

/*
 * Put a lease in the pool directly. This is intended to be used when
 * loading leases from the file.
 */
isc_result_t
add_lease6(struct ipv6_pool *pool, struct iaaddr *iaaddr,
	   time_t valid_lifetime_end_time) {
	isc_result_t insert_result;
	struct iaaddr *test_iaaddr;
	struct iaaddr *tmp_iaaddr;

	/* If a state was not assigned by the caller, assume active. */
	if (iaaddr->state == 0)
		iaaddr->state = FTS_ACTIVE;

	iaaddr->valid_lifetime_end_time = valid_lifetime_end_time;
	ipv6_pool_reference(&iaaddr->ipv6_pool, pool, MDL);

	/*
	 * If this IAADDR is already in our structures, remove the 
	 * old one.
	 */
	test_iaaddr = NULL;
	if (iaaddr_hash_lookup(&test_iaaddr, pool->addrs,
			       &iaaddr->addr, sizeof(iaaddr->addr), MDL)) {
		/* XXX: we should probably ask the iaaddr what heap it is on
		 * (as a consistency check).
		 * XXX: we should probably have one function to "put this lease
		 * on its heap" rather than doing these if's everywhere.  If
		 * you add more states to this list, don't.
		 */
		if ((test_iaaddr->state == FTS_ACTIVE) ||
		    (test_iaaddr->state == FTS_ABANDONED)) {
			isc_heap_delete(pool->active_timeouts,
					test_iaaddr->heap_index);
			pool->num_active--;
		} else {
			isc_heap_delete(pool->inactive_timeouts,
					test_iaaddr->heap_index);
			pool->num_inactive--;
		}

		iaaddr_hash_delete(pool->addrs, &test_iaaddr->addr, 
				   sizeof(test_iaaddr->addr), MDL);

		/*
		 * We're going to do a bit of evil trickery here.
		 *
		 * We need to dereference the entry once to remove our
		 * current reference (in test_iaaddr), and then one
		 * more time to remove the reference left when the
		 * address was added to the pool before.
		 */
		tmp_iaaddr = test_iaaddr;
		iaaddr_dereference(&test_iaaddr, MDL);
		iaaddr_dereference(&tmp_iaaddr, MDL);
	}

	/* 
	 * Add IAADDR to our structures.
	 */
	tmp_iaaddr = NULL;
	iaaddr_reference(&tmp_iaaddr, iaaddr, MDL);
	if ((tmp_iaaddr->state == FTS_ACTIVE) ||
	    (tmp_iaaddr->state == FTS_ABANDONED)) {
		iaaddr_hash_add(pool->addrs, &tmp_iaaddr->addr, 
				sizeof(tmp_iaaddr->addr), iaaddr, MDL);
		insert_result = isc_heap_insert(pool->active_timeouts,
						tmp_iaaddr);
		if (insert_result == ISC_R_SUCCESS)
			pool->num_active++;
	} else {
		insert_result = isc_heap_insert(pool->inactive_timeouts,
						tmp_iaaddr);
		if (insert_result == ISC_R_SUCCESS)
			pool->num_inactive++;
	}
	if (insert_result != ISC_R_SUCCESS) {
		iaaddr_hash_delete(pool->addrs, &iaaddr->addr, 
				   sizeof(iaaddr->addr), MDL);
		iaaddr_dereference(&tmp_iaaddr, MDL);
		return insert_result;
	}

	/* 
	 * Note: we intentionally leave tmp_iaaddr referenced; there
	 * is a reference in the heap/hash, after all.
	 */

	return ISC_R_SUCCESS;
}

/*
 * Determine if an address is present in a pool or not.
 */
isc_boolean_t
lease6_exists(const struct ipv6_pool *pool, const struct in6_addr *addr) {
	struct iaaddr *test_iaaddr;

	test_iaaddr = NULL;
	if (iaaddr_hash_lookup(&test_iaaddr, pool->addrs, 
			       (void *)addr, sizeof(*addr), MDL)) {
		iaaddr_dereference(&test_iaaddr, MDL);
		return ISC_TRUE;
	} else {
		return ISC_FALSE;
	}
}

/*
 * Put the lease on our active pool.
 */
static isc_result_t
move_lease_to_active(struct ipv6_pool *pool, struct iaaddr *addr) {
	isc_result_t insert_result;
	int old_heap_index;

	old_heap_index = addr->heap_index;
	insert_result = isc_heap_insert(pool->active_timeouts, addr);
	if (insert_result == ISC_R_SUCCESS) {
       		iaaddr_hash_add(pool->addrs, &addr->addr, 
				sizeof(addr->addr), addr, MDL);
		isc_heap_delete(pool->inactive_timeouts, old_heap_index);
		pool->num_active++;
		pool->num_inactive--;
		addr->state = FTS_ACTIVE;
	}
	return insert_result;
}

/*
 * Renew an lease in the pool.
 *
 * To do this, first set the new valid_lifetime_end_time for the address, 
 * and then invoke renew_lease() on the address.
 *
 * WARNING: lease times must only be extended, never reduced!!!
 */
isc_result_t
renew_lease6(struct ipv6_pool *pool, struct iaaddr *addr) {
	/*
	 * If we're already active, then we can just move our expiration
	 * time down the heap. 
	 *
	 * Otherwise, we have to move from the inactive heap to the 
	 * active heap.
	 */
	if (addr->state == FTS_ACTIVE) {
		isc_heap_decreased(pool->active_timeouts, addr->heap_index);
		return ISC_R_SUCCESS;
	} else {
		return move_lease_to_active(pool, addr);
	}
}

/*
 * Put the lease on our inactive pool, with the specified state.
 */
static isc_result_t
move_lease_to_inactive(struct ipv6_pool *pool, struct iaaddr *addr, 
		       binding_state_t state) {
	isc_result_t insert_result;
	int old_heap_index;

	old_heap_index = addr->heap_index;
	insert_result = isc_heap_insert(pool->inactive_timeouts, addr);
	if (insert_result == ISC_R_SUCCESS) {
		/* Process events upon expiration. */
		ddns_removals(NULL, addr);

		/* Binding scopes are no longer valid after expiry or
		 * release.
		 */
		if (addr->scope != NULL) {
			binding_scope_dereference(&addr->scope, MDL);
		}

		iaaddr_hash_delete(pool->addrs, 
				   &addr->addr, sizeof(addr->addr), MDL);
		isc_heap_delete(pool->active_timeouts, old_heap_index);
		addr->state = state;
		pool->num_active--;
		pool->num_inactive++;
	}
	return insert_result;
}

/*
 * Expire the oldest lease if it's lifetime_end_time is 
 * older than the given time.
 *
 * - iaaddr must be a pointer to a (struct iaaddr *) pointer previously
 *   initialized to NULL
 *
 * On return iaaddr has a reference to the removed entry. It is left
 * pointing to NULL if the oldest lease has not expired.
 */
isc_result_t
expire_lease6(struct iaaddr **addr, struct ipv6_pool *pool, time_t now) {
	struct iaaddr *tmp;
	isc_result_t result;

	if (addr == NULL) {
		log_error("%s(%d): NULL pointer reference", MDL);
		return ISC_R_INVALIDARG;
	}
	if (*addr != NULL) {
		log_error("%s(%d): non-NULL pointer", MDL);
		return ISC_R_INVALIDARG;
	}

	if (pool->num_active > 0) {
		tmp = (struct iaaddr *)isc_heap_element(pool->active_timeouts, 
							1);
		if (now > tmp->valid_lifetime_end_time) {
			result = move_lease_to_inactive(pool, tmp, FTS_EXPIRED);
			if (result == ISC_R_SUCCESS) {
				iaaddr_reference(addr, tmp, MDL);
			}
			return result;
		}
	}
	return ISC_R_SUCCESS;
}


/*
 * For a declined lease, leave it on the "active" pool, but mark
 * it as declined. Give it an infinite (well, really long) life.
 */
isc_result_t
decline_lease6(struct ipv6_pool *pool, struct iaaddr *addr) {
	isc_result_t result;

	if (addr->state != FTS_ACTIVE) {
		result = move_lease_to_active(pool, addr);
		if (result != ISC_R_SUCCESS) {
			return result;
		}
	}
	addr->state = FTS_ABANDONED;
	addr->valid_lifetime_end_time = MAX_TIME;
	isc_heap_decreased(pool->active_timeouts, addr->heap_index);
	return ISC_R_SUCCESS;
}

/*
 * Put the returned lease on our inactive pool.
 */
isc_result_t
release_lease6(struct ipv6_pool *pool, struct iaaddr *addr) {
	if (addr->state == FTS_ACTIVE) {
		return move_lease_to_inactive(pool, addr, FTS_RELEASED);
	} else {
		return ISC_R_SUCCESS;
	}
}

/*
 * Mark an IPv6 address as unavailable from a pool.
 *
 * This is used for host entries and the addresses of the server itself.
 */
isc_result_t
mark_address_unavailable(struct ipv6_pool *pool, const struct in6_addr *addr) {
	struct iaaddr *dummy_iaaddr;
	isc_result_t result;

	dummy_iaaddr = NULL;
	result = iaaddr_allocate(&dummy_iaaddr, MDL);
	if (result == ISC_R_SUCCESS) {
		dummy_iaaddr->addr = *addr;
		iaaddr_hash_add(pool->addrs, &dummy_iaaddr->addr,
				sizeof(*addr), dummy_iaaddr, MDL);
	}
	return result;
}

/* 
 * Add a pool.
 */
isc_result_t
add_ipv6_pool(struct ipv6_pool *pool) {
	struct ipv6_pool **new_pools;

	new_pools = dmalloc(sizeof(struct ipv6_pool *) * (num_pools+1), MDL);
	if (new_pools == NULL) {
		return ISC_R_NOMEMORY;
	}

	if (num_pools > 0) {
		memcpy(new_pools, pools, 
		       sizeof(struct ipv6_pool *) * num_pools);
		dfree(pools, MDL);
	}
	pools = new_pools;

	pools[num_pools] = NULL;
	ipv6_pool_reference(&pools[num_pools], pool, MDL);
	num_pools++;
	return ISC_R_SUCCESS;
}


static void
cleanup_old_expired(struct ipv6_pool *pool) {
	struct iaaddr *tmp;
	struct ia_na *ia_na;
	struct ia_na *ia_na_active;
	unsigned char *tmpd;
	
	while (pool->num_inactive > 0) {
		tmp = (struct iaaddr *)isc_heap_element(pool->inactive_timeouts,
							1);
		if (cur_time < 
		    tmp->valid_lifetime_end_time + EXPIRED_IPV6_CLEANUP_TIME) {
			break;
		}

		isc_heap_delete(pool->inactive_timeouts, tmp->heap_index);
		pool->num_inactive--;

		if (tmp->ia_na != NULL) {
			/*
			 * Check to see if this IA_NA is in the active list,
			 * but has no remaining addresses. If so, remove it
			 * from the active list.
			 */
			ia_na = NULL;
			ia_na_reference(&ia_na, tmp->ia_na, MDL);
			ia_na_remove_iaaddr(ia_na, tmp, MDL);
			ia_na_active = NULL;
			tmpd = (unsigned char *)ia_na->iaid_duid.data;
			if ((ia_na->num_iaaddr <= 0) &&
			    (ia_na_hash_lookup(&ia_na_active, ia_active, tmpd,
			    		       ia_na->iaid_duid.len,
					       MDL) == 0) &&
			    (ia_na_active == ia_na)) {
				ia_na_hash_delete(ia_active, tmpd, 
					  	  ia_na->iaid_duid.len, MDL);
			}
			ia_na_dereference(&ia_na, MDL);
		}
		iaaddr_dereference(&tmp, MDL);
	}
}

static void
lease_timeout_support(void *vpool) {
	struct ipv6_pool *pool;
	struct iaaddr *addr;
	
	pool = (struct ipv6_pool *)vpool;
	for (;;) {
		/*
		 * Get the next lease scheduled to expire.
		 *
		 * Note that if there are no leases in the pool, 
		 * expire_lease6() will return ISC_R_SUCCESS with 
		 * a NULL lease.
		 */
		addr = NULL;
		if (expire_lease6(&addr, pool, cur_time) != ISC_R_SUCCESS) {
			break;
		}
		if (addr == NULL) {
			break;
		}

		/* Look to see if there were ddns updates, and if
		 * so, drop them.
		 *
		 * DH: Do we want to do this on a special 'depref'
		 * timer rather than expiration timer?
		 */
		ddns_removals(NULL, addr);

		write_ia_na(addr->ia_na);

		iaaddr_dereference(&addr, MDL);
	}

	/*
	 * Do some cleanup of our expired leases.
	 */
	cleanup_old_expired(pool);

	/*
	 * Schedule next round of expirations.
	 */
	schedule_lease_timeout(pool);
}

/*
 * For a given pool, add a timer that will remove the next
 * lease to expire.
 */
void 
schedule_lease_timeout(struct ipv6_pool *pool) {
	struct iaaddr *tmp;
	time_t timeout;
	time_t next_timeout;

	next_timeout = MAX_TIME;

	if (pool->num_active > 0) {
		tmp = (struct iaaddr *)isc_heap_element(pool->active_timeouts, 
							1);
		if (tmp->valid_lifetime_end_time < next_timeout) {
			next_timeout = tmp->valid_lifetime_end_time + 1;
		}
	}

	if (pool->num_inactive > 0) {
		tmp = (struct iaaddr *)isc_heap_element(pool->inactive_timeouts,
							1);
		timeout = tmp->valid_lifetime_end_time + 
			  EXPIRED_IPV6_CLEANUP_TIME;
		if (timeout < next_timeout) {
			next_timeout = timeout;
		}
	}

	if (next_timeout < MAX_TIME) {
		add_timeout(next_timeout, lease_timeout_support, pool,
			    (tvref_t)ipv6_pool_reference, 
			    (tvunref_t)ipv6_pool_dereference);
	}
}

/*
 * Schedule timeouts across all pools.
 */
void
schedule_all_ipv6_lease_timeouts(void) {
	int i;

	for (i=0; i<num_pools; i++) {
		schedule_lease_timeout(pools[i]);
	}
}

/* 
 * Given an address and the length of the network mask, return
 * only the network portion.
 *
 * Examples:
 *
 *   "fe80::216:6fff:fe49:7d9b", length 64 = "fe80::"
 *   "2001:888:1936:2:216:6fff:fe49:7d9b", length 48 = "2001:888:1936::"
 */
static void
ipv6_network_portion(struct in6_addr *result, 
		     const struct in6_addr *addr, int bits) {
	unsigned char *addrp;
	int mask_bits;
	int bytes;
	int extra_bits;
	int i;

	static const unsigned char bitmasks[] = {
		0x00, 0xFE, 0xFC, 0xF8, 
		0xF0, 0xE0, 0xC0, 0x80, 
	};

	/* 
	 *  Sanity check our bits. ;)
	 */
	if ((bits < 0) || (bits > 128)) {
		log_fatal("ipv6_network_portion: bits %d not between 0 and 128",
			  bits);
	}

	/* 
	 * Copy our address portion.
	 */
	*result = *addr;
	addrp = ((unsigned char *)result) + 15;

	/* 
	 * Zero out masked portion.
	 */
	mask_bits = 128 - bits;
	bytes = mask_bits / 8;
	extra_bits = mask_bits % 8;

	for (i=0; i<bytes; i++) {
		*addrp = 0;
		addrp--;
	}
	if (extra_bits) {
		*addrp &= bitmasks[extra_bits];
	}
}

/*
 * Determine if the given address is in the pool.
 */
isc_boolean_t
ipv6_addr_in_pool(const struct in6_addr *addr, const struct ipv6_pool *pool) {
	struct in6_addr tmp;
	
	ipv6_network_portion(&tmp, addr, pool->bits);
	if (memcmp(&tmp, &pool->start_addr, sizeof(tmp)) == 0) {
		return ISC_TRUE;
	} else {
		return ISC_FALSE;
	}
}

/*
 * Find the pool that contains the given address.
 *
 * - pool must be a pointer to a (struct ipv6_pool *) pointer previously
 *   initialized to NULL
 */
isc_result_t
find_ipv6_pool(struct ipv6_pool **pool, const struct in6_addr *addr) {
	int i;

	if (pool == NULL) {
		log_error("%s(%d): NULL pointer reference", MDL);
		return ISC_R_INVALIDARG;
	}
	if (*pool != NULL) {
		log_error("%s(%d): non-NULL pointer", MDL);
		return ISC_R_INVALIDARG;
	}

	for (i=0; i<num_pools; i++) {
		if (ipv6_addr_in_pool(addr, pools[i])) { 
			ipv6_pool_reference(pool, pools[i], MDL);
			return ISC_R_SUCCESS;
		}
	}
	return ISC_R_NOTFOUND;
}

/*
 * Helper function for the various functions that act across all
 * pools.
 */
static isc_result_t 
change_leases(struct ia_na *ia_na, 
	      isc_result_t (*change_func)(struct ipv6_pool *, struct iaaddr*)) {
	isc_result_t retval;
	isc_result_t renew_retval;
	struct ipv6_pool *pool;
	struct in6_addr *addr;
	int i;

	retval = ISC_R_SUCCESS;
	for (i=0; i<ia_na->num_iaaddr; i++) {
		pool = NULL;
		addr = &ia_na->iaaddr[i]->addr;
		if (find_ipv6_pool(&pool, addr) == ISC_R_SUCCESS) {
			renew_retval =  change_func(pool, ia_na->iaaddr[i]);
			if (renew_retval != ISC_R_SUCCESS) {
				retval = renew_retval;
			}
		}
		/* XXXsk: should we warn if we don't find a pool? */
	}
	return retval;
}

/*
 * Renew all leases in an IA_NA from all pools.
 *
 * The new valid_lifetime_end_time should be updated for the addresses.
 *
 * WARNING: lease times must only be extended, never reduced!!!
 */
isc_result_t 
renew_leases(struct ia_na *ia_na) {
	return change_leases(ia_na, renew_lease6);
}

/*
 * Release all leases in an IA_NA from all pools.
 */
isc_result_t 
release_leases(struct ia_na *ia_na) {
	return change_leases(ia_na, release_lease6);
}

/*
 * Decline all leases in an IA_NA from all pools.
 */
isc_result_t 
decline_leases(struct ia_na *ia_na) {
	return change_leases(ia_na, decline_lease6);
}

#ifdef DHCPv6
/*
 * Helper function to output leases.
 */
static int write_error;

static isc_result_t 
write_ia_na_leases(const void *name, unsigned len, void *value) {
	struct ia_na *ia_na = (struct ia_na *)value;
	
	if (!write_error) { 
		if (!write_ia_na(ia_na)) {
			write_error = 1;
		}
	}
	return ISC_R_SUCCESS;
}

/*
 * Write all DHCPv6 information.
 */
int
write_leases6(void) {
	write_error = 0;
	write_server_duid();
	iaaddr_hash_foreach(ia_active, write_ia_na_leases);
	if (write_error) {
		return 0;
	}
	return 1;
}
#endif /* DHCPv6 */

static isc_result_t
mark_hosts_unavailable_support(const void *name, unsigned len, void *value) {
	struct host_decl *h;
	struct data_string fixed_addr;
	struct in6_addr addr;
	struct ipv6_pool *p;

	h = (struct host_decl *)value;

	/*
	 * If the host has no address, we don't need to mark anything.
	 */
	if (h->fixed_addr == NULL) {
		return ISC_R_SUCCESS;
	}

	/* 
	 * Evaluate the fixed address.
	 */
	memset(&fixed_addr, 0, sizeof(fixed_addr));
	if (!evaluate_option_cache(&fixed_addr, NULL, NULL, NULL, NULL, NULL,
				   &global_scope, h->fixed_addr, MDL)) {
		log_error("mark_hosts_unavailable: "
			  "error evaluating host address.");
		return ISC_R_SUCCESS;
	}
	if (fixed_addr.len != 16) {
		log_error("mark_hosts_unavailable: "
			  "host address is not 128 bits.");
		return ISC_R_SUCCESS;
	}
	memcpy(&addr, fixed_addr.data, 16);
	data_string_forget(&fixed_addr, MDL);

	/*
	 * Find the pool holding this host, and mark the address.
	 * (I suppose it is arguably valid to have a host that does not
	 * sit in any pool.)
	 */
	p = NULL;
	if (find_ipv6_pool(&p, &addr) == ISC_R_SUCCESS) {
		mark_address_unavailable(p, &addr);
		ipv6_pool_dereference(&p, MDL);
	} 

	return ISC_R_SUCCESS;
}

void
mark_hosts_unavailable(void) {
	hash_foreach(host_name_hash, mark_hosts_unavailable_support);
}

void 
mark_interfaces_unavailable(void) {
	struct interface_info *ip;
	int i;
	struct ipv6_pool *p;

	ip = interfaces;
	while (ip != NULL) {
		for (i=0; i<ip->v6address_count; i++) {
			p = NULL;
			if (find_ipv6_pool(&p, &ip->v6addresses[i]) 
							== ISC_R_SUCCESS) {
				mark_address_unavailable(p, 
							 &ip->v6addresses[i]);
				ipv6_pool_dereference(&p, MDL);
			} 
		}
		ip = ip->next;
	}
}


#ifdef UNIT_TEST
#include <stdlib.h>

int 
main(int argc, char *argv[]) {
	struct iaaddr *iaaddr;
	struct iaaddr *iaaddr_copy;
	u_int32_t iaid;
	struct ia_na *ia_na;
	struct ia_na *ia_na_copy;
	int i;
	struct in6_addr addr;
	struct ipv6_pool *pool;
	struct ipv6_pool *pool_copy;
	char addr_buf[INET6_ADDRSTRLEN];
	char *uid;
	struct data_string ds;
	struct iaaddr *expired_iaaddr;
	unsigned int attempts;

	/*
	 * Test 0: Basic iaaddr manipulation.
	 */
	iaaddr = NULL;
	if (iaaddr_allocate(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_allocate() %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr->state != FTS_FREE) {
		printf("ERROR: bad state %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr->heap_index != -1) {
		printf("ERROR: bad heap_index %s:%d\n", MDL);
		return 1;
	}
	iaaddr_copy = NULL;
	if (iaaddr_reference(&iaaddr_copy, iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_reference() %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_reference() %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&iaaddr_copy, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_reference() %s:%d\n", MDL);
		return 1;
	}

	/* 
	 * Test 1: Error iaaddr manipulation.
	 */
	/* bogus allocate arguments */
	if (iaaddr_allocate(NULL, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: iaaddr_allocate() %s:%d\n", MDL);
		return 1;
	}
	iaaddr = (struct iaaddr *)1;
	if (iaaddr_allocate(&iaaddr, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: iaaddr_allocate() %s:%d\n", MDL);
		return 1;
	}

	/* bogus reference arguments */
	iaaddr = NULL;
	if (iaaddr_allocate(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_allocate() %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_reference(NULL, iaaddr, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: iaaddr_reference() %s:%d\n", MDL);
		return 1;
	}
	iaaddr_copy = (struct iaaddr *)1;
	if (iaaddr_reference(&iaaddr_copy, iaaddr, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: iaaddr_reference() %s:%d\n", MDL);
		return 1;
	}
	iaaddr_copy = NULL;
	if (iaaddr_reference(&iaaddr_copy, NULL, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: iaaddr_reference() %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_reference() %s:%d\n", MDL);
		return 1;
	}

	/* bogus dereference arguments */
	if (iaaddr_dereference(NULL, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
		return 1;
	}
	iaaddr = NULL;
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
		return 1;
	}

	/*
	 * Test 2: Basic ia_na manipulation.
	 */
	iaid = 666;
	ia_na = NULL;
	if (ia_na_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_allocate() %s:%d\n", MDL);
		return 1;
	}
	if (memcmp(ia_na->iaid_duid.data, &iaid, sizeof(iaid)) != 0) {
		printf("ERROR: bad IAID_DUID %s:%d\n", MDL);
		return 1;
	}
	if (memcmp(ia_na->iaid_duid.data+sizeof(iaid), "TestDUID", 8) != 0) {
		printf("ERROR: bad IAID_DUID %s:%d\n", MDL);
		return 1;
	}
	if (ia_na->num_iaaddr != 0) {
		printf("ERROR: bad num_iaaddr %s:%d\n", MDL);
		return 1;
	}
	ia_na_copy = NULL;
	if (ia_na_reference(&ia_na_copy, ia_na, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_reference() %s:%d\n", MDL);
		return 1;
	}
	iaaddr = NULL;
	if (iaaddr_allocate(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_allocate() %s:%d\n", MDL);
		return 1;
	}
	if (ia_na_add_iaaddr(ia_na, iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_add_iaaddr() %s:%d\n", MDL);
		return 1;
	}
	ia_na_remove_iaaddr(ia_na, iaaddr, MDL);
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_reference() %s:%d\n", MDL);
		return 1;
	}
	if (ia_na_dereference(&ia_na, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_dereference() %s:%d\n", MDL);
		return 1;
	}
	if (ia_na_dereference(&ia_na_copy, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_dereference() %s:%d\n", MDL);
		return 1;
	}

	/* 
	 * Test 3: lots of iaaddr in our ia_na
	 */

	/* lots of iaaddr that we delete */
	iaid = 666;
	ia_na = NULL;
	if (ia_na_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_allocate() %s:%d\n", MDL);
		return 1;
	}
	for (i=0; i<100; i++) {
		iaaddr = NULL;
		if (iaaddr_allocate(&iaaddr, MDL) != ISC_R_SUCCESS) {
			printf("ERROR: iaaddr_allocate() %s:%d\n", MDL);
			return 1;
		}
		if (ia_na_add_iaaddr(ia_na, iaaddr, MDL) != ISC_R_SUCCESS) {
			printf("ERROR: ia_na_add_iaaddr() %s:%d\n", MDL);
			return 1;
		}
		if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
			printf("ERROR: iaaddr_reference() %s:%d\n", MDL);
			return 1;
		}
	}
	for (i=0; i<100; i++) {
		iaaddr = ia_na->iaaddr[random() % ia_na->num_iaaddr];
		ia_na_remove_iaaddr(ia_na, iaaddr, MDL);
	}
	if (ia_na_dereference(&ia_na, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_dereference() %s:%d\n", MDL);
		return 1;
	}

	/* lots of iaaddr, let dereference cleanup */
	iaid = 666;
	ia_na = NULL;
	if (ia_na_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_allocate() %s:%d\n", MDL);
		return 1;
	}
	for (i=0; i<100; i++) {
		iaaddr = NULL;
		if (iaaddr_allocate(&iaaddr, MDL) != ISC_R_SUCCESS) {
			printf("ERROR: iaaddr_allocate() %s:%d\n", MDL);
			return 1;
		}
		if (ia_na_add_iaaddr(ia_na, iaaddr, MDL) != ISC_R_SUCCESS) {
			printf("ERROR: ia_na_add_iaaddr() %s:%d\n", MDL);
			return 1;
		}
		if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
			printf("ERROR: iaaddr_reference() %s:%d\n", MDL);
			return 1;
		}
	}
	if (ia_na_dereference(&ia_na, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_dereference() %s:%d\n", MDL);
		return 1;
	}

	/*
	 * Test 4: Errors in ia_na.
	 */
	/* bogus allocate arguments */
	if (ia_na_allocate(NULL, 123, "", 0, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ia_na_allocate() %s:%d\n", MDL);
		return 1;
	}
	ia_na = (struct ia_na *)1;
	if (ia_na_allocate(&ia_na, 456, "", 0, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ia_na_allocate() %s:%d\n", MDL);
		return 1;
	}

	/* bogus reference arguments */
	iaid = 666;
	ia_na = NULL;
	if (ia_na_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_allocate() %s:%d\n", MDL);
		return 1;
	}
	if (ia_na_reference(NULL, ia_na, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ia_na_reference() %s:%d\n", MDL);
		return 1;
	}
	ia_na_copy = (struct ia_na *)1;
	if (ia_na_reference(&ia_na_copy, ia_na, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ia_na_reference() %s:%d\n", MDL);
		return 1;
	}
	ia_na_copy = NULL;
	if (ia_na_reference(&ia_na_copy, NULL, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ia_na_reference() %s:%d\n", MDL);
		return 1;
	}
	if (ia_na_dereference(&ia_na, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_dereference() %s:%d\n", MDL);
		return 1;
	}

	/* bogus dereference arguments */
	if (ia_na_dereference(NULL, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ia_na_dereference() %s:%d\n", MDL);
		return 1;
	}

	/* bogus remove */
	iaid = 666;
	ia_na = NULL;
	if (ia_na_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_allocate() %s:%d\n", MDL);
		return 1;
	}
	ia_na_remove_iaaddr(ia_na, NULL, MDL);
	if (ia_na_dereference(&ia_na, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_dereference() %s:%d\n", MDL);
		return 1;
	}

	/*
	 * Test 5: Basic ipv6_pool manipulation.
	 */

	/* allocate, reference */
	inet_pton(AF_INET6, "1:2:3:4::", &addr);
	pool = NULL;
	if (ipv6_pool_allocate(&pool, &addr, 64, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
		return 1;
	}
	if (pool->num_active != 0) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	if (pool->bits != 64) {
		printf("ERROR: bad bits %s:%d\n", MDL);
		return 1;
	}
	inet_ntop(AF_INET6, &pool->start_addr, addr_buf, sizeof(addr_buf));
	if (strcmp(inet_ntop(AF_INET6, &pool->start_addr, addr_buf, 
			     sizeof(addr_buf)), "1:2:3:4::") != 0) {
		printf("ERROR: bad start_addr %s:%d\n", MDL);
		return 1;
	}
	pool_copy = NULL;
	if (ipv6_pool_reference(&pool_copy, pool, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
		return 1;
	}

	/* activate_lease6, renew_lease6, expire_lease6 */
	uid = "client0";
	memset(&ds, 0, sizeof(ds));
	ds.len = strlen(uid);
	if (!buffer_allocate(&ds.buffer, ds.len, MDL)) {
		printf("Out of memory\n");
		return 1;
	}
	ds.data = ds.buffer->data;
	memcpy((char *)ds.data, uid, ds.len);
	if (activate_lease6(pool, &iaaddr, 
			    &attempts, &ds, 1) != ISC_R_SUCCESS) {
		printf("ERROR: activate_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (pool->num_active != 1) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	if (renew_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
		printf("ERROR: renew_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (pool->num_active != 1) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	expired_iaaddr = NULL;
	if (expire_lease6(&expired_iaaddr, pool, 0) != ISC_R_SUCCESS) {
		printf("ERROR: expire_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (expired_iaaddr != NULL) {
		printf("ERROR: should not have expired a lease %s:%d\n", MDL);
		return 1;
	}
	if (pool->num_active != 1) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	if (expire_lease6(&expired_iaaddr, pool, 1000) != ISC_R_SUCCESS) {
		printf("ERROR: expire_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (expired_iaaddr == NULL) {
		printf("ERROR: should have expired a lease %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&expired_iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
		return 1;
	}
	if (pool->num_active != 0) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
		return 1;
	}

	/* release_lease6, decline_lease6 */
	if (activate_lease6(pool, &iaaddr, &attempts, 
			    &ds, 1) != ISC_R_SUCCESS) {
		printf("ERROR: activate_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (pool->num_active != 1) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	if (release_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
		printf("ERROR: decline_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (pool->num_active != 0) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
		return 1;
	}
	if (activate_lease6(pool, &iaaddr, &attempts, 
			    &ds, 1) != ISC_R_SUCCESS) {
		printf("ERROR: activate_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (pool->num_active != 1) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	if (decline_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
		printf("ERROR: decline_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (pool->num_active != 1) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
		return 1;
	}

	/* dereference */
	if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(&pool_copy, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
		return 1;
	}

	/*
	 * Test 6: Error ipv6_pool manipulation
	 */
	if (ipv6_pool_allocate(NULL, &addr, 64, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
		return 1;
	}
	pool = (struct ipv6_pool *)1;
	if (ipv6_pool_allocate(&pool, &addr, 64, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_reference(NULL, pool, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
		return 1;
	}
	pool_copy = (struct ipv6_pool *)1;
	if (ipv6_pool_reference(&pool_copy, pool, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
		return 1;
	}
	pool_copy = NULL;
	if (ipv6_pool_reference(&pool_copy, NULL, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ipv6_pool_reference() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(NULL, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(&pool_copy, MDL) != ISC_R_INVALIDARG) {
		printf("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
		return 1;
	}

	/*
	 * Test 7: order of expiration
	 */
	pool = NULL;
	if (ipv6_pool_allocate(&pool, &addr, 64, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
		return 1;
	}
	for (i=10; i<100; i+=10) {
		if (activate_lease6(pool, &iaaddr, &attempts,
				    &ds, i) != ISC_R_SUCCESS) {
			printf("ERROR: activate_lease6() %s:%d\n", MDL);
			return 1;
		}
		if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
			printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
			return 1;
		}
		if (pool->num_active != (i / 10)) {
			printf("ERROR: bad num_active %s:%d\n", MDL);
			return 1;
		}
	}
	if (pool->num_active != 9) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	for (i=10; i<100; i+=10) {
		if (expire_lease6(&expired_iaaddr, 
				  pool, 1000) != ISC_R_SUCCESS) {
			printf("ERROR: expire_lease6() %s:%d\n", MDL);
			return 1;
		}
		if (expired_iaaddr == NULL) {
			printf("ERROR: should have expired a lease %s:%d\n", 
			       MDL);
			return 1;
		}
		if (pool->num_active != (9 - (i / 10))) {
			printf("ERROR: bad num_active %s:%d\n", MDL);
			return 1;
		}
		if (expired_iaaddr->valid_lifetime_end_time != i) {
			printf("ERROR: bad valid_lifetime_end_time %s:%d\n", 
			       MDL);
			return 1;
		}
		if (iaaddr_dereference(&expired_iaaddr, MDL) != ISC_R_SUCCESS) {
			printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
			return 1;
		}
	}
	if (pool->num_active != 0) {
		printf("ERROR: bad num_active %s:%d\n", MDL);
		return 1;
	}
	expired_iaaddr = NULL;
	if (expire_lease6(&expired_iaaddr, pool, 1000) != ISC_R_SUCCESS) {
		printf("ERROR: expire_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
		return 1;
	}

	/*
	 * Test 8: small pool
	 */
	pool = NULL;
	if (ipv6_pool_allocate(&pool, &addr, 127, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
		return 1;
	}
	if (activate_lease6(pool, &iaaddr, &attempts, 
			    &ds, 42) != ISC_R_SUCCESS) {
		printf("ERROR: activate_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
		return 1;
	}
	if (activate_lease6(pool, &iaaddr, &attempts, 
			    &ds, 11) != ISC_R_SUCCESS) {
		printf("ERROR: activate_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
		return 1;
	}
	if (activate_lease6(pool, &iaaddr, &attempts, 
			    &ds, 11) != ISC_R_NORESOURCES) {
		printf("ERROR: activate_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
		return 1;
	}

	/* 
 	 * Test 9: functions across all pools
	 */
	pool = NULL;
	if (ipv6_pool_allocate(&pool, &addr, 64, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
		return 1;
	}
	if (add_ipv6_pool(pool) != ISC_R_SUCCESS) {
		printf("ERROR: add_ipv6_pool() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
		return 1;
	}
	pool = NULL;
	if (find_ipv6_pool(&pool, &addr) != ISC_R_SUCCESS) {
		printf("ERROR: find_ipv6_pool() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
		return 1;
	}
	inet_pton(AF_INET6, "1:2:3:4:ffff:ffff:ffff:ffff", &addr);
	pool = NULL;
	if (find_ipv6_pool(&pool, &addr) != ISC_R_SUCCESS) {
		printf("ERROR: find_ipv6_pool() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
		return 1;
	}
	inet_pton(AF_INET6, "1:2:3:5::", &addr);
	pool = NULL;
	if (find_ipv6_pool(&pool, &addr) != ISC_R_NOTFOUND) {
		printf("ERROR: find_ipv6_pool() %s:%d\n", MDL);
		return 1;
	}
	inet_pton(AF_INET6, "1:2:3:3:ffff:ffff:ffff:ffff", &addr);
	pool = NULL;
	if (find_ipv6_pool(&pool, &addr) != ISC_R_NOTFOUND) {
		printf("ERROR: find_ipv6_pool() %s:%d\n", MDL);
		return 1;
	}

/*	iaid = 666;
	ia_na = NULL;
	if (ia_na_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_allocate() %s:%d\n", MDL);
		return 1;
	}*/

	printf("SUCCESS: all tests passed (ignore any warning messages)\n");
	return 0;
}
#endif
