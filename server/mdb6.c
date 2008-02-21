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

ia_na_hash_t *ia_na_active;
ia_na_hash_t *ia_ta_active;

HASH_FUNCTIONS(ia_pd, unsigned char *, struct ia_pd, ia_pd_hash_t,
	       ia_pd_reference, ia_pd_dereference, do_string_hash);

ia_pd_hash_t *ia_pd_active;

HASH_FUNCTIONS(iaaddr, struct in6_addr *, struct iaaddr, iaaddr_hash_t,
	       iaaddr_reference, iaaddr_dereference, do_string_hash);

HASH_FUNCTIONS(iaprefix, struct in6_addr *, struct iaprefix, iaprefix_hash_t,
	       iaprefix_reference, iaprefix_dereference, do_string_hash);

struct ipv6_pool **pools;
int num_pools;

struct ipv6_ppool **ppools;
int num_ppools;

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
 * Create a new IAPREFIX structure.
 *
 * - iapref must be a pointer to a (struct iaprefix *) pointer previously
 *   initialized to NULL
 */
isc_result_t
iaprefix_allocate(struct iaprefix **iapref, const char *file, int line) {
	struct iaprefix *tmp;

	if (iapref == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*iapref != NULL) {
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

	*iapref = tmp;
	return ISC_R_SUCCESS;
}

/*
 * Reference an IAPREFIX structure.
 *
 * - iapref must be a pointer to a (struct iaprefix *) pointer previously
 *   initialized to NULL
 */
isc_result_t
iaprefix_reference(struct iaprefix **iapref, struct iaprefix *src,
		 const char *file, int line) {
	if (iapref == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*iapref != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}
	if (src == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	*iapref = src;
	src->refcnt++;
	return ISC_R_SUCCESS;
}


/*
 * Dereference an IAPREFIX structure.
 *
 * If it is the last reference, then the memory for the 
 * structure is freed.
 */
isc_result_t
iaprefix_dereference(struct iaprefix **iapref, const char *file, int line) {
	struct iaprefix *tmp;

	if ((iapref == NULL) || (*iapref == NULL)) {
		log_error("%s(%d): NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = *iapref;
	*iapref = NULL;

	tmp->refcnt--;
	if (tmp->refcnt < 0) {
		log_error("%s(%d): negative refcnt", file, line);
		tmp->refcnt = 0;
	}
	if (tmp->refcnt == 0) {
		if (tmp->ia_pd != NULL) {
			ia_pd_dereference(&(tmp->ia_pd), file, line);
		}
		if (tmp->ipv6_ppool != NULL) {
			ipv6_ppool_dereference(&(tmp->ipv6_ppool), file, line);
		}
		if (tmp->scope != NULL) {
			binding_scope_dereference(&tmp->scope, file, line);
		}
		dfree(tmp, file, line);
	}

	return ISC_R_SUCCESS;
}

/* 
 * Make the key that we use for IA.
 */
isc_result_t
ia_make_key(struct data_string *key, u_int32_t iaid,
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
 * Create a new IA structure.
 *
 * - ia must be a pointer to a (struct ia_na *) pointer previously
 *   initialized to NULL
 * - iaid and duid are values from the client
 *
 * XXXsk: we don't concern ourself with the byte order of the IAID, 
 *        which might be a problem if we transfer this structure 
 *        between machines of different byte order
 */
isc_result_t
ia_na_allocate(struct ia_na **ia, u_int32_t iaid, 
	       const char *duid, unsigned int duid_len,
	       const char *file, int line) {
	struct ia_na *tmp;

	if (ia == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*ia != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = dmalloc(sizeof(*tmp), file, line);
	if (tmp == NULL) {
		return ISC_R_NOMEMORY;
	}

	if (ia_make_key(&tmp->iaid_duid, iaid, 
			duid, duid_len, file, line) != ISC_R_SUCCESS) {
		dfree(tmp, file, line);
		return ISC_R_NOMEMORY;
	}

	tmp->refcnt = 1;

	*ia = tmp;
	return ISC_R_SUCCESS;
}

/*
 * Reference an IA structure.
 *
 * - ia must be a pointer to a (struct ia_na *) pointer previously
 *   initialized to NULL
 */
isc_result_t
ia_na_reference(struct ia_na **ia, struct ia_na *src,
		const char *file, int line) {
	if (ia == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*ia != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}
	if (src == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	*ia = src;
	src->refcnt++;
	return ISC_R_SUCCESS;
}

/*
 * Dereference an IA structure.
 *
 * If it is the last reference, then the memory for the 
 * structure is freed.
 */
isc_result_t
ia_na_dereference(struct ia_na **ia, const char *file, int line) {
	struct ia_na *tmp;
	int i;

	if ((ia == NULL) || (*ia == NULL)) {
		log_error("%s(%d): NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = *ia;
	*ia = NULL;

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
 * Add an IAADDR entry to an IA structure.
 */
isc_result_t
ia_na_add_iaaddr(struct ia_na *ia, struct iaaddr *iaaddr, 
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
	if (ia->max_iaaddr <= ia->num_iaaddr) {
		max = ia->max_iaaddr + 4;
		new = dmalloc(max * sizeof(struct iaaddr *), file, line);
		if (new == NULL) {
			return ISC_R_NOMEMORY;
		}
		memcpy(new, ia->iaaddr, 
		       ia->num_iaaddr * sizeof(struct iaaddr *));
		ia->iaaddr = new;
		ia->max_iaaddr = max;
	}

	iaaddr_reference(&(ia->iaaddr[ia->num_iaaddr]), iaaddr, 
			 file, line);
	ia->num_iaaddr++;

	return ISC_R_SUCCESS;
}

/*
 * Remove an IAADDR entry to an IA structure.
 *
 * Note: if an IAADDR appears more than once, then only ONE will be removed.
 */
void
ia_na_remove_iaaddr(struct ia_na *ia, struct iaaddr *iaaddr,
		    const char *file, int line) {
	int i, j;

	for (i=0; i<ia->num_iaaddr; i++) {
		if (ia->iaaddr[i] == iaaddr) {
			/* remove this IAADDR */
			iaaddr_dereference(&(ia->iaaddr[i]), file, line);
			/* move remaining IAADDR pointers down one */
			for (j=i+1; j < ia->num_iaaddr; j++) {
				ia->iaaddr[j-1] = ia->iaaddr[j];
			}
			/* decrease our total count */
			/* remove the back-reference in the IAADDR itself */
			ia_na_dereference(&iaaddr->ia_na, file, line);
			ia->num_iaaddr--;
			return;
		}
	}
	log_error("%s(%d): IAADDR not in IA", file, line);
}

/*
 * Remove all addresses from an IA.
 */
void
ia_na_remove_all_iaaddr(struct ia_na *ia, const char *file, int line) {
	int i;

	for (i=0; i<ia->num_iaaddr; i++) {
		ia_na_dereference(&(ia->iaaddr[i]->ia_na), file, line);
		iaaddr_dereference(&(ia->iaaddr[i]), file, line);
	}
	ia->num_iaaddr = 0;
}

/*
 * Compare two IA.
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
	 * Check the type is the same.
	 */
	if (a->ia_type != b->ia_type) {
		return ISC_FALSE;
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
				   sizeof(struct in6_addr)) == 0) {
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
 * Create a new IA_PD structure.
 *
 * - ia_pd must be a pointer to a (struct ia_pd *) pointer previously
 *   initialized to NULL
 * - iaid and duid are values from the client
 *
 * XXXsk: we don't concern ourself with the byte order of the IAID, 
 *        which might be a problem if we transfer this structure 
 *        between machines of different byte order
 */
isc_result_t
ia_pd_allocate(struct ia_pd **ia_pd, u_int32_t iaid, 
	       const char *duid, unsigned int duid_len,
	       const char *file, int line) {
	struct ia_pd *tmp;

	if (ia_pd == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*ia_pd != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = dmalloc(sizeof(*tmp), file, line);
	if (tmp == NULL) {
		return ISC_R_NOMEMORY;
	}

	if (ia_make_key(&tmp->iaid_duid, iaid, 
			duid, duid_len, file, line) != ISC_R_SUCCESS) {
		dfree(tmp, file, line);
		return ISC_R_NOMEMORY;
	}

	tmp->refcnt = 1;

	*ia_pd = tmp;
	return ISC_R_SUCCESS;
}

/*
 * Reference an IA_PD structure.
 *
 * - ia_pd must be a pointer to a (struct ia_pd *) pointer previously
 *   initialized to NULL
 */
isc_result_t
ia_pd_reference(struct ia_pd **ia_pd, struct ia_pd *src,
		const char *file, int line) {
	if (ia_pd == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*ia_pd != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}
	if (src == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	*ia_pd = src;
	src->refcnt++;
	return ISC_R_SUCCESS;
}

/*
 * Dereference an IA_PD structure.
 *
 * If it is the last reference, then the memory for the 
 * structure is freed.
 */
isc_result_t
ia_pd_dereference(struct ia_pd **ia_pd, const char *file, int line) {
	struct ia_pd *tmp;
	int i;

	if ((ia_pd == NULL) || (*ia_pd == NULL)) {
		log_error("%s(%d): NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = *ia_pd;
	*ia_pd = NULL;

	tmp->refcnt--;
	if (tmp->refcnt < 0) {
		log_error("%s(%d): negative refcnt", file, line);
		tmp->refcnt = 0;
	}
	if (tmp->refcnt == 0) {
		if (tmp->iaprefix != NULL) {
			for (i=0; i<tmp->num_iaprefix; i++) {
				iaprefix_dereference(&(tmp->iaprefix[i]), 
						     file, line);
			}
			dfree(tmp->iaprefix, file, line);
		}
		data_string_forget(&(tmp->iaid_duid), file, line);
		dfree(tmp, file, line);
	}
	return ISC_R_SUCCESS;
}


/*
 * Add an IAPREFIX entry to an IA_PD structure.
 */
isc_result_t
ia_pd_add_iaprefix(struct ia_pd *ia_pd, struct iaprefix *iapref, 
		   const char *file, int line) {
	int max;
	struct iaprefix **new;

	/* 
	 * Grow our array if we need to.
	 * 
	 * Note: we pick 4 as the increment, as that seems a reasonable
	 *       guess as to how many prefixes we might expect on an 
	 *       interface.
	 */
	if (ia_pd->max_iaprefix <= ia_pd->num_iaprefix) {
		max = ia_pd->max_iaprefix + 4;
		new = dmalloc(max * sizeof(struct iaprefix *), file, line);
		if (new == NULL) {
			return ISC_R_NOMEMORY;
		}
		memcpy(new, ia_pd->iaprefix, 
		       ia_pd->num_iaprefix * sizeof(struct iaprefix *));
		ia_pd->iaprefix = new;
		ia_pd->max_iaprefix = max;
	}

	iaprefix_reference(&(ia_pd->iaprefix[ia_pd->num_iaprefix]), iapref, 
			   file, line);
	ia_pd->num_iaprefix++;

	return ISC_R_SUCCESS;
}

/*
 * Remove an IAPREFIX entry to an IA_PD structure.
 *
 * Note: if an IAPREFIX appears more than once, then only ONE will be removed.
 */
void
ia_pd_remove_iaprefix(struct ia_pd *ia_pd, struct iaprefix *iapref,
		      const char *file, int line) {
	int i, j;

	for (i=0; i<ia_pd->num_iaprefix; i++) {
		if (ia_pd->iaprefix[i] == iapref) {
			/* remove this IAPREFIX */
			iaprefix_dereference(&(ia_pd->iaprefix[i]),
					     file, line);
			/* move remaining IAPREFIX pointers down one */
			for (j=i+1; j < ia_pd->num_iaprefix; j++) {
				ia_pd->iaprefix[j-1] = ia_pd->iaprefix[j];
			}
			/* decrease our total count */
			/* remove the back-reference in the IAPREFIX itself */
			ia_pd_dereference(&iapref->ia_pd, file, line);
			ia_pd->num_iaprefix--;
			return;
		}
	}
	log_error("%s(%d): IAPREFIX not in IA_PD", file, line);
}

/*
 * Remove all prefixes from an IA_PD.
 */
void
ia_pd_remove_all_iaprefix(struct ia_pd *ia_pd, const char *file, int line) {
	int i;

	for (i=0; i<ia_pd->num_iaprefix; i++) {
		ia_pd_dereference(&(ia_pd->iaprefix[i]->ia_pd), file, line);
		iaprefix_dereference(&(ia_pd->iaprefix[i]), file, line);
	}
	ia_pd->num_iaprefix = 0;
}

/*
 * Compare two IA_PD.
 */
isc_boolean_t
ia_pd_equal(const struct ia_pd *a, const struct ia_pd *b) 
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
	 * Make sure we have the same number of prefixes in each.
	 */
	if (a->num_iaprefix != b->num_iaprefix) {
		return ISC_FALSE;
	}

	/*
	 * Check that each prefix is present in both.
	 */
	for (i=0; i<a->num_iaprefix; i++) {
		found = ISC_FALSE;
		for (j=0; j<a->num_iaprefix; j++) {
			if (a->iaprefix[i]->plen != b->iaprefix[i]->plen)
				continue;
			if (memcmp(&(a->iaprefix[i]->pref),
			           &(b->iaprefix[j]->pref), 
				   sizeof(struct in6_addr)) == 0) {
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
 * Note: this relies on the unique layout for leases!
 */
static isc_boolean_t 
lease_older(void *a, void *b) {
	struct iaaddr *ia = (struct iaaddr *)a;
	struct iaaddr *ib = (struct iaaddr *)b;

	if (ia->hard_lifetime_end_time == ib->hard_lifetime_end_time) {
		return difftime(ia->soft_lifetime_end_time,
				ib->soft_lifetime_end_time) < 0;
	} else {
		return difftime(ia->hard_lifetime_end_time, 
				ib->hard_lifetime_end_time) < 0;
	}
}

/*
 * Helper function for lease address heaps.
 * Callback when an address's position in the heap changes.
 */
static void
lease_address_index_changed(void *iaaddr, unsigned int new_heap_index) {
	((struct iaaddr *)iaaddr)-> heap_index = new_heap_index;
}

/*
 * Helper function for lease prefix heaps.
 * Callback when a prefix's position in the heap changes.
 */
static void
lease_prefix_index_changed(void *iapref, unsigned int new_heap_index) {
	((struct iaprefix *)iapref)-> heap_index = new_heap_index;
}


/*
 * Create a new IPv6 lease (address) pool structure.
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
 * Create a new IPv6 lease (prefix) pool structure.
 *
 * - ppool must be a pointer to a (struct ipv6_ppool *) pointer previously
 *   initialized to NULL
 */
isc_result_t
ipv6_ppool_allocate(struct ipv6_ppool **ppool,
		    const struct in6_addr *start_pref,
		    u_int8_t pool_plen, u_int8_t alloc_plen,
		    const char *file, int line) {
	struct ipv6_ppool *tmp;

	if (ppool == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*ppool != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = dmalloc(sizeof(*tmp), file, line);
	if (tmp == NULL) {
		return ISC_R_NOMEMORY;
	}

	tmp->refcnt = 1;
	tmp->start_pref = *start_pref;
	tmp->pool_plen = pool_plen;
	tmp->alloc_plen = alloc_plen;
	if (!iaprefix_new_hash(&tmp->prefs, DEFAULT_HASH_SIZE, file, line)) {
		dfree(tmp, file, line);
		return ISC_R_NOMEMORY;
	}
	if (isc_heap_create(lease_older, lease_prefix_index_changed,
			    0, &(tmp->active_timeouts)) != ISC_R_SUCCESS) {
		iaprefix_free_hash_table(&(tmp->prefs), file, line);
		dfree(tmp, file, line);
		return ISC_R_NOMEMORY;
	}
	if (isc_heap_create(lease_older, lease_prefix_index_changed,
			    0, &(tmp->inactive_timeouts)) != ISC_R_SUCCESS) {
		isc_heap_destroy(&(tmp->active_timeouts));
		iaprefix_free_hash_table(&(tmp->prefs), file, line);
		dfree(tmp, file, line);
		return ISC_R_NOMEMORY;
	}

	*ppool = tmp;
	return ISC_R_SUCCESS;
}

/*
 * Reference an IPv6 prefix pool structure.
 *
 * - ppool must be a pointer to a (struct ppool *) pointer previously
 *   initialized to NULL
 */
isc_result_t
ipv6_ppool_reference(struct ipv6_ppool **ppool, struct ipv6_ppool *src,
		     const char *file, int line) {
	if (ppool == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	if (*ppool != NULL) {
		log_error("%s(%d): non-NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}
	if (src == NULL) {
		log_error("%s(%d): NULL pointer reference", file, line);
		return ISC_R_INVALIDARG;
	}
	*ppool = src;
	src->refcnt++;
	return ISC_R_SUCCESS;
}

/* 
 * Note: Each IAPREFIX in a pool is referenced by the pool. This is needed
 * to prevent the IAPREFIX from being garbage collected out from under the
 * pool.
 *
 * The references are made from the hash and from the heap. The following
 * helper functions dereference these when a pool is destroyed.
 */

/*
 * Helper function for prefix pool cleanup.
 * Dereference each of the hash entries in a pool.
 */
static isc_result_t 
dereference_phash_entry(const void *name, unsigned len, void *value) {
	struct iaprefix *iapref = (struct iaprefix *)value;

	iaprefix_dereference(&iapref, MDL);
	return ISC_R_SUCCESS;
}

/*
 * Helper function for prefix pool cleanup.
 * Dereference each of the heap entries in a pool.
 */
static void
dereference_pheap_entry(void *value, void *dummy) {
	struct iaprefix *iapref = (struct iaprefix *)value;

	iaprefix_dereference(&iapref, MDL);
}


/*
 * Dereference an IPv6 prefix pool structure.
 *
 * If it is the last reference, then the memory for the 
 * structure is freed.
 */
isc_result_t
ipv6_ppool_dereference(struct ipv6_ppool **ppool, const char *file, int line) {
	struct ipv6_ppool *tmp;

	if ((ppool == NULL) || (*ppool == NULL)) {
		log_error("%s(%d): NULL pointer", file, line);
		return ISC_R_INVALIDARG;
	}

	tmp = *ppool;
	*ppool = NULL;

	tmp->refcnt--;
	if (tmp->refcnt < 0) {
		log_error("%s(%d): negative refcnt", file, line);
		tmp->refcnt = 0;
	}
	if (tmp->refcnt == 0) {
		iaprefix_hash_foreach(tmp->prefs, dereference_phash_entry);
		iaprefix_free_hash_table(&(tmp->prefs), file, line);
		isc_heap_foreach(tmp->active_timeouts, 
				 dereference_pheap_entry, NULL);
		isc_heap_destroy(&(tmp->active_timeouts));
		isc_heap_foreach(tmp->inactive_timeouts, 
				 dereference_pheap_entry, NULL);
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
build_address6(struct in6_addr *addr, 
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
	/* set the 'u' bit to zero for /64s. */
	if (net_bits == 64)
		str[8] &= ~0x02;
}

/* 
 * Create a temporary address by a variant of RFC 4941 algo.
 */
static void
build_temporary6(struct in6_addr *addr, 
		 const struct in6_addr *net_start_addr, 
		 const struct data_string *input) {
	static u_int8_t history[8];
	static u_int32_t counter = 0;
	MD5_CTX ctx;
	unsigned char md[16];
	extern int dst_s_random(u_int8_t *, unsigned);

	/*
	 * First time/time to reseed.
	 * Please use a good pseudo-random generator here!
	 */
	if (counter == 0) {
		if (dst_s_random(history, 8) != 8)
			log_fatal("Random failed.");
	}

	/* 
	 * Use MD5 as recommended by RFC 4941.
	 */
	MD5_Init(&ctx);
	MD5_Update(&ctx, history, 8UL);
	MD5_Update(&ctx, input->data, input->len);
	MD5_Final(md, &ctx);

	/*
	 * Build the address.
	 */
	memcpy(&addr->s6_addr[0], &net_start_addr->s6_addr[0], 8);
	memcpy(&addr->s6_addr[8], md, 8);
	addr->s6_addr[8] &= ~0x02;

	/*
	 * Save history for the next call.
	 */
	memcpy(history, md + 8, 8);
	counter++;
}

/* Reserved Subnet Router Anycast ::0:0:0:0. */
static struct in6_addr rtany;
/* Reserved Subnet Anycasts ::fdff:ffff:ffff:ff80-::fdff:ffff:ffff:ffff. */
static struct in6_addr resany;

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
create_lease6(struct ipv6_pool *pool, struct iaaddr **addr, 
	      unsigned int *attempts,
	      const struct data_string *uid, time_t soft_lifetime_end_time) {
	struct data_string ds;
	struct in6_addr tmp;
	struct iaaddr *test_iaaddr;
	struct data_string new_ds;
	struct iaaddr *iaaddr;
	isc_result_t result;
	isc_boolean_t reserved_iid;
	static isc_boolean_t init_resiid = ISC_FALSE;

	/*
	 * Fill the reserved IIDs.
	 */
	if (!init_resiid) {
		memset(&rtany, 0, 16);
		memset(&resany, 0, 8);
		resany.s6_addr[8] = 0xfd;
		memset(&resany.s6_addr[9], 0xff, 6);
		init_resiid = ISC_TRUE;
	}

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
		 * Build an address or a temporary address.
		 */
		if ((pool->bits & POOL_IS_FOR_TEMP) == 0) {
			build_address6(&tmp, &pool->start_addr,
				       pool->bits, &ds);
		} else {
			build_temporary6(&tmp, &pool->start_addr, &ds);
		}

		/*
		 * Avoid reserved interface IDs.
		 * (cf. draft-krishnan-ipv6-reserved-iids-02.txt)
		 */
		reserved_iid = ISC_FALSE;
		if (memcmp(&tmp.s6_addr[8], &rtany, 8) == 0) {
			reserved_iid = ISC_TRUE;
		}
		if (!reserved_iid &&
		    (memcmp(&tmp.s6_addr[8], &resany, 7) == 0) &&
		    ((tmp.s6_addr[15] & 0x80) == 0x80)) {
			reserved_iid = ISC_TRUE;
		}

		/*
		 * If this address is not in use, we're happy with it
		 */
		test_iaaddr = NULL;
		if (!reserved_iid &&
		    (iaaddr_hash_lookup(&test_iaaddr, pool->addrs,
					&tmp, sizeof(tmp), MDL) == 0)) {
			break;
		}
		if (test_iaaddr != NULL)
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
	 * Add the lease to the pool (note state is free, not active?!).
	 */
	result = add_lease6(pool, iaaddr, soft_lifetime_end_time);
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
		tmp_iaaddr->hard_lifetime_end_time = valid_lifetime_end_time;
		iaaddr_hash_add(pool->addrs, &tmp_iaaddr->addr, 
				sizeof(tmp_iaaddr->addr), iaaddr, MDL);
		insert_result = isc_heap_insert(pool->active_timeouts,
						tmp_iaaddr);
		if (insert_result == ISC_R_SUCCESS)
			pool->num_active++;
	} else {
		tmp_iaaddr->soft_lifetime_end_time = valid_lifetime_end_time;
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
 * To do this, first set the new hard_lifetime_end_time for the address, 
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
		if (now > tmp->hard_lifetime_end_time) {
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
	addr->hard_lifetime_end_time = MAX_TIME;
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
 * Create a prefix by hashing the input, and using that for
 * the part subject to allocation.
 */
static void
build_prefix6(struct in6_addr *pref, 
	      const struct in6_addr *net_start_pref,
	      int pool_bits, int pref_bits,
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
	MD5_Final((unsigned char *)pref, &ctx);

	/*
	 * Copy the network bits over.
	 */
	str = (char *)pref;
	net_str = (const char *)net_start_pref;
	net_bytes = pool_bits / 8;
	for (i=0; i<net_bytes; i++) {
		str[i] = net_str[i];
	}
	i = net_bytes;
	switch (pool_bits % 8) {
		case 1: str[i] = (str[i] & 0x7F) | (net_str[i] & 0x80); break;
		case 2: str[i] = (str[i] & 0x3F) | (net_str[i] & 0xC0); break;
		case 3: str[i] = (str[i] & 0x1F) | (net_str[i] & 0xE0); break;
		case 4: str[i] = (str[i] & 0x0F) | (net_str[i] & 0xF0); break;
		case 5: str[i] = (str[i] & 0x07) | (net_str[i] & 0xF8); break;
		case 6: str[i] = (str[i] & 0x03) | (net_str[i] & 0xFC); break;
		case 7: str[i] = (str[i] & 0x01) | (net_str[i] & 0xFE); break;
	}
	/*
	 * Zero the remaining bits.
	 */
	net_bytes = pref_bits / 8;
	for (i=net_bytes+1; i<16; i++) {
		str[i] = 0;
	}
	i = net_bytes;
	switch (pref_bits % 8) {
		case 0: str[i] &= 0; break;
		case 1: str[i] &= 0x80; break;
		case 2: str[i] &= 0xC0; break;
		case 3: str[i] &= 0xE0; break;
		case 4: str[i] &= 0xF0; break;
		case 5: str[i] &= 0xF8; break;
		case 6: str[i] &= 0xFC; break;
		case 7: str[i] &= 0xFE; break;
	}
}

/*
 * Create a lease for the given prefix and client duid.
 *
 * - ppool must be a pointer to a (struct ppool *) pointer previously
 *   initialized to NULL
 *
 * Right now we simply hash the DUID, and if we get a collision, we hash 
 * again until we find a free prefix. We try this a fixed number of times,
 * to avoid getting stuck in a loop (this is important on small pools
 * where we can run out of space).
 *
 * We return the number of attempts that it took to find an available
 * prefix. This tells callers when a pool is are filling up, as
 * well as an indication of how full the pool is; statistically the 
 * more full a pool is the more attempts must be made before finding
 * a free prefix. Realistically this will only happen in very full
 * pools.
 *
 * We probably want different algorithms depending on the network size, in
 * the long term.
 */
isc_result_t
create_prefix6(struct ipv6_ppool *ppool, struct iaprefix **pref, 
	       unsigned int *attempts,
	       const struct data_string *uid,
	       time_t soft_lifetime_end_time) {
	struct data_string ds;
	struct in6_addr tmp;
	struct iaprefix *test_iapref;
	struct data_string new_ds;
	struct iaprefix *iapref;
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
		if (++(*attempts) > 10) {
			data_string_forget(&ds, MDL);
			return ISC_R_NORESOURCES;
		}

		/* 
		 * Build a prefix
		 */
		build_prefix6(&tmp, &ppool->start_pref,
			      (int)ppool->pool_plen, (int)ppool->alloc_plen,
			      &ds);

		/*
		 * If this prefix is not in use, we're happy with it
		 */
		test_iapref = NULL;
		if (iaprefix_hash_lookup(&test_iapref, ppool->prefs,
					 &tmp, sizeof(tmp), MDL) == 0) {
			break;
		}
		iaprefix_dereference(&test_iapref, MDL);

		/* 
		 * Otherwise, we create a new input, adding the prefix
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
	 * We're happy with the prefix, create an IAPREFIX
	 * to hold it.
	 */
	iapref = NULL;
	result = iaprefix_allocate(&iapref, MDL);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	iapref->plen = ppool->alloc_plen;
	memcpy(&iapref->pref, &tmp, sizeof(iapref->pref));

	/*
	 * Add the prefix to the pool (note state is free, not active?!).
	 */
	result = add_prefix6(ppool, iapref, soft_lifetime_end_time);
	if (result == ISC_R_SUCCESS) {
		iaprefix_reference(pref, iapref, MDL);
	}
	iaprefix_dereference(&iapref, MDL);
	return result;
}

/*
 * Put a prefix in the pool directly. This is intended to be used when
 * loading leases from the file.
 */
isc_result_t
add_prefix6(struct ipv6_ppool *ppool, struct iaprefix *iapref,
	    time_t valid_lifetime_end_time) {
	isc_result_t insert_result;
	struct iaprefix *test_iapref;
	struct iaprefix *tmp_iapref;

	/* If a state was not assigned by the caller, assume active. */
	if (iapref->state == 0)
		iapref->state = FTS_ACTIVE;

	ipv6_ppool_reference(&iapref->ipv6_ppool, ppool, MDL);

	/*
	 * If this IAPREFIX is already in our structures, remove the 
	 * old one.
	 */
	test_iapref = NULL;
	if (iaprefix_hash_lookup(&test_iapref, ppool->prefs,
				 &iapref->pref, sizeof(iapref->pref), MDL)) {
		/* XXX: we should probably ask the iaprefix what heap it is on
		 * (as a consistency check).
		 * XXX: we should probably have one function to "put this
		 * prefix on its heap" rather than doing these if's
		 * everywhere.  If you add more states to this list, don't.
		 */
		if ((test_iapref->state == FTS_ACTIVE) ||
		    (test_iapref->state == FTS_ABANDONED)) {
			isc_heap_delete(ppool->active_timeouts,
					test_iapref->heap_index);
			ppool->num_active--;
		} else {
			isc_heap_delete(ppool->inactive_timeouts,
					test_iapref->heap_index);
			ppool->num_inactive--;
		}

		iaprefix_hash_delete(ppool->prefs, &test_iapref->pref, 
				     sizeof(test_iapref->pref), MDL);

		/*
		 * We're going to do a bit of evil trickery here.
		 *
		 * We need to dereference the entry once to remove our
		 * current reference (in test_iapref), and then one
		 * more time to remove the reference left when the
		 * prefix was added to the pool before.
		 */
		tmp_iapref = test_iapref;
		iaprefix_dereference(&test_iapref, MDL);
		iaprefix_dereference(&tmp_iapref, MDL);
	}

	/* 
	 * Add IAPREFIX to our structures.
	 */
	tmp_iapref = NULL;
	iaprefix_reference(&tmp_iapref, iapref, MDL);
	if ((tmp_iapref->state == FTS_ACTIVE) ||
	    (tmp_iapref->state == FTS_ABANDONED)) {
		tmp_iapref->hard_lifetime_end_time = valid_lifetime_end_time;
		iaprefix_hash_add(ppool->prefs, &tmp_iapref->pref, 
				  sizeof(tmp_iapref->pref), iapref, MDL);
		insert_result = isc_heap_insert(ppool->active_timeouts,
						tmp_iapref);
		if (insert_result == ISC_R_SUCCESS)
			ppool->num_active++;
	} else {
		tmp_iapref->soft_lifetime_end_time = valid_lifetime_end_time;
		insert_result = isc_heap_insert(ppool->inactive_timeouts,
						tmp_iapref);
		if (insert_result == ISC_R_SUCCESS)
			ppool->num_inactive++;
	}
	if (insert_result != ISC_R_SUCCESS) {
		iaprefix_hash_delete(ppool->prefs, &iapref->pref, 
				     sizeof(iapref->pref), MDL);
		iaprefix_dereference(&tmp_iapref, MDL);
		return insert_result;
	}

	/* 
	 * Note: we intentionally leave tmp_iapref referenced; there
	 * is a reference in the heap/hash, after all.
	 */

	return ISC_R_SUCCESS;
}

/*
 * Determine if a prefix is present in a pool or not.
 */
isc_boolean_t
prefix6_exists(const struct ipv6_ppool *ppool,
	       const struct in6_addr *pref, u_int8_t plen) {
	struct iaprefix *test_iapref;

	if (plen != ppool->alloc_plen)
		return ISC_FALSE;

	test_iapref = NULL;
	if (iaprefix_hash_lookup(&test_iapref, ppool->prefs, 
				 (void *)pref, sizeof(*pref), MDL)) {
		iaprefix_dereference(&test_iapref, MDL);
		return ISC_TRUE;
	} else {
		return ISC_FALSE;
	}
}

/*
 * Put the prefix on our active pool.
 */
static isc_result_t
move_prefix_to_active(struct ipv6_ppool *ppool, struct iaprefix *pref) {
	isc_result_t insert_result;
	int old_heap_index;

	old_heap_index = pref->heap_index;
	insert_result = isc_heap_insert(ppool->active_timeouts, pref);
	if (insert_result == ISC_R_SUCCESS) {
       		iaprefix_hash_add(ppool->prefs, &pref->pref, 
				  sizeof(pref->pref), pref, MDL);
		isc_heap_delete(ppool->inactive_timeouts, old_heap_index);
		ppool->num_active++;
		ppool->num_inactive--;
		pref->state = FTS_ACTIVE;
	}
	return insert_result;
}

/*
 * Renew a prefix in the pool.
 *
 * To do this, first set the new hard_lifetime_end_time for the prefix, 
 * and then invoke renew_prefix() on the prefix.
 *
 * WARNING: lease times must only be extended, never reduced!!!
 */
isc_result_t
renew_prefix6(struct ipv6_ppool *ppool, struct iaprefix *pref) {
	/*
	 * If we're already active, then we can just move our expiration
	 * time down the heap. 
	 *
	 * Otherwise, we have to move from the inactive heap to the 
	 * active heap.
	 */
	if (pref->state == FTS_ACTIVE) {
		isc_heap_decreased(ppool->active_timeouts, pref->heap_index);
		return ISC_R_SUCCESS;
	} else {
		return move_prefix_to_active(ppool, pref);
	}
}

/*
 * Put the prefix on our inactive pool, with the specified state.
 */
static isc_result_t
move_prefix_to_inactive(struct ipv6_ppool *ppool, struct iaprefix *pref, 
			binding_state_t state) {
	isc_result_t insert_result;
	int old_heap_index;

	old_heap_index = pref->heap_index;
	insert_result = isc_heap_insert(ppool->inactive_timeouts, pref);
	if (insert_result == ISC_R_SUCCESS) {
		/* Process events upon expiration. */
		/* No DDNS for prefixes. */

		/* Binding scopes are no longer valid after expiry or
		 * release.
		 */
		if (pref->scope != NULL) {
			binding_scope_dereference(&pref->scope, MDL);
		}

		iaprefix_hash_delete(ppool->prefs, 
				     &pref->pref, sizeof(pref->pref), MDL);
		isc_heap_delete(ppool->active_timeouts, old_heap_index);
		pref->state = state;
		ppool->num_active--;
		ppool->num_inactive++;
	}
	return insert_result;
}

/*
 * Expire the oldest prefix if it's lifetime_end_time is 
 * older than the given time.
 *
 * - iapref must be a pointer to a (struct iaprefix *) pointer previously
 *   initialized to NULL
 *
 * On return iapref has a reference to the removed entry. It is left
 * pointing to NULL if the oldest prefix has not expired.
 */
isc_result_t
expire_prefix6(struct iaprefix **pref, struct ipv6_ppool *ppool, time_t now) {
	struct iaprefix *tmp;
	isc_result_t result;

	if (pref == NULL) {
		log_error("%s(%d): NULL pointer reference", MDL);
		return ISC_R_INVALIDARG;
	}
	if (*pref != NULL) {
		log_error("%s(%d): non-NULL pointer", MDL);
		return ISC_R_INVALIDARG;
	}

	if (ppool->num_active > 0) {
		tmp = (struct iaprefix *)
			isc_heap_element(ppool->active_timeouts, 1);
		if (now > tmp->hard_lifetime_end_time) {
			result = move_prefix_to_inactive(ppool, tmp,
							 FTS_EXPIRED);
			if (result == ISC_R_SUCCESS) {
				iaprefix_reference(pref, tmp, MDL);
			}
			return result;
		}
	}
	return ISC_R_SUCCESS;
}


/*
 * Put the returned prefix on our inactive pool.
 */
isc_result_t
release_prefix6(struct ipv6_ppool *ppool, struct iaprefix *pref) {
	if (pref->state == FTS_ACTIVE) {
		return move_prefix_to_inactive(ppool, pref, FTS_RELEASED);
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
 * Mark an IPv6 prefix as unavailable from a prefix pool.
 *
 * This is used for host entries.
 */
isc_result_t
mark_prefix_unavailable(struct ipv6_ppool *ppool,
			const struct in6_addr *pref) {
	struct iaprefix *dummy_iapref;
	isc_result_t result;

	dummy_iapref = NULL;
	result = iaprefix_allocate(&dummy_iapref, MDL);
	if (result == ISC_R_SUCCESS) {
		dummy_iapref->pref = *pref;
		iaprefix_hash_add(ppool->prefs, &dummy_iapref->pref,
				  sizeof(*pref), dummy_iapref, MDL);
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

/* 
 * Add a prefix pool.
 */
isc_result_t
add_ipv6_ppool(struct ipv6_ppool *ppool) {
	struct ipv6_ppool **new_ppools;

	new_ppools = dmalloc(sizeof(struct ipv6_ppool *) * (num_ppools + 1),
			     MDL);
	if (new_ppools == NULL) {
		return ISC_R_NOMEMORY;
	}

	if (num_ppools > 0) {
		memcpy(new_ppools, ppools, 
		       sizeof(struct ipv6_ppool *) * num_ppools);
		dfree(ppools, MDL);
	}
	ppools = new_ppools;

	ppools[num_ppools] = NULL;
	ipv6_ppool_reference(&ppools[num_ppools], ppool, MDL);
	num_ppools++;
	return ISC_R_SUCCESS;
}


static void
cleanup_old_expired(struct ipv6_pool *pool) {
	struct iaaddr *tmp;
	struct ia_na *ia;
	struct ia_na *ia_active;
	unsigned char *tmpd;
	time_t timeout;
	
	while (pool->num_inactive > 0) {
		tmp = (struct iaaddr *)isc_heap_element(pool->inactive_timeouts,
							1);
		if (tmp->hard_lifetime_end_time != 0) {
			timeout = tmp->hard_lifetime_end_time;
			timeout += EXPIRED_IPV6_CLEANUP_TIME;
		} else {
			timeout = tmp->soft_lifetime_end_time;
		}
		if (cur_time < timeout) {
			break;
		}

		isc_heap_delete(pool->inactive_timeouts, tmp->heap_index);
		pool->num_inactive--;

		if (tmp->ia_na != NULL) {
			/*
			 * Check to see if this IA is in the active list,
			 * but has no remaining addresses. If so, remove it
			 * from the active list.
			 */
			ia = NULL;
			ia_na_reference(&ia, tmp->ia_na, MDL);
			ia_na_remove_iaaddr(ia, tmp, MDL);
			ia_active = NULL;
			tmpd = (unsigned char *)ia->iaid_duid.data;
			if ((ia->ia_type == D6O_IA_NA) &&
			    (ia->num_iaaddr <= 0) &&
			    (ia_na_hash_lookup(&ia_active, ia_na_active, tmpd,
			    		       ia->iaid_duid.len,
					       MDL) == 0) &&
			    (ia_active == ia)) {
				ia_na_hash_delete(ia_na_active, tmpd, 
					  	  ia->iaid_duid.len, MDL);
			}
			if ((ia->ia_type == D6O_IA_TA) &&
			    (ia->num_iaaddr <= 0) &&
			    (ia_na_hash_lookup(&ia_active, ia_ta_active, tmpd,
			    		       ia->iaid_duid.len,
					       MDL) == 0) &&
			    (ia_active == ia)) {
				ia_na_hash_delete(ia_ta_active, tmpd, 
					  	  ia->iaid_duid.len, MDL);
			}
			ia_na_dereference(&ia, MDL);
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

		write_ia(addr->ia_na);

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
	struct timeval tv;

	next_timeout = MAX_TIME;

	if (pool->num_active > 0) {
		tmp = (struct iaaddr *)isc_heap_element(pool->active_timeouts, 
							1);
		if (tmp->hard_lifetime_end_time < next_timeout) {
			next_timeout = tmp->hard_lifetime_end_time + 1;
		}
	}

	if (pool->num_inactive > 0) {
		tmp = (struct iaaddr *)isc_heap_element(pool->inactive_timeouts,
							1);
		if (tmp->hard_lifetime_end_time != 0) {
			timeout = tmp->hard_lifetime_end_time;
			timeout += EXPIRED_IPV6_CLEANUP_TIME;
		} else {
			timeout = tmp->soft_lifetime_end_time + 1;
		}
		if (timeout < next_timeout) {
			next_timeout = timeout;
		}
	}

	if (next_timeout < MAX_TIME) {
		tv.tv_sec = next_timeout;
		tv.tv_usec = 0;
		add_timeout(&tv, lease_timeout_support, pool,
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

static void
cleanup_old_pexpired(struct ipv6_ppool *ppool) {
	struct iaprefix *tmp;
	struct ia_pd *ia_pd;
	struct ia_pd *ia_active;
	unsigned char *tmpd;
	time_t timeout;
	
	while (ppool->num_inactive > 0) {
		tmp = (struct iaprefix *)
			isc_heap_element(ppool->inactive_timeouts, 1);
		if (tmp->hard_lifetime_end_time != 0) {
			timeout = tmp->hard_lifetime_end_time;
			timeout += EXPIRED_IPV6_CLEANUP_TIME;
		} else {
			timeout = tmp->soft_lifetime_end_time;
		}
		if (cur_time < timeout) {
			break;
		}

		isc_heap_delete(ppool->inactive_timeouts, tmp->heap_index);
		ppool->num_inactive--;

		if (tmp->ia_pd != NULL) {
			/*
			 * Check to see if this IA_PD is in the active list,
			 * but has no remaining prefixes. If so, remove it
			 * from the active list.
			 */
			ia_pd = NULL;
			ia_pd_reference(&ia_pd, tmp->ia_pd, MDL);
			ia_pd_remove_iaprefix(ia_pd, tmp, MDL);
			ia_active = NULL;
			tmpd = (unsigned char *)ia_pd->iaid_duid.data;
			if ((ia_pd->num_iaprefix <= 0) &&
			    (ia_pd_hash_lookup(&ia_active, ia_pd_active,
					       tmpd, ia_pd->iaid_duid.len,
					       MDL) == 0) &&
			    (ia_active == ia_pd)) {
				ia_pd_hash_delete(ia_pd_active, tmpd, 
					  	  ia_pd->iaid_duid.len, MDL);
			}
			ia_pd_dereference(&ia_pd, MDL);
		}
		iaprefix_dereference(&tmp, MDL);
	}
}

static void
prefix_timeout_support(void *vppool) {
	struct ipv6_ppool *ppool;
	struct iaprefix *pref;
	
	ppool = (struct ipv6_ppool *)vppool;
	for (;;) {
		/*
		 * Get the next prefix scheduled to expire.
		 *
		 * Note that if there are no prefixes in the pool, 
		 * expire_prefix6() will return ISC_R_SUCCESS with 
		 * a NULL prefix.
		 */
		pref = NULL;
		if (expire_prefix6(&pref, ppool, cur_time) != ISC_R_SUCCESS) {
			break;
		}
		if (pref == NULL) {
			break;
		}

		/* No DDNS for prefixes. */

		write_ia_pd(pref->ia_pd);

		iaprefix_dereference(&pref, MDL);
	}

	/*
	 * Do some cleanup of our expired prefixes.
	 */
	cleanup_old_pexpired(ppool);

	/*
	 * Schedule next round of expirations.
	 */
	schedule_prefix_timeout(ppool);
}

/*
 * For a given prefix pool, add a timer that will remove the next
 * prefix to expire.
 */
void 
schedule_prefix_timeout(struct ipv6_ppool *ppool) {
	struct iaprefix *tmp;
	time_t timeout;
	time_t next_timeout;
	struct timeval tv;

	next_timeout = MAX_TIME;

	if (ppool->num_active > 0) {
		tmp = (struct iaprefix *)
			isc_heap_element(ppool->active_timeouts, 1);
		if (tmp->hard_lifetime_end_time < next_timeout) {
			next_timeout = tmp->hard_lifetime_end_time + 1;
		}
	}

	if (ppool->num_inactive > 0) {
		tmp = (struct iaprefix *)
			isc_heap_element(ppool->inactive_timeouts, 1);
		if (tmp->hard_lifetime_end_time != 0) {
			timeout = tmp->hard_lifetime_end_time;
			timeout += EXPIRED_IPV6_CLEANUP_TIME;
		} else {
			timeout = tmp->soft_lifetime_end_time + 1;
		}
		if (timeout < next_timeout) {
			next_timeout = timeout;
		}
	}

	if (next_timeout < MAX_TIME) {
		tv.tv_sec = next_timeout;
		tv.tv_usec = 0;
		add_timeout(&tv, prefix_timeout_support, ppool,
			    (tvref_t)ipv6_ppool_reference, 
			    (tvunref_t)ipv6_ppool_dereference);
	}
}

/*
 * Schedule timeouts across all pools.
 */
void
schedule_all_ipv6_prefix_timeouts(void) {
	int i;

	for (i=0; i<num_ppools; i++) {
		schedule_prefix_timeout(ppools[i]);
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
	
	ipv6_network_portion(&tmp, addr, pool->bits & ~POOL_IS_FOR_TEMP);
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
find_ipv6_pool(struct ipv6_pool **pool, int temp,
	       const struct in6_addr *addr) {
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
		if (temp && ((pools[i]->bits & POOL_IS_FOR_TEMP) == 0)) {
			continue;
		}
		if (!temp && ((pools[i]->bits & POOL_IS_FOR_TEMP) != 0)) {
			continue;
		}
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
change_leases(struct ia_na *ia, 
	      isc_result_t (*change_func)(struct ipv6_pool *, struct iaaddr*)) {
	isc_result_t retval;
	isc_result_t renew_retval;
	struct ipv6_pool *pool;
	struct in6_addr *addr;
	int temp, i;

	retval = ISC_R_SUCCESS;
	if (ia->ia_type == D6O_IA_NA) {
		temp = 0;
	} else if (ia->ia_type == D6O_IA_TA) {
		temp = 1;
	} else {
		log_error("IA without type.");
		return ISC_R_INVALIDARG;
	}
	for (i=0; i<ia->num_iaaddr; i++) {
		pool = NULL;
		addr = &ia->iaaddr[i]->addr;
		if (find_ipv6_pool(&pool, temp, addr) == ISC_R_SUCCESS) {
			renew_retval =  change_func(pool, ia->iaaddr[i]);
			if (renew_retval != ISC_R_SUCCESS) {
				retval = renew_retval;
			}
		}
		/* XXXsk: should we warn if we don't find a pool? */
	}
	return retval;
}

/*
 * Renew all leases in an IA from all pools.
 *
 * The new hard_lifetime_end_time should be updated for the addresses.
 *
 * WARNING: lease times must only be extended, never reduced!!!
 */
isc_result_t 
renew_leases(struct ia_na *ia) {
	return change_leases(ia, renew_lease6);
}

/*
 * Release all leases in an IA from all pools.
 */
isc_result_t 
release_leases(struct ia_na *ia) {
	return change_leases(ia, release_lease6);
}

/*
 * Decline all leases in an IA from all pools.
 */
isc_result_t 
decline_leases(struct ia_na *ia) {
	return change_leases(ia, decline_lease6);
}

/*
 * Determine if the given prefix is in the pool.
 */
isc_boolean_t
ipv6_prefix_in_ppool(const struct in6_addr *pref,
		     const struct ipv6_ppool *ppool) {
	struct in6_addr tmp;
	
	ipv6_network_portion(&tmp, pref, (int)ppool->pool_plen);
	if (memcmp(&tmp, &ppool->start_pref, sizeof(tmp)) == 0) {
		return ISC_TRUE;
	} else {
		return ISC_FALSE;
	}
}

/*
 * Find the pool that contains the given prefix.
 *
 * - pool must be a pointer to a (struct ipv6_ppool *) pointer previously
 *   initialized to NULL
 */
isc_result_t
find_ipv6_ppool(struct ipv6_ppool **ppool, const struct in6_addr *pref) {
	int i;

	if (ppool == NULL) {
		log_error("%s(%d): NULL pointer reference", MDL);
		return ISC_R_INVALIDARG;
	}
	if (*ppool != NULL) {
		log_error("%s(%d): non-NULL pointer", MDL);
		return ISC_R_INVALIDARG;
	}

	for (i=0; i<num_ppools; i++) {
		if (ipv6_prefix_in_ppool(pref, ppools[i])) { 
			ipv6_ppool_reference(ppool, ppools[i], MDL);
			return ISC_R_SUCCESS;
		}
	}
	return ISC_R_NOTFOUND;
}

/*
 * Helper function for the various functions that act across all
 * prefix pools.
 */
static isc_result_t 
change_prefixes(struct ia_pd *ia_pd, 
		isc_result_t (*change_func)(struct ipv6_ppool *,
					    struct iaprefix*)) {
	isc_result_t retval;
	isc_result_t renew_retval;
	struct ipv6_ppool *ppool;
	struct in6_addr *pref;
	int i;

	retval = ISC_R_SUCCESS;
	for (i=0; i<ia_pd->num_iaprefix; i++) {
		ppool = NULL;
		pref = &ia_pd->iaprefix[i]->pref;
		if (find_ipv6_ppool(&ppool, pref) == ISC_R_SUCCESS) {
			renew_retval = change_func(ppool, ia_pd->iaprefix[i]);
			if (renew_retval != ISC_R_SUCCESS) {
				retval = renew_retval;
			}
		}
		/* XXXsk: should we warn if we don't find a pool? */
	}
	return retval;
}

/*
 * Renew all prefixes in an IA_PD from all pools.
 *
 * The new hard_lifetime_end_time should be updated for the addresses.
 *
 * WARNING: lease times must only be extended, never reduced!!!
 */
isc_result_t 
renew_prefixes(struct ia_pd *ia_pd) {
	return change_prefixes(ia_pd, renew_prefix6);
}

/*
 * Release all prefixes in an IA_PD from all pools.
 */
isc_result_t 
release_prefixes(struct ia_pd *ia_pd) {
	return change_prefixes(ia_pd, release_prefix6);
}

#ifdef DHCPv6
/*
 * Helper function to output leases.
 */
static int write_error;

static isc_result_t 
write_ia_leases(const void *name, unsigned len, void *value) {
	struct ia_na *ia = (struct ia_na *)value;
	
	if (!write_error) { 
		if (!write_ia(ia)) {
			write_error = 1;
		}
	}
	return ISC_R_SUCCESS;
}

/*
 * Helper function to output prefixes.
 */
static isc_result_t 
write_ia_pd_prefixes(const void *name, unsigned len, void *value) {
	struct ia_pd *ia_pd = (struct ia_pd *)value;
	
	if (!write_error) { 
		if (!write_ia_pd(ia_pd)) {
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
	ia_na_hash_foreach(ia_na_active, write_ia_leases);
	if (write_error) {
		return 0;
	}
	ia_na_hash_foreach(ia_ta_active, write_ia_leases);
	if (write_error) {
		return 0;
	}
	ia_pd_hash_foreach(ia_pd_active, write_ia_pd_prefixes);
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
	if (find_ipv6_pool(&p, 0, &addr) == ISC_R_SUCCESS) {
		mark_address_unavailable(p, &addr);
		ipv6_pool_dereference(&p, MDL);
	} 
	if (find_ipv6_pool(&p, 1, &addr) == ISC_R_SUCCESS) {
		mark_address_unavailable(p, &addr);
		ipv6_pool_dereference(&p, MDL);
	} 

	return ISC_R_SUCCESS;
}

void
mark_hosts_unavailable(void) {
	hash_foreach(host_name_hash, mark_hosts_unavailable_support);
}

static isc_result_t
mark_phosts_unavailable_support(const void *name, unsigned len, void *value) {
	struct host_decl *h;
	struct iaddrcidrnetlist *l;
	struct in6_addr pref;
	struct ipv6_ppool *p;

	h = (struct host_decl *)value;

	/*
	 * If the host has no prefix, we don't need to mark anything.
	 */
	if (h->fixed_prefix == NULL) {
		return ISC_R_SUCCESS;
	}

	/* 
	 * Get the fixed prefixes.
	 */
	for (l = h->fixed_prefix; l != NULL; l = l->next) {
		if (l->cidrnet.lo_addr.len != 16) {
			continue;
		}
		memcpy(&pref, l->cidrnet.lo_addr.iabuf, 16);

		/*
		 * Find the pool holding this host, and mark the prefix.
		 * (I suppose it is arguably valid to have a host that does not
		 * sit in any pool.)
		 */
		p = NULL;
		if (find_ipv6_ppool(&p, &pref) != ISC_R_SUCCESS) {
			continue;
		}
		if (l->cidrnet.bits != (int) p->alloc_plen) {
			ipv6_ppool_dereference(&p, MDL);
			continue;
		}
		mark_prefix_unavailable(p, &pref);
		ipv6_ppool_dereference(&p, MDL);
	} 

	return ISC_R_SUCCESS;
}

void
mark_phosts_unavailable(void) {
	hash_foreach(host_name_hash, mark_phosts_unavailable_support);
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
			if (find_ipv6_pool(&p, 0, &ip->v6addresses[i]) 
							== ISC_R_SUCCESS) {
				mark_address_unavailable(p, 
							 &ip->v6addresses[i]);
				ipv6_pool_dereference(&p, MDL);
			} 
			if (find_ipv6_pool(&p, 1, &ip->v6addresses[i]) 
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

	/* create_lease6, renew_lease6, expire_lease6 */
	uid = "client0";
	memset(&ds, 0, sizeof(ds));
	ds.len = strlen(uid);
	if (!buffer_allocate(&ds.buffer, ds.len, MDL)) {
		printf("Out of memory\n");
		return 1;
	}
	ds.data = ds.buffer->data;
	memcpy((char *)ds.data, uid, ds.len);
	if (create_lease6(pool, &iaaddr, 
			  &attempts, &ds, 1) != ISC_R_SUCCESS) {
		printf("ERROR: create_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (pool->num_inactive != 1) {
		printf("ERROR: bad num_inactive %s:%d\n", MDL);
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
	if (create_lease6(pool, &iaaddr, &attempts, 
			  &ds, 1) != ISC_R_SUCCESS) {
		printf("ERROR: create_lease6() %s:%d\n", MDL);
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
	if (create_lease6(pool, &iaaddr, &attempts, 
			  &ds, 1) != ISC_R_SUCCESS) {
		printf("ERROR: create_lease6() %s:%d\n", MDL);
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
		if (create_lease6(pool, &iaaddr, &attempts,
				  &ds, i) != ISC_R_SUCCESS) {
			printf("ERROR: create_lease6() %s:%d\n", MDL);
			return 1;
		}
		if (renew_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
			printf("ERROR: renew_lease6() %s:%d\n", MDL);
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
		if (expired_iaaddr->hard_lifetime_end_time != i) {
			printf("ERROR: bad hard_lifetime_end_time %s:%d\n", 
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
	addr.s6_addr[14] = 0x81;
	if (ipv6_pool_allocate(&pool, &addr, 127, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_allocate() %s:%d\n", MDL);
		return 1;
	}
	if (create_lease6(pool, &iaaddr, &attempts, 
			  &ds, 42) != ISC_R_SUCCESS) {
		printf("ERROR: create_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (renew_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
		printf("ERROR: renew_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
		return 1;
	}
	if (create_lease6(pool, &iaaddr, &attempts, 
			  &ds, 11) != ISC_R_SUCCESS) {
		printf("ERROR: create_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (renew_lease6(pool, iaaddr) != ISC_R_SUCCESS) {
		printf("ERROR: renew_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (iaaddr_dereference(&iaaddr, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: iaaddr_dereference() %s:%d\n", MDL);
		return 1;
	}
	if (create_lease6(pool, &iaaddr, &attempts, 
			  &ds, 11) != ISC_R_NORESOURCES) {
		printf("ERROR: create_lease6() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
		return 1;
	}
	addr.s6_addr[14] = 0;

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
	if (find_ipv6_pool(&pool, 0, &addr) != ISC_R_SUCCESS) {
		printf("ERROR: find_ipv6_pool() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
		return 1;
	}
	inet_pton(AF_INET6, "1:2:3:4:ffff:ffff:ffff:ffff", &addr);
	pool = NULL;
	if (find_ipv6_pool(&pool, 0, &addr) != ISC_R_SUCCESS) {
		printf("ERROR: find_ipv6_pool() %s:%d\n", MDL);
		return 1;
	}
	if (ipv6_pool_dereference(&pool, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ipv6_pool_dereference() %s:%d\n", MDL);
		return 1;
	}
	inet_pton(AF_INET6, "1:2:3:5::", &addr);
	pool = NULL;
	if (find_ipv6_pool(&pool, 0, &addr) != ISC_R_NOTFOUND) {
		printf("ERROR: find_ipv6_pool() %s:%d\n", MDL);
		return 1;
	}
	inet_pton(AF_INET6, "1:2:3:3:ffff:ffff:ffff:ffff", &addr);
	pool = NULL;
	if (find_ipv6_pool(&pool, 0, &addr) != ISC_R_NOTFOUND) {
		printf("ERROR: find_ipv6_pool() %s:%d\n", MDL);
		return 1;
	}

/*	iaid = 666;
	ia_na = NULL;
	if (ia_na_allocate(&ia_na, iaid, "TestDUID", 8, MDL) != ISC_R_SUCCESS) {
		printf("ERROR: ia_na_allocate() %s:%d\n", MDL);
		return 1;
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
				create_prefix(&r, &addr, i, j, &ds);
				inet_ntop(AF_INET6, &r, buf, 64);
				printf("%d,%d-> %s/%d\n", i, j, buf, j);
			}
	}
	
	printf("SUCCESS: all tests passed (ignore any warning messages)\n");
	return 0;
}
#endif
