/* alloc.c

   Memory allocation... */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

#ifndef lint
static char copyright[] =
"$Id: alloc.c,v 1.29 1999/05/07 17:34:30 mellon Exp $ Copyright (c) 1995, 1996, 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

struct dhcp_packet *dhcp_free_list;
struct packet *packet_free_list;

VOIDPTR dmalloc (size, name)
	int size;
	char *name;
{
	VOIDPTR foo = (VOIDPTR)malloc (size);
	if (!foo)
		log_error ("No memory for %s.", name);
	else
		memset (foo, 0, size);
	return foo;
}

void dfree (ptr, name)
	VOIDPTR ptr;
	char *name;
{
	if (!ptr) {
		log_error ("dfree %s: free on null pointer.", name);
		return;
	}
	free (ptr);
}

struct packet *new_packet (name)
	char *name;
{
	struct packet *rval;
	rval = (struct packet *)dmalloc (sizeof (struct packet), name);
	return rval;
}

struct dhcp_packet *new_dhcp_packet (name)
	char *name;
{
	struct dhcp_packet *rval;
	rval = (struct dhcp_packet *)dmalloc (sizeof (struct dhcp_packet),
					      name);
	return rval;
}

struct hash_table *new_hash_table (count, name)
	int count;
	char *name;
{
	struct hash_table *rval = dmalloc (sizeof (struct hash_table)
					   - (DEFAULT_HASH_SIZE
					      * sizeof (struct hash_bucket *))
					   + (count
					      * sizeof (struct hash_bucket *)),
					   name);
	rval -> hash_count = count;
	return rval;
}

struct hash_bucket *new_hash_bucket (name)
	char *name;
{
	struct hash_bucket *rval = dmalloc (sizeof (struct hash_bucket), name);
	return rval;
}

struct lease *new_leases (n, name)
	int n;
	char *name;
{
	struct lease *rval = dmalloc (n * sizeof (struct lease), name);
	return rval;
}

struct lease *new_lease (name)
	char *name;
{
	struct lease *rval = dmalloc (sizeof (struct lease), name);
	return rval;
}

struct subnet *new_subnet (name)
	char *name;
{
	struct subnet *rval = dmalloc (sizeof (struct subnet), name);
	return rval;
}

struct class *new_class (name)
	char *name;
{
	struct class *rval = dmalloc (sizeof (struct class), name);
	return rval;
}

struct shared_network *new_shared_network (name)
	char *name;
{
	struct shared_network *rval =
		dmalloc (sizeof (struct shared_network), name);
	return rval;
}

struct group *new_group (name)
	char *name;
{
	struct group *rval =
		dmalloc (sizeof (struct group), name);
	if (rval)
		memset (rval, 0, sizeof *rval);
	return rval;
}

struct protocol *new_protocol (name)
	char *name;
{
	struct protocol *rval = dmalloc (sizeof (struct protocol), name);
	return rval;
}

struct lease_state *free_lease_states;

struct lease_state *new_lease_state (name)
	char *name;
{
	struct lease_state *rval;

	if (free_lease_states) {
		rval = free_lease_states;
		free_lease_states =
			(struct lease_state *)(free_lease_states -> next);
	} else {
		rval = dmalloc (sizeof (struct lease_state), name);
		if (!rval)
			return rval;
	}
	memset (rval, 0, sizeof *rval);
	if (!option_state_allocate (&rval -> options, name)) {
		free_lease_state (rval, name);
		return (struct lease_state *)0;
	}
	return rval;
}

struct domain_search_list *new_domain_search_list (name)
	char *name;
{
	struct domain_search_list *rval =
		dmalloc (sizeof (struct domain_search_list), name);
	return rval;
}

struct name_server *new_name_server (name)
	char *name;
{
	struct name_server *rval =
		dmalloc (sizeof (struct name_server), name);
	return rval;
}

void free_name_server (ptr, name)
	struct name_server *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

struct option *new_option (name)
	char *name;
{
	struct option *rval =
		dmalloc (sizeof (struct option), name);
	if (rval)
		memset (rval, 0, sizeof *rval);
	return rval;
}

void free_option (ptr, name)
	struct option *ptr;
	char *name;
{
/* XXX have to put all options on heap before this is possible. */
#if 0
	if (ptr -> name)
		dfree ((VOIDPTR)option -> name, name);
	dfree ((VOIDPTR)ptr, name);
#endif
}

struct universe *new_universe (name)
	char *name;
{
	struct universe *rval =
		dmalloc (sizeof (struct universe), name);
	return rval;
}

void free_universe (ptr, name)
	struct universe *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_domain_search_list (ptr, name)
	struct domain_search_list *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_lease_state (ptr, name)
	struct lease_state *ptr;
	char *name;
{
	option_state_dereference (&ptr -> options, name);
	ptr -> next = free_lease_states;
	free_lease_states = ptr;
}

void free_protocol (ptr, name)
	struct protocol *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_group (ptr, name)
	struct group *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_shared_network (ptr, name)
	struct shared_network *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_class (ptr, name)
	struct class *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_subnet (ptr, name)
	struct subnet *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_lease (ptr, name)
	struct lease *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_hash_bucket (ptr, name)
	struct hash_bucket *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_hash_table (ptr, name)
	struct hash_table *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_packet (ptr, name)
	struct packet *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

void free_dhcp_packet (ptr, name)
	struct dhcp_packet *ptr;
	char *name;
{
	dfree ((VOIDPTR)ptr, name);
}

struct client_lease *new_client_lease (name)
	char *name;
{
	return (struct client_lease *)dmalloc (sizeof (struct client_lease),
					       name);
}

void free_client_lease (lease, name)
	struct client_lease *lease;
	char *name;
{
	dfree (lease, name);
}

struct pool *new_pool (name)
	char *name;
{
	struct pool *pool = ((struct pool *)
			     dmalloc (sizeof (struct pool), name));
	if (!pool)
		return pool;
	memset (pool, 0, sizeof *pool);
	return pool;
}

void free_pool (pool, name)
	struct pool *pool;
	char *name;
{
	dfree (pool, name);
}

#if defined (FAILOVER_PROTOCOL)
struct failover_peer *new_failover_peer (name)
	char *name;
{
	struct failover_peer *peer = ((struct failover_peer *)
				      dmalloc (sizeof (struct failover_peer),
					       name));
	if (!peer)
		return peer;
	memset (peer, 0, sizeof *peer);
	return peer;
}

void free_failover_peer (peer, name)
	struct failover_peer *peer;
	char *name;
{
	dfree (peer, name);
}
#endif /* defined (FAILOVER_PROTOCOL) */

struct auth_key *new_auth_key (len, name)
	int len;
	char *name;
{
	struct auth_key *peer;
	int size = len - 1 + sizeof (struct auth_key);

	peer = (struct auth_key *)dmalloc (size, name);
	if (!peer)
		return peer;
	memset (peer, 0, size);
	return peer;
}

void free_auth_key (peer, name)
	struct auth_key *peer;
	char *name;
{
	dfree (peer, name);
}

struct permit *new_permit (name)
	char *name;
{
	struct permit *permit = ((struct permit *)
				 dmalloc (sizeof (struct permit), name));
	if (!permit)
		return permit;
	memset (permit, 0, sizeof *permit);
	return permit;
}

void free_permit (permit, name)
	struct permit *permit;
	char *name;
{
	dfree (permit, name);
}

pair free_pairs;

pair new_pair (name)
	char *name;
{
	pair foo;

	if (free_pairs) {
		foo = free_pairs;
		free_pairs = foo -> cdr;
		memset (foo, 0, sizeof *foo);
		return foo;
	}

	foo = dmalloc (sizeof *foo, name);
	if (!foo)
		return foo;
	memset (foo, 0, sizeof *foo);
	return foo;
}

void free_pair (foo, name)
	pair foo;
	char *name;
{
	foo -> cdr = free_pairs;
	free_pairs = foo;
}

struct expression *free_expressions;

int expression_allocate (cptr, name)
	struct expression **cptr;
	char *name;
{
	struct expression *rval;

	if (free_expressions) {
		rval = free_expressions;
		free_expressions = rval -> data.not;
	} else {
		rval = dmalloc (sizeof (struct expression), name);
		if (!rval)
			return 0;
	}
	memset (rval, 0, sizeof *rval);
	return expression_reference (cptr, rval, name);
}

void free_expression (expr, name)
	struct expression *expr;
	char *name;
{
	expr -> data.not = free_expressions;
	free_expressions = expr;
}

int expression_reference (ptr, src, name)
	struct expression **ptr;
	struct expression *src;
	char *name;
{
	if (!ptr) {
		log_error ("Null pointer in expression_reference: %s", name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	if (*ptr) {
		log_error ("Non-null pointer in expression_reference (%s)",
		      name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	*ptr = src;
	src -> refcnt++;
	return 1;
}

struct option_cache *free_option_caches;

int option_cache_allocate (cptr, name)
	struct option_cache **cptr;
	char *name;
{
	struct option_cache *rval;

	if (free_option_caches) {
		rval = free_option_caches;
		free_option_caches =
			(struct option_cache *)(rval -> expression);
	} else {
		rval = dmalloc (sizeof (struct option_cache), name);
		if (!rval)
			return 0;
	}
	memset (rval, 0, sizeof *rval);
	return option_cache_reference (cptr, rval, name);
}

int option_cache_reference (ptr, src, name)
	struct option_cache **ptr;
	struct option_cache *src;
	char *name;
{
	if (!ptr) {
		log_error ("Null pointer in option_cache_reference: %s", name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	if (*ptr) {
		log_error ("Non-null pointer in option_cache_reference (%s)",
		      name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	*ptr = src;
	src -> refcnt++;
	return 1;
}

int buffer_allocate (ptr, len, name)
	struct buffer **ptr;
	int len;
	char *name;
{
	struct buffer *bp;

	bp = dmalloc (len + sizeof *bp, name);
	if (!bp)
		return 0;
	memset (bp, 0, sizeof *bp);
	bp -> refcnt = 0;
	return buffer_reference (ptr, bp, name);
}

int buffer_reference (ptr, bp, name)
	struct buffer **ptr;
	struct buffer *bp;
	char *name;
{
	if (!ptr) {
		log_error ("Null pointer passed to buffer_reference: %s",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	if (*ptr) {
		log_error ("Non-null pointer in buffer_reference (%s)", name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	*ptr = bp;
	bp -> refcnt++;
	return 1;
}

int buffer_dereference (ptr, name)
	struct buffer **ptr;
	char *name;
{
	struct buffer *bp;

	if (!ptr || !*ptr) {
		log_error ("Null pointer passed to buffer_dereference: %s",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}

	(*ptr) -> refcnt--;
	if (!(*ptr) -> refcnt)
		dfree ((*ptr), name);
	*ptr = (struct buffer *)0;
	return 1;
}

int dns_host_entry_allocate (ptr, hostname, name)
	struct dns_host_entry **ptr;
	char *hostname;
	char *name;
{
	struct dns_host_entry *bp;

	bp = dmalloc (strlen (hostname) + sizeof *bp, name);
	if (!bp)
		return 0;
	memset (bp, 0, sizeof *bp);
	bp -> refcnt = 0;
	strcpy (bp -> hostname, hostname);
	return dns_host_entry_reference (ptr, bp, name);
}

int dns_host_entry_reference (ptr, bp, name)
	struct dns_host_entry **ptr;
	struct dns_host_entry *bp;
	char *name;
{
	if (!ptr) {
		log_error ("Null pointer in dns_host_entry_reference: %s",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	if (*ptr) {
		log_error ("Non-null pointer in dns_host_entry_reference (%s)",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	*ptr = bp;
	bp -> refcnt++;
	return 1;
}

int dns_host_entry_dereference (ptr, name)
	struct dns_host_entry **ptr;
	char *name;
{
	struct dns_host_entry *bp;

	if (!ptr || !*ptr) {
		log_error ("Null pointer in dns_host_entry_dereference: %s",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}

	(*ptr) -> refcnt--;
	if (!(*ptr) -> refcnt)
		dfree ((*ptr), name);
	*ptr = (struct dns_host_entry *)0;
	return 1;
}

int option_state_allocate (ptr, name)
	struct option_state **ptr;
	char *name;
{
	int size;

	if (!ptr) {
		log_error ("Null pointer passed to option_state_allocate: %s",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	if (*ptr) {
		log_error ("Non-null pointer in option_state_allocate (%s)",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}

	size = sizeof **ptr + (universe_count - 1) * sizeof (VOIDPTR);
	*ptr = dmalloc (size, name);
	if (*ptr) {
		memset (*ptr, 0, size);
		(*ptr) -> universe_count = universe_count;
		(*ptr) -> refcnt = 1;
		return 1;
	}
	return 0;
}

int option_state_reference (ptr, bp, name)
	struct option_state **ptr;
	struct option_state *bp;
	char *name;
{
	if (!ptr) {
		log_error ("Null pointer in option_state_reference: %s",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	if (*ptr) {
		log_error ("Non-null pointer in option_state_reference (%s)",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
	*ptr = bp;
	bp -> refcnt++;
	return 1;
}

int option_state_dereference (ptr, name)
	struct option_state **ptr;
	char *name;
{
	int i;
	struct option_state *options;

	if (!ptr || !*ptr) {
		log_error ("Null pointer in option_state_dereference: %s",
			   name);
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}

	options = *ptr;
	*ptr = (struct option_state *)0;
	--options -> refcnt;
	if (options -> refcnt)
		return 1;

	/* Loop through the per-universe state. */
	for (i = 0; i < options -> universe_count; i++)
		if (options -> universes [i] &&
		    universes [i] -> option_state_dereference)
			((*(universes [i] -> option_state_dereference))
			 (universes [i], options));

	dfree (options, name);
	return 1;
}
