/* alloc.c

   Memory allocation... */

/*
 * Copyright (c) 1995, 1996 The Internet Software Consortium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

#ifndef lint
static char copyright[] =
"$Id: alloc.c,v 1.16 1998/11/05 18:39:54 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
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
		warn ("No memory for %s.", name);
	else
		memset (foo, 0, size);
	return foo;
}

void dfree (ptr, name)
	VOIDPTR ptr;
	char *name;
{
	if (!ptr) {
		warn ("dfree %s: free on null pointer.", name);
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
	}
	memset (rval, 0, sizeof *rval);
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
		warn ("Null pointer in expression_reference: %s", name);
		abort ();
	}
	if (*ptr) {
		warn ("Non-null pointer in expression_reference (%s)",
		      name);
		abort ();
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
		warn ("Null pointer in option_cache_reference: %s", name);
		abort ();
	}
	if (*ptr) {
		warn ("Non-null pointer in option_cache_reference (%s)",
		      name);
		abort ();
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
		warn ("Null pointer passed to buffer_reference: %s", name);
		abort ();
	}
	if (*ptr) {
		warn ("Non-null pointer in buffer_reference (%s)", name);
		abort ();
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
		warn ("Null pointer passed to buffer_dereference: %s", name);
		abort ();
	}

	(*ptr) -> refcnt--;
	if (!(*ptr) -> refcnt)
		dfree ((*ptr), name);
	*ptr = (struct buffer *)0;
	return 1;
}

int dns_host_entry_allocate (ptr, name)
	struct dns_host_entry **ptr;
	char *name;
{
	struct dns_host_entry *bp;

	bp = dmalloc (sizeof *bp, name);
	if (!bp)
		return 0;
	memset (bp, 0, sizeof *bp);
	bp -> refcnt = 0;
	return dns_host_entry_reference (ptr, bp, name);
}

int dns_host_entry_reference (ptr, bp, name)
	struct dns_host_entry **ptr;
	struct dns_host_entry *bp;
	char *name;
{
	if (!ptr) {
		warn ("Null pointer in dns_host_entry_reference: %s", name);
		abort ();
	}
	if (*ptr) {
		warn ("Non-null pointer in dns_host_entry_reference (%s)",
		      name);
		abort ();
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
		warn ("Null pointer in dns_host_entry_dereference: %s", name);
		abort ();
	}

	(*ptr) -> refcnt--;
	if (!(*ptr) -> refcnt)
		dfree ((*ptr), name);
	*ptr = (struct dns_host_entry *)0;
	return 1;
}
