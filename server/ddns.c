/* ddns.c

   Dynamic DNS updates. */

/*
 * Copyright (c) 2000 Internet Software Consortium.
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
 * This software has been donated to the Internet Software Consortium
 * by Damien Neil of Nominum, Inc.
 *
 * To learn more about the Internet Software Consortium, see
 * ``http://www.isc.org/''.   To learn more about Nominum, Inc., see
 * ``http://www.nominum.com''.
 */

#ifndef lint
static char copyright[] =
"$Id: ddns.c,v 1.2 2000/12/28 23:23:46 mellon Exp $ Copyright (c) 1995-2000 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "../minires/md5.h"

#ifdef NSUPDATE

/* Have to use TXT records for now. */
#define T_DHCID T_TXT

static int get_dhcid (struct data_string *, struct lease *);

static struct __res_state resolver_state;
static int                resolver_inited = 0;


static int get_dhcid (struct data_string *id, struct lease *lease)
{
	unsigned char buf[MD5_DIGEST_LENGTH];
	MD5_CTX md5;
	int i;

	if (!buffer_allocate (&id -> buffer,
			      (MD5_DIGEST_LENGTH * 2) + 3, MDL))
		return 0;
	id -> data = id -> buffer -> data;

	/*
	 * DHCP clients and servers should use the following forms of client
	 * identification, starting with the most preferable, and finishing
	 * with the least preferable.  If the client does not send any of these
	 * forms of identification, the DHCP/DDNS interaction is not defined by
	 * this specification.  The most preferable form of identification is
	 * the Globally Unique Identifier Option [TBD].  Next is the DHCP
	 * Client Identifier option.  Last is the client's link-layer address,
	 * as conveyed in its DHCPREQUEST message.  Implementors should note
	 * that the link-layer address cannot be used if there are no
	 * significant bytes in the chaddr field of the DHCP client's request,
	 * because this does not constitute a unique identifier.
	 *   -- "Interaction between DHCP and DNS"
	 *      <draft-ietf-dhc-dhcp-dns-12.txt>
	 *      M. Stapp, Y. Rekhter
	 */

	MD5_Init (&md5);

	if (lease -> uid) {
		id -> buffer -> data [0] =
			"0123456789abcdef" [DHO_DHCP_CLIENT_IDENTIFIER >> 4];
		id -> buffer -> data [1] =
			"0123456789abcdef" [DHO_DHCP_CLIENT_IDENTIFIER % 15];
		/* Use the DHCP Client Identifier option. */
		MD5_Update (&md5, lease -> uid, lease -> uid_len);
	} else if (lease -> hardware_addr.hlen) {
		id -> buffer -> data [0] = '0';
		id -> buffer -> data [1] = '0';
		/* Use the link-layer address. */
		MD5_Update (&md5,
			    lease -> hardware_addr.hbuf,
			    lease -> hardware_addr.hlen);
	} else {
		/* Uh-oh.  Something isn't right here. */
		return 1;
	}

	MD5_Final (buf, &md5);

	/* Convert into ASCII. */
	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		id -> buffer -> data [i * 2 + 2] =
			"0123456789abcdef" [(buf [i] >> 4) & 0xf];
		id -> buffer -> data [i * 2 + 3] =
			"0123456789abcdef" [buf [i] & 0xf];
	}
	id -> len = MD5_DIGEST_LENGTH * 2 + 2;
	id -> buffer -> data [id -> len] = 0;
	id -> terminated = 1;

	return 0;
}


/* DN: No way of checking that there is enough space in a data_string's
   buffer.  Be certain to allocate enough!
   TL: This is why we the expression evaluation code allocates a *new*
   data_string.   :') */
static void data_string_append (struct data_string *ds1,
				struct data_string *ds2)
{
	memcpy (ds1 -> buffer -> data + ds1 -> len,
		ds2 -> data,
		ds2 -> len);
	ds1 -> len += ds2 -> len;
}


static struct binding *create_binding (struct binding_scope **scope,
				       const char *name)
{
	struct binding *binding;

	if (!*scope) {
		if (!binding_scope_allocate (scope, MDL))
			return (struct binding *)0;
	}

	binding = find_binding (*scope, name);
	if (!binding) {
		binding = dmalloc (sizeof *binding, MDL);
		if (!binding)
			return (struct binding *)0;

		memset (binding, 0, sizeof *binding);
		binding -> name = dmalloc (strlen (name) + 1, MDL);
		if (!binding -> name) {
			dfree (binding, MDL);
			return (struct binding *)0;
		}
		strcpy (binding -> name, name);

		binding -> next = (*scope) -> bindings;
		(*scope) -> bindings = binding;
	}

	return binding;
}


static int bind_ds_value (struct binding_scope **scope,
			  const char *name,
			  struct data_string *value)
{
	struct binding *binding;

	binding = create_binding (scope, name);
	if (!binding)
		return 0;

	if (binding -> value)
		binding_value_dereference (&binding -> value, MDL);

	if (!binding_value_allocate (&binding -> value, MDL))
		return 0;

	data_string_copy (&binding -> value -> value.data, value, MDL);
	binding -> value -> type = binding_data;

	return 1;
}


static int find_bound_string (struct data_string *value,
			      struct binding_scope *scope,
			      const char *name)
{
	struct binding *binding;

	binding = find_binding (scope, name);
	if (!binding ||
	    !binding -> value ||
	    binding -> value -> type != binding_data)
		return 0;

	if (binding -> value -> value.data.terminated) {
		data_string_copy (value, &binding -> value -> value.data, MDL);
	} else {
		buffer_allocate (&value -> buffer,
				 binding -> value -> value.data.len,
				 MDL);
		if (!value -> buffer)
			return 0;

		memcpy (value -> buffer -> data,
			binding -> value -> value.data.data,
			binding -> value -> value.data.len);
		value -> data = value -> buffer -> data;
		value -> len  = binding -> value -> value.data.len;

		data_string_forget (&binding -> value -> value.data, MDL);
		data_string_copy (&binding -> value -> value.data, value, MDL);
	}

	return 1;
}


static ns_rcode ddns_update_a (struct data_string *ddns_fwd_name,
			       struct data_string *ddns_address,
			       struct data_string *ddns_dhcid,
			       unsigned long ttl)
{
	ns_updque updque;
	ns_updrec *updrec;
	ns_rcode result;

	/*
	 * When a DHCP client or server intends to update an A RR, it first
	 * prepares a DNS UPDATE query which includes as a prerequisite the
	 * assertion that the name does not exist.  The update section of the
	 * query attempts to add the new name and its IP address mapping (an A
	 * RR), and the DHCID RR with its unique client-identity.
	 *   -- "Interaction between DHCP and DNS"
	 */

	ISC_LIST_INIT (updque);

	/*
	 * A RR does not exist.
	 */
	updrec = minires_mkupdrec (S_PREREQ, ddns_fwd_name -> data,
				   C_IN, T_A, 0);
	if (!updrec) goto error;

	updrec -> r_data   = (unsigned char *)0;
	updrec -> r_size   = 0;
	updrec -> r_opcode = NXDOMAIN;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Add A RR.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_fwd_name -> data,
				   C_IN, T_A, ttl);
	if (!updrec) goto error;

	updrec -> r_data = ddns_address -> buffer -> data;
	updrec -> r_size = ddns_address -> len;
	updrec -> r_opcode = ADD;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Add DHCID RR.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_fwd_name -> data,
				   C_IN, T_DHCID, ttl);
	if (!updrec) goto error;

	updrec -> r_data = ddns_dhcid -> buffer -> data;
	updrec -> r_size = ddns_dhcid -> len;
	updrec -> r_opcode = ADD;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Attempt to perform the update.
	 */
	result = minires_nupdate (&resolver_state, ISC_LIST_HEAD (updque));

	while (!ISC_LIST_EMPTY (updque)) {
		updrec = ISC_LIST_HEAD (updque);
		ISC_LIST_UNLINK (updque, updrec, r_link);
		minires_freeupdrec (updrec);
	}


	/*
	 * If this update operation succeeds, the updater can conclude that it
	 * has added a new name whose only RRs are the A and DHCID RR records.
	 * The A RR update is now complete (and a client updater is finished,
	 * while a server might proceed to perform a PTR RR update).
	 *   -- "Interaction between DHCP and DNS"
	 */

	if (result == NOERROR)
		return result;


	/*
	 * If the first update operation fails with YXDOMAIN, the updater can
	 * conclude that the intended name is in use.  The updater then
	 * attempts to confirm that the DNS name is not being used by some
	 * other host. The updater prepares a second UPDATE query in which the
	 * prerequisite is that the desired name has attached to it a DHCID RR
	 * whose contents match the client identity.  The update section of
	 * this query deletes the existing A records on the name, and adds the
	 * A record that matches the DHCP binding and the DHCID RR with the
	 * client identity.
	 *   -- "Interaction between DHCP and DNS"
	 */

	if (result != YXDOMAIN)
		return result;


	/*
	 * DHCID RR exists, and matches client identity.
	 */
	updrec = minires_mkupdrec (S_PREREQ, ddns_fwd_name -> data,
				   C_IN, T_DHCID, 0);
	if (!updrec) goto error;

	updrec -> r_data = ddns_dhcid -> buffer -> data;
	updrec -> r_size = ddns_dhcid -> len;
	updrec -> r_opcode = YXRRSET;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Delete A RRset.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_fwd_name -> data,
				   C_IN, T_A, 0);
	if (!updrec) goto error;

	updrec -> r_data = (unsigned char *)0;
	updrec -> r_size = 0;
	updrec -> r_opcode = DELETE;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Add A RR.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_fwd_name -> data,
				   C_IN, T_A, ttl);
	if (!updrec) goto error;

	updrec -> r_data = ddns_address -> buffer -> data;
	updrec -> r_size = ddns_address -> len;
	updrec -> r_opcode = ADD;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Attempt to perform the update.
	 */
	result = minires_nupdate (&resolver_state, ISC_LIST_HEAD (updque));

	while (!ISC_LIST_EMPTY (updque)) {
		updrec = ISC_LIST_HEAD (updque);
		ISC_LIST_UNLINK (updque, updrec, r_link);
		minires_freeupdrec (updrec);
	}


	/*
	 * If this query succeeds, the updater can conclude that the current
	 * client was the last client associated with the domain name, and that
	 * the name now contains the updated A RR. The A RR update is now
	 * complete (and a client updater is finished, while a server would
	 * then proceed to perform a PTR RR update).
	 *   -- "Interaction between DHCP and DNS"
	 */

	if (result == NOERROR)
		return result;


	/*
	 * If the second query fails with NXRRSET, the updater must conclude
	 * that the client's desired name is in use by another host.  At this
	 * juncture, the updater can decide (based on some administrative
	 * configuration outside of the scope of this document) whether to let
	 * the existing owner of the name keep that name, and to (possibly)
	 * perform some name disambiguation operation on behalf of the current
	 * client, or to replace the RRs on the name with RRs that represent
	 * the current client. If the configured policy allows replacement of
	 * existing records, the updater submits a query that deletes the
	 * existing A RR and the existing DHCID RR, adding A and DHCID RRs that
	 * represent the IP address and client-identity of the new client.
	 *   -- "Interaction between DHCP and DNS"
	 */

	return result;


  error:
	while (!ISC_LIST_EMPTY (updque)) {
		updrec = ISC_LIST_HEAD (updque);
		ISC_LIST_UNLINK (updque, updrec, r_link);
		minires_freeupdrec (updrec);
	}

	return SERVFAIL;
}


static ns_rcode ddns_update_ptr (struct data_string *ddns_fwd_name,
				 struct data_string *ddns_rev_name,
				 struct data_string *ddns_dhcid,
				 unsigned long ttl)
{
	ns_updque updque;
	ns_updrec *updrec;
	ns_rcode result = SERVFAIL;

	/*
	 * The DHCP server submits a DNS query which deletes all of the PTR RRs
	 * associated with the lease IP address, and adds a PTR RR whose data
	 * is the client's (possibly disambiguated) host name. The server also
	 * adds a DHCID RR specified in Section 4.3.
	 *   -- "Interaction between DHCP and DNS"
	 */

	ISC_LIST_INIT (updque);

	/*
	 * Delete all PTR RRs.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_rev_name -> data,
				   C_IN, T_PTR, 0);
	if (!updrec) goto error;

	updrec -> r_data   = (unsigned char *)0;
	updrec -> r_size   = 0;
	updrec -> r_opcode = DELETE;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Add PTR RR.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_rev_name -> data,
				   C_IN, T_PTR, ttl);
	if (!updrec) goto error;

	updrec -> r_data   = ddns_fwd_name -> buffer -> data;
	updrec -> r_size   = ddns_fwd_name -> len;
	updrec -> r_opcode = ADD;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Add DHCID RR.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_rev_name -> data,
				   C_IN, T_DHCID,ttl);
	if (!updrec) goto error;

	updrec -> r_data = ddns_dhcid -> buffer -> data;
	updrec -> r_size = ddns_dhcid -> len;
	updrec -> r_opcode = ADD;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Attempt to perform the update.
	 */
	result = minires_nupdate (&resolver_state, ISC_LIST_HEAD (updque));


	/* Fall through. */
  error:

	while (!ISC_LIST_EMPTY (updque)) {
		updrec = ISC_LIST_HEAD (updque);
		ISC_LIST_UNLINK (updque, updrec, r_link);
		minires_freeupdrec (updrec);
	}

	return result;
}


static ns_rcode ddns_remove_a (struct data_string *ddns_fwd_name,
			       struct data_string *ddns_address,
			       struct data_string *ddns_dhcid)
{
	ns_updque updque;
	ns_updrec *updrec;
	ns_rcode result = SERVFAIL;

	/*
	 * The entity chosen to handle the A record for this client (either the
	 * client or the server) SHOULD delete the A record that was added when
	 * the lease was made to the client.
	 *
	 * In order to perform this delete, the updater prepares an UPDATE
	 * query which contains two prerequisites.  The first prerequisite
	 * asserts that the DHCID RR exists whose data is the client identity
	 * described in Section 4.3. The second prerequisite asserts that the
	 * data in the A RR contains the IP address of the lease that has
	 * expired or been released.
	 *   -- "Interaction between DHCP and DNS"
	 */

	ISC_LIST_INIT (updque);

	/*
	 * DHCID RR exists, and matches client identity.
	 */
	updrec = minires_mkupdrec (S_PREREQ, ddns_fwd_name -> data,
				   C_IN, T_DHCID,0);
	if (!updrec) goto error;

	updrec -> r_data = ddns_dhcid -> buffer -> data;
	updrec -> r_size = ddns_dhcid -> len;
	updrec -> r_opcode = YXRRSET;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * A RR matches the expiring lease.
	 */
	updrec = minires_mkupdrec (S_PREREQ, ddns_fwd_name -> data,
				   C_IN, T_A, 0);
	if (!updrec) goto error;

	updrec -> r_data = ddns_address -> buffer -> data;
	updrec -> r_size = ddns_address -> len;
	updrec -> r_opcode = YXRRSET;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Delete appropriate A RR.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_fwd_name -> data,
				   C_IN, T_A, 0);
	if (!updrec) goto error;

	updrec -> r_data   = ddns_address -> buffer -> data;
	updrec -> r_size   = ddns_address -> len;
	updrec -> r_opcode = DELETE;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Delete appropriate DHCID RR.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_fwd_name -> data,
				   C_IN, T_DHCID, 0);
	if (!updrec) goto error;

	updrec -> r_data   = ddns_dhcid -> buffer -> data;
	updrec -> r_size   = ddns_dhcid -> len;
	updrec -> r_opcode = DELETE;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Attempt to perform the update.
	 */
	result = minires_nupdate (&resolver_state, ISC_LIST_HEAD (updque));


	/*
	 * If the query fails, the updater MUST NOT delete the DNS name.  It
	 * may be that the host whose lease on the server has expired has moved
	 * to another network and obtained a lease from a different server,
	 * which has caused the client's A RR to be replaced. It may also be
	 * that some other client has been configured with a name that matches
	 * the name of the DHCP client, and the policy was that the last client
	 * to specify the name would get the name.  In this case, the DHCID RR
	 * will no longer match the updater's notion of the client-identity of
	 * the host pointed to by the DNS name.
	 *   -- "Interaction between DHCP and DNS"
	 */


	/* Fall through. */
  error:

	while (!ISC_LIST_EMPTY (updque)) {
		updrec = ISC_LIST_HEAD (updque);
		ISC_LIST_UNLINK (updque, updrec, r_link);
		minires_freeupdrec (updrec);
	}

	return result;
}


static ns_rcode ddns_remove_ptr (struct data_string *ddns_fwd_name,
				 struct data_string *ddns_rev_name,
				 struct data_string *ddns_dhcid)
{
	ns_updque updque;
	ns_updrec *updrec;
	ns_rcode result = SERVFAIL;

	/*
	 * When a lease expires or a DHCP client issues a DHCPRELEASE request,
	 * the DHCP server SHOULD delete the PTR RR that matches the DHCP
	 * binding, if one was successfully added. The server's update query
	 * SHOULD assert that the name in the PTR record matches the name of
	 * the client whose lease has expired or been released.
	 *   -- "Interaction between DHCP and DNS"
	 */

	ISC_LIST_INIT (updque);

	/*
	 * Delete appropriate PTR RR.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_rev_name -> data,
				   C_IN, T_PTR, 0);
	if (!updrec) goto error;

	updrec -> r_data   = ddns_fwd_name -> buffer -> data;
	updrec -> r_size   = ddns_fwd_name -> len;
	updrec -> r_opcode = DELETE;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Delete appropriate DHCID RR.
	 */
	updrec = minires_mkupdrec (S_UPDATE, ddns_rev_name -> data,
				   C_IN, T_DHCID, 0);
	if (!updrec) goto error;

	updrec -> r_data   = ddns_dhcid -> buffer -> data;
	updrec -> r_size   = ddns_dhcid -> len;
	updrec -> r_opcode = DELETE;

	ISC_LIST_APPEND (updque, updrec, r_link);


	/*
	 * Attempt to perform the update.
	 */
	result = minires_nupdate (&resolver_state, ISC_LIST_HEAD (updque));


	/* Fall through. */
  error:

	while (!ISC_LIST_EMPTY (updque)) {
		updrec = ISC_LIST_HEAD (updque);
		ISC_LIST_UNLINK (updque, updrec, r_link);
		minires_freeupdrec (updrec);
	}

	return result;
}


int ddns_updates (struct packet *packet,
		  struct lease *lease,
		  struct lease_state *state)
{
	unsigned long ddns_ttl = DEFAULT_DDNS_TTL;
	struct data_string ddns_hostname;
	struct data_string ddns_domainname;
	struct data_string ddns_fwd_name;
	struct data_string ddns_rev_name;
	struct data_string ddns_address;
	struct data_string ddns_dhcid;
	unsigned len;
	unsigned ddns_address_len = 0;
	struct data_string d1;
	struct option_cache *oc;
	int s1, s2;
	int result = 0;
	ns_rcode rcode1, rcode2;

	/* Can only cope with IPv4 addrs at the moment. */
	if (lease -> ip_addr . len != 4)
		return 0;


	memset (&ddns_hostname, 0, sizeof (ddns_hostname));
	memset (&ddns_domainname, 0, sizeof (ddns_domainname));
	memset (&ddns_fwd_name, 0, sizeof (ddns_fwd_name));
	memset (&ddns_rev_name, 0, sizeof (ddns_rev_name));
	memset (&ddns_address, 0, sizeof (ddns_address));
	memset (&ddns_dhcid, 0, sizeof (ddns_dhcid));


	/*
	 * Look up the RR TTL.
	 */
	ddns_ttl = DEFAULT_DDNS_TTL;
	if ((oc = lookup_option (&server_universe, state -> options,
				 SV_DDNS_TTL))) {
		if (evaluate_option_cache (&d1, packet, lease,
					   (struct client_state *)0,
					   packet -> options,
					   state -> options,
					   &lease -> scope, oc, MDL)) {
			if (d1.len == sizeof (u_int32_t))
				ddns_ttl = getULong (d1.data);
			data_string_forget (&d1, MDL);
		}
	}


	/*
	 * Look up the lease FQDN.
	 */
	s1 = s2 = 0;

	oc = lookup_option (&server_universe, state -> options,
			    SV_DDNS_HOST_NAME);
	if (oc)
		s1 = evaluate_option_cache (&ddns_hostname, packet, lease,
					    (struct client_state *)0,
					    packet -> options,
					    state -> options,
					    &lease -> scope, oc, MDL);

	oc = lookup_option (&server_universe, state -> options,
			    SV_DDNS_DOMAIN_NAME);
	if (oc)
		s2 = evaluate_option_cache (&ddns_domainname, packet, lease,
					    (struct client_state *)0,
					    packet -> options,
					    state -> options,
					    &lease -> scope, oc, MDL);

	if (s1 && s2) {
		buffer_allocate (&ddns_fwd_name.buffer,
				 ddns_hostname.len + ddns_domainname.len + 2,
				 MDL);
		if (ddns_fwd_name.buffer) {
			ddns_fwd_name.data = ddns_fwd_name.buffer -> data;
			data_string_append (&ddns_fwd_name, &ddns_hostname);
			ddns_fwd_name.buffer -> data [ddns_fwd_name.len] = '.';
			ddns_fwd_name.len++;
			data_string_append (&ddns_fwd_name, &ddns_domainname);
			ddns_fwd_name.buffer -> data [ddns_fwd_name.len] ='\0';
			ddns_fwd_name.terminated = 1;
		}
	}


	/*
	 * Look up the lease IP address (as a string).
	 */
	/* XXX.XXX.XXX.XXX\0 = 16 characters. */
	buffer_allocate (&ddns_address.buffer, 16, MDL);
			 
#ifndef NO_SNPRINTF
	snprintf (ddns_address.buffer -> data, 16,
		  "%d.%d.%d.%d",
		  lease -> ip_addr . iabuf[0],
		  lease -> ip_addr . iabuf[1],
		  lease -> ip_addr . iabuf[2],
		  lease -> ip_addr . iabuf[3]);
#else
	sprintf (ddns_address.buffer -> data,
		 "%d.%d.%d.%d",
		 lease -> ip_addr . iabuf[0],
		 lease -> ip_addr . iabuf[1],
		 lease -> ip_addr . iabuf[2],
		 lease -> ip_addr . iabuf[3]);
#endif
	ddns_address.data = ddns_address.buffer -> data;
	ddns_address.len = strlen (ddns_address.data);
	ddns_address.terminated = 1;


	/*
	 * Look up the reverse IP name.
	 */
	oc = lookup_option (&server_universe, state -> options,
			    SV_DDNS_REV_DOMAIN_NAME);
	if (oc)
		s1 = evaluate_option_cache (&d1, packet, lease,
					    (struct client_state *)0,
					    packet -> options,
					    state -> options,
					    &lease -> scope, oc, MDL);
	
	if (oc && s1) {
		/* Buffer length:
		   XXX.XXX.XXX.XXX.<ddns-rev-domain-name>\0 */
		buffer_allocate (&ddns_rev_name.buffer,
				 d1.len + 17, MDL);
		if (ddns_rev_name.buffer) {
			ddns_rev_name.data = ddns_rev_name.buffer -> data;
#ifndef NO_SNPRINTF
			snprintf (ddns_rev_name.buffer -> data, 17,
				  "%d.%d.%d.%d.",
				  lease -> ip_addr . iabuf[3],
				  lease -> ip_addr . iabuf[2],
				  lease -> ip_addr . iabuf[1],
				  lease -> ip_addr . iabuf[0]);
#else
			sprintf (ddns_rev_name.buffer -> data,
				 "%d.%d.%d.%d.",
				 lease -> ip_addr . iabuf[3],
				 lease -> ip_addr . iabuf[2],
				 lease -> ip_addr . iabuf[1],
				 lease -> ip_addr . iabuf[0]);
#endif
			ddns_rev_name.len = strlen (ddns_rev_name.data);
			data_string_append (&ddns_rev_name, &d1);
			ddns_rev_name.buffer -> data [ddns_rev_name.len] ='\0';
			ddns_rev_name.terminated = 1;
		}
		
		data_string_forget (&d1, MDL);
	}


	/*
	 * Look up the DHCID value.  (Should this be cached in the lease?)
	 */
	memset (&ddns_dhcid, 0, sizeof ddns_dhcid);
	get_dhcid (&ddns_dhcid, lease);


	/*
	 * Start the resolver, if necessary.
	 */
	if (!resolver_inited) {
		minires_ninit (&resolver_state);
		resolver_inited = 1;
	}


	/*
	 * Perform updates.
	 */
	if (ddns_fwd_name.len && ddns_address.len && ddns_dhcid.len)
		rcode1 = ddns_update_a(&ddns_fwd_name, &ddns_address,
				       &ddns_dhcid, ddns_ttl);
	
	if (ddns_fwd_name.len && ddns_rev_name.len && ddns_dhcid.len)
		rcode2 = ddns_update_ptr(&ddns_fwd_name, &ddns_rev_name,
					 &ddns_dhcid, ddns_ttl);

	/* minires_update() can return -1 under certain circumstances. */
	if (rcode1 == -1)
		rcode1 = SERVFAIL;
	if (rcode2 == -1)
		rcode2 = SERVFAIL;

	if (rcode1 == NOERROR || rcode2 == NOERROR) {
		bind_ds_value (&lease -> scope, "ddns-fwd-name",
			       &ddns_fwd_name);
		bind_ds_value (&lease -> scope, "ddns-dhcid",
			       &ddns_dhcid);
	}
	if (rcode1 == NOERROR) {
		bind_ds_value (&lease -> scope, "ddns-address",
			       &ddns_address);
	}
	if (rcode2 == NOERROR) {
		bind_ds_value (&lease -> scope, "ddns-rev-name",
			       &ddns_rev_name);
	}


	/*
	 * If the client sent us the FQDN option, respond appropriately.
	 */
	oc = lookup_option (&fqdn_universe, packet -> options,
			    FQDN_SERVER_UPDATE);
	if (oc) {
		oc -> data.buffer -> data[0] = 1;
	}

	oc = lookup_option (&fqdn_universe, packet -> options,
			    FQDN_NO_CLIENT_UPDATE);
	if (oc) {
		oc -> data.buffer -> data[0] = 1;
	}

	oc = lookup_option (&fqdn_universe, packet -> options,
			    FQDN_RCODE1);
	if (oc) {
		oc -> data.buffer -> data[0] = rcode1;
	}

	oc = lookup_option (&fqdn_universe, packet -> options,
			    FQDN_RCODE2);
	if (oc) {
		oc -> data.buffer -> data[0] = rcode2;
	}

	oc = lookup_option (&fqdn_universe, packet -> options,
			    FQDN_HOSTNAME);
	if (oc && ddns_hostname.buffer) {
		data_string_forget (&oc -> data, MDL);
		data_string_copy (&oc -> data, &ddns_hostname, MDL);
	}

	oc = lookup_option (&fqdn_universe, packet -> options,
			    FQDN_DOMAINNAME);
	if (oc && ddns_hostname.buffer) {
		data_string_forget (&oc -> data, MDL);
		data_string_copy (&oc -> data, &ddns_domainname, MDL);
	}


	/*
	 * Final cleanup.
	 */
	data_string_forget (&ddns_hostname, MDL);
	data_string_forget (&ddns_domainname, MDL);
	data_string_forget (&ddns_fwd_name, MDL);
	data_string_forget (&ddns_rev_name, MDL);
	data_string_forget (&ddns_address, MDL);
	data_string_forget (&ddns_dhcid, MDL);

	return rcode1 == NOERROR || rcode2 == NOERROR;
}


int ddns_removals(struct lease *lease) {
	struct data_string ddns_fwd_name;
	struct data_string ddns_rev_name;
	struct data_string ddns_address;
	struct data_string ddns_dhcid;
	ns_rcode rcode;

	/* No scope implies that DDNS has not been performed for this lease. */
	if (!lease -> scope)
		return 1;


	/*
	 * Look up stored names.
	 */
	memset (&ddns_fwd_name, 0, sizeof (ddns_fwd_name));
	memset (&ddns_rev_name, 0, sizeof (ddns_rev_name));
	memset (&ddns_address, 0, sizeof (ddns_address));
	memset (&ddns_dhcid, 0, sizeof (ddns_dhcid));

	find_bound_string (&ddns_fwd_name, lease -> scope, "ddns-fwd-name");
	find_bound_string (&ddns_rev_name, lease -> scope, "ddns-rev-name");
	find_bound_string (&ddns_address, lease -> scope, "ddns-address");
	find_bound_string (&ddns_dhcid, lease -> scope, "ddns-dhcid");


	/*
	 * Start the resolver, if necessary.
	 */
	if (!resolver_inited) {
		minires_ninit (&resolver_state);
		resolver_inited = 1;
	}


	/*
	 * Perform removals.
	 */
	if (ddns_fwd_name.len && ddns_address.len && ddns_dhcid.len) {
		rcode = ddns_remove_a (&ddns_fwd_name, &ddns_address,
				       &ddns_dhcid);
	}
	if (ddns_fwd_name.len && ddns_rev_name.len && ddns_dhcid.len) {
		rcode = ddns_remove_ptr(&ddns_fwd_name, &ddns_rev_name,
					&ddns_dhcid);
	}


	data_string_forget (&ddns_fwd_name, MDL);
	data_string_forget (&ddns_rev_name, MDL);
	data_string_forget (&ddns_address, MDL);
	data_string_forget (&ddns_dhcid, MDL);


	return 1;
}


#endif /* NSUPDATE */
