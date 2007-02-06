/* dhc6.c - DHCPv6 client routines. */

/*
 * Copyright (c) 2006 by Internet Systems Consortium, Inc. ("ISC")
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
 *   http://www.isc.org/
 */

#ifndef lint
static char ocopyright[] =
"$Id: dhc6.c,v 1.1.4.6 2007/02/06 22:10:47 dhankins Exp $ Copyright (c) 2006 Internet Systems Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

struct sockaddr_in6 DHCPv6DestAddr;
struct option *ia_na_option = NULL;
struct option *ia_addr_option = NULL;

static void dhc6_lease_destroy(struct dhc6_lease *lease, char *file, int line);
static isc_result_t dhc6_parse_ia_na(struct dhc6_ia **pia,
				     struct packet *packet,
				     struct option_state *options);
static isc_result_t dhc6_parse_addrs(struct dhc6_addr **paddr,
				     struct packet *packet,
				     struct option_state *options);
void init_handler(struct packet *packet, struct client_state *client);
void do_init6(void *input);
void reply_handler(struct packet *packet, struct client_state *client);
static isc_result_t dhc6_add_ia(struct client_state *client,
				struct data_string *packet,
				struct dhc6_lease *lease);
void do_select6(void *input);
void do_refresh6(void *input);
static void start_bound(struct client_state *client);
void bound_handler(struct packet *packet, struct client_state *client);
void start_renew6(void *input);
void start_rebind6(void *input);
void do_depref(void *input);
void do_expire(void *input);
static void make_client6_options(struct client_state *client,
				 struct option_state **op,
				 struct dhc6_lease *lease);
static void script_write_params6(struct client_state *client, char *prefix,
				 struct option_state *options);

/* For now, simply because we do not retain this information statefully,
 * the DUID is simply the first interface's hardware address.
 */
void
form_duid(struct data_string *duid, char *file, int line)
{
	struct interface_info *ip;
	int len;

	/* For now, just use the first interface on the list. */
	ip = interfaces;

	if (ip == NULL)
		log_fatal("Impossible condition at %s:%d.", MDL);

	if ((ip->hw_address.hlen == 0) ||
	    (ip->hw_address.hlen > sizeof(ip->hw_address.hbuf)))
		log_fatal("Impossible hardware address length at %s:%d.", MDL);

	len = 4 + (ip->hw_address.hlen - 1);
	if (!buffer_allocate(&duid->buffer, len, MDL))
		log_fatal("no memory for DUID!");
	duid->data = duid->buffer->data;
	duid->len = len;

	/* Basic Link Local Address type of DUID. */
	putUShort(duid->buffer->data, DUID_LL);
	putUShort(duid->buffer->data + 2, ip->hw_address.hbuf[0]);
	memcpy(duid->buffer->data + 4, ip->hw_address.hbuf + 1,
	       ip->hw_address.hlen - 1);
}

/* Assign DHCPv6 port numbers as a client.
 */
void
dhcpv6_client_assignments(void)
{
	struct servent *ent;
	unsigned code;

	if (local_port == 0) {
		ent = getservbyname("dhcpv6-client", "udp");
		if (ent == NULL)
			local_port = htons(546);
		else
			local_port = ent->s_port;
	}

	if (remote_port == 0) {
		ent = getservbyname("dhcpv6-server", "udp");
		if (ent == NULL)
			remote_port = htons(547);
		else
			remote_port = ent->s_port;
	}

	memset(&DHCPv6DestAddr, 0, sizeof(DHCPv6DestAddr));
	DHCPv6DestAddr.sin6_family = AF_INET6;
	DHCPv6DestAddr.sin6_port = remote_port;
	inet_pton(AF_INET6, All_DHCP_Relay_Agents_and_Servers,
		  &DHCPv6DestAddr.sin6_addr);

	code = D6O_IA_NA;
	if (!option_code_hash_lookup(&ia_na_option, dhcpv6_universe.code_hash,
				     &code, 0, MDL))
		log_fatal("Unable to find the IA_NA option definition.");

	code = D6O_IAADDR;
	if (!option_code_hash_lookup(&ia_addr_option, dhcpv6_universe.code_hash,
				     &code, 0, MDL))
		log_fatal("Unable to find the IAADDR option definition.");

#ifndef __CYGWIN32__ /* XXX */
	endservent();
#endif
}

/* Instead of implementing RFC3315 RAND (section 14) as a float "between"
 * -0.1 and 0.1 non-inclusive, we implement it as an integer.
 *
 * The result is expected to follow this table:
 *
 *		split range answer
 *		    - ERROR -		      base <= 0
 *		0	1   0..0	 1 <= base <= 10
 *		1	3  -1..1	11 <= base <= 20
 *		2	5  -2..2	21 <= base <= 30
 *		3	7  -3..3	31 <= base <= 40
 *		...
 *
 * XXX: For this to make sense, we really need to do timing on a
 * XXX: usec scale...we currently can assume zero for any value less than
 * XXX: 11, which are very common in early stages of transmission for most
 * XXX: messages.
 */
static TIME
dhc6_rand(TIME base)
{
	TIME rval;
	TIME range;
	TIME split;

	/* A zero or less timeout is a bad thing...we don't want to
	 * DHCP-flood anyone.
	 */
	if (base <= 0)
		log_fatal("Impossible condition at %s:%d.", MDL);

	/* The first thing we do is count how many random integers we want
	 * in either direction (best thought of as the maximum negative
	 * integer, as we will subtract this potentially from a random 0).
	 */
	split = (base - 1) / 10;

	/* Don't bother with the rest of the math if we know we'll get 0. */
	if (split == 0)
		return 0;

	/* Then we count the total number of integers in this set.  This
	 * is twice the number of integers in positive and negative
	 * directions, plus zero (-1, 0, 1 is 3, -2..2 adds 2 to 5, so forth).
	 */
	range = (split * 2) + 1;

	/* Take a random number from [0..(range-1)]. */
	rval = random();
	rval %= range;

	/* Offset it to uncover potential negative values. */
	rval -= split;

	return rval;
}

/* Get a new dhcpv6_transaction_id and store it to the client state. */
static void
dhc6_new_xid(struct client_state *client)
{
	int xid;

	if (RAND_MAX >= 0x00ffffff)
		xid = random();
	else if (RAND_MAX >= 0x0000ffff)
		xid = (random() << 16) | random();
	else
		xid = (random() << 24) | (random() << 16) | random();

	client->dhcpv6_transaction_id[0] = (xid >> 16) & 0xff;
	client->dhcpv6_transaction_id[1] = (xid >>  8) & 0xff;
	client->dhcpv6_transaction_id[2] =  xid        & 0xff;
}

/* Set RT from initial RT. */
static void
dhc6_retrans_init(struct client_state *client)
{
	client->start_time = cur_time;
	client->txcount = 0;
	client->RT = client->IRT + dhc6_rand(client->IRT);
}

/* Advance the DHCPv6 retransmission state once. */
static void
dhc6_retrans_advance(struct client_state *client)
{
	TIME elapsed;

	elapsed = cur_time - client->start_time;
	/* retrans_advance is called after consuming client->RT. */
	elapsed += client->RT;

        /* RT for each subsequent message transmission is based on the previous
         * value of RT:
         *
         *    RT = 2*RTprev + RAND*RTprev
         */
        client->RT += client->RT + dhc6_rand(client->RT);

        /* MRT specifies an upper bound on the value of RT (disregarding the
         * randomization added by the use of RAND).  If MRT has a value of 0,
         * there is no upper limit on the value of RT.  Otherwise:
         *
         *    if (RT > MRT)
         *       RT = MRT + RAND*MRT
         */
        if ((client->MRT != 0) && (client->RT > client->MRT))
                client->RT = client->MRT + dhc6_rand(client->MRT);

	/* Further, if there's an MRD, we should wake up upon reaching
	 * the MRD rather than at some point after it.
	 */
	if ((client->MRD != 0) && ((elapsed + client->RT) > client->MRD)) {
		client->RT = (client->start_time + client->MRD) - cur_time;
	}

	client->txcount++;
}

/* Quick validation of DHCPv6 ADVERTISE packet contents. */
static int
valid_reply(struct packet *packet, struct client_state *client)
{
	struct data_string sid, cid;
	struct option_cache *oc;
	int rval = ISC_TRUE;

	memset(&sid, 0, sizeof(sid));
	memset(&cid, 0, sizeof(cid));

	if (!lookup_option(&dhcpv6_universe, packet->options, D6O_SERVERID)) {
		log_error("Advertise without a server identifier received.");
		rval = ISC_FALSE;
	}

	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_CLIENTID);
	if (!oc ||
	    !evaluate_option_cache(&sid, packet, NULL, client, packet->options,
				   client->sent_options, &global_scope, oc,
				   MDL)) {
		log_error("Advertise without a client identifier.");
		rval = ISC_FALSE;
	}

	oc = lookup_option(&dhcpv6_universe, client->sent_options,
			   D6O_CLIENTID);
	if (!oc ||
	    !evaluate_option_cache(&cid, packet, NULL, client,
				   client->sent_options, NULL, &global_scope,
				   oc, MDL)) {
		log_error("Local client identifier is missing!");
		rval = ISC_FALSE;
	}

	if (sid.len == 0 ||
	    sid.len != cid.len ||
	    memcmp(sid.data, cid.data, sid.len)) {
		log_error("Advertise with matching transaction ID, but "
			  "mismatching client id.");
		rval = ISC_FALSE;
	}

	return rval;
}

/* Form a DHCPv6 lease structure based upon packet contents.  Creates and
 * populates IA's and any IAADDR's they contain.
 */
static struct dhc6_lease *
dhc6_leaseify(struct packet *packet)
{
	struct data_string ds;
	struct dhc6_lease *lease;
	struct option_cache *oc;

	lease = dmalloc(sizeof(*lease), MDL);
	if (lease == NULL) {
		log_error("Out of memory for v6 lease structure.");
		return NULL;
	}

	memcpy(lease->dhcpv6_transaction_id, packet->dhcpv6_transaction_id, 3);
	option_state_reference(&lease->options, packet->options, MDL);

	memset(&ds, 0, sizeof(ds));

	/* Determine preference (default zero). */
	oc = lookup_option(&dhcpv6_universe, lease->options, D6O_PREFERENCE);
	if (oc &&
	    evaluate_option_cache(&ds, packet, NULL, NULL, lease->options,
				  NULL, &global_scope, oc, MDL)) {
		if (ds.len != 1) {
			log_error("Invalid length of DHCPv6 Preference option "
				  "(%d != 1)", ds.len);
			dhc6_lease_destroy(lease, MDL);
			return NULL;
		} else {
			lease->pref = ds.data[0];
			log_debug("RCV:  X-- Preference %u.",
				  (unsigned)lease->pref);
		}

		data_string_forget(&ds, MDL);
	}

	/* Dig into recursive DHCPv6 pockets for IA_NA and contained IAADDR
	 * options.
	 */
	if (dhc6_parse_ia_na(&lease->bindings, packet,
			     lease->options) != ISC_R_SUCCESS) {
		/* Error conditions are logged by the caller. */
		dhc6_lease_destroy(lease, MDL);
		return NULL;
	}

	/* This is last because in the future we may want to make a different
	 * key based upon additional information from the packet (we may need
	 * to allow multiple leases in one client state per server, but we're
	 * not sure based on what additional keys now).
	 */
	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_SERVERID);
	if (!evaluate_option_cache(&lease->server_id, packet, NULL, NULL,
				   lease->options, NULL, &global_scope,
				   oc, MDL) ||
	    lease->server_id.len == 0) {
		/* This should be impossible due to validation checks earlier.
		 */
		log_error("Invalid SERVERID option cache.");
		dhc6_lease_destroy(lease, MDL);
		return NULL;
	} else {
		log_debug("RCV:  X-- Server ID: %s",
			  print_hex_1(lease->server_id.len,
				      lease->server_id.data, 52));
	}

	return lease;
}

static isc_result_t
dhc6_parse_ia_na(struct dhc6_ia **pia, struct packet *packet,
		 struct option_state *options)
{
	struct data_string ds;
	struct dhc6_ia *ia;
	struct option_cache *oc;
	isc_result_t result;

	memset(&ds, 0, sizeof(ds));

	oc = lookup_option(&dhcpv6_universe, options, D6O_IA_NA);
	while(oc != NULL) {
		ia = dmalloc(sizeof(*ia), MDL);
		if (ia == NULL) {
			log_error("Out of memory allocating IA_NA structure.");
			return ISC_R_NOMEMORY;
		} else if (evaluate_option_cache(&ds, packet, NULL, NULL,
						 options, NULL,
						 &global_scope, oc, MDL) &&
			   ds.len >= 12) {
			memcpy(ia->iaid, ds.data, 4);
			ia->starts = cur_time;
			ia->renew = getULong(ds.data + 4);
			ia->rebind = getULong(ds.data + 8);

			log_debug("RCV:  X-- IA_NA %s",
				  print_hex_1(4, ia->iaid, 59));
			/* XXX: This should be the printed time I think. */
			log_debug("RCV:  | X-- starts %u",
				  (unsigned)ia->starts);
			log_debug("RCV:  | X-- renew  +%u", ia->renew);
			log_debug("RCV:  | X-- rebind +%u", ia->rebind);

			if (ds.len > 12) {
				log_debug("RCV:  | X-- [Options]");

				if (!option_state_allocate(&ia->options,
							   MDL)) {
					log_error("Out of memory allocating "
						  "IA option state.");
					dfree(ia, MDL);
					data_string_forget(&ds, MDL);
					return ISC_R_NOMEMORY;
				}

				if (!parse_option_buffer(ia->options,
							 ds.data + 12,
							 ds.len - 12,
							 &dhcpv6_universe)) {
					log_error("Corrupt IA_NA options.");
					option_state_dereference(&ia->options,
								 MDL);
					dfree(ia, MDL);
					data_string_forget(&ds, MDL);
					return ISC_R_BADPARSE;
				}
			}
			data_string_forget(&ds, MDL);

			if (ia->options != NULL) {
				result = dhc6_parse_addrs(&ia->addrs, packet,
							  ia->options);
				if (result != ISC_R_SUCCESS) {
					option_state_dereference(&ia->options,
								 MDL);
					dfree(ia, MDL);
					return result;
				}
			}

			*pia = ia;
			pia = &ia->next;
		} else {
			log_error("Invalid IA_NA option cache.");
			dfree(ia, MDL);
			if (ds.len != 0)
				data_string_forget(&ds, MDL);
			return ISC_R_UNEXPECTED;
		}

		oc = oc->next;
	}

	return ISC_R_SUCCESS;
}


static isc_result_t
dhc6_parse_addrs(struct dhc6_addr **paddr, struct packet *packet,
		 struct option_state *options)
{
	struct data_string ds;
	struct option_cache *oc;
	struct dhc6_addr *addr;

	memset(&ds, 0, sizeof(ds));

	oc = lookup_option(&dhcpv6_universe, options, D6O_IAADDR);
	while(oc != NULL) {
		addr = dmalloc(sizeof(*addr), MDL);
		if (addr == NULL) {
			log_error("Out of memory allocating "
				  "address structure.");
			return ISC_R_NOMEMORY;
		} else if (evaluate_option_cache(&ds, packet, NULL, NULL,
						 options, NULL, &global_scope,
						 oc, MDL) &&
			   (ds.len >= 24)) {

			addr->address.len = 16;
			memcpy(addr->address.iabuf, ds.data, 16);
			addr->preferred_life = getULong(ds.data + 16);
			addr->max_life = getULong(ds.data + 20);

			log_debug("RCV:  | | X-- IAADDR %s",
				  piaddr(addr->address));
			log_debug("RCV:  | | | X-- Preferred lifetime %u.",
				  addr->preferred_life);
			log_debug("RCV:  | | | X-- Max lifetime %u.",
				  addr->max_life);

			/* Fortunately this is the last recursion in the
			 * protocol.
			 */
			if (ds.len > 24) {
				if (!option_state_allocate(&addr->options,
							   MDL)) {
					log_error("Out of memory allocating "
						  "IAADDR option state.");
					dfree(addr, MDL);
					data_string_forget(&ds, MDL);
					return ISC_R_NOMEMORY;
				}

				if (!parse_option_buffer(addr->options,
							 ds.data + 24,
							 ds.len - 24,
							 &dhcpv6_universe)) {
					log_error("Corrupt IAADDR options.");
					option_state_dereference(&addr->options,
								 MDL);
					dfree(addr, MDL);
					data_string_forget(&ds, MDL);
					return ISC_R_BADPARSE;
				}
			}

			if (addr->options != NULL)
				log_debug("RCV:  | | | X-- "
					  "[Options]");

			data_string_forget(&ds, MDL);

			*paddr = addr;
			paddr = &addr->next;
		} else {
			log_error("Invalid IAADDR option cache.");
			dfree(addr, MDL);
			if (ds.len != 0)
				data_string_forget(&ds, MDL);
			return ISC_R_UNEXPECTED;
		}

		oc = oc->next;
	}

	return ISC_R_SUCCESS;
}

/* Clean up a lease object and deallocate all its parts. */
static void
dhc6_lease_destroy(struct dhc6_lease *lease, char *file, int line)
{
	struct dhc6_addr *addr, *naddr;
	struct dhc6_ia *ia, *nia;

	/* no-op */
	if (lease == NULL)
		return;

	if (lease->server_id.len != 0)
		data_string_forget(&lease->server_id, file, line);

	for (ia = lease->bindings ; ia != NULL ; ia = nia) {
		for (addr = ia->addrs ; addr != NULL ; addr = naddr) {
			if (addr->options != NULL)
				option_state_dereference(&addr->options,
							 file, line);

			naddr = addr->next;
			dfree(addr, file, line);
		}

		if (ia->options != NULL)
			option_state_dereference(&ia->options, file, line);

		nia = ia->next;
		dfree(ia, file, line);
	}

	if (lease->options != NULL)
		option_state_dereference(&lease->options, file, line);

	dfree(lease, file, line);
}

/* For a given lease, insert it into the tail of the lease list.  Upon
 * finding a duplicate by server id, remove it and take over its position.
 */
static void
insert_lease(struct dhc6_lease **head, struct dhc6_lease *new)
{
	while (*head != NULL) {
		if ((*head)->server_id.len == new->server_id.len &&
		    memcmp((*head)->server_id.data, new->server_id.data,
			   new->server_id.len) == 0) {
			new->next = (*head)->next;
			dhc6_lease_destroy(*head, MDL);
			break;
		}

		head= &(*head)->next;
	}

	*head = new;
	return;
}

/* start_init6() kicks off the process, transmitting a packet and
 * scheduling a retransmission event.
 */
void
start_init6(struct client_state *client)
{
	log_debug("PRC: Soliciting for leases (INIT).");
	client->state = S_INIT;

	/* Fetch a 24-bit transaction ID. */
	dhc6_new_xid(client);

	/* Initialize timers, RFC3315 section 17.1.2. */
	client->IRT = SOL_TIMEOUT;
	client->MRT = SOL_MAX_RT;
	client->MRC = 0;
	client->MRD = 0;

	dhc6_retrans_init(client);
	/* RFC3315 section 17.1.2 goes out of its way:
	 *
	 * Also, the first RT MUST be selected to be strictly greater than IRT
	 * by choosing RAND to be strictly greater than 0.
	 */
	if (client->RT <= client->IRT)
		client->RT = client->IRT + 1;

	client->v6_handler = init_handler;

	/* RFC3315 section 17.1.2 says we MUST start the first packet
	 * between 0 and SOL_MAX_DELAY seconds.  The good news is
	 * SOL_MAX_DELAY is 1.
	 */
	add_timeout(cur_time + (random() % SOL_MAX_DELAY), do_init6, client,
		    NULL, NULL);
}

/* do_init6() marshals and transmits a solicit.
 */
void
do_init6(void *input)
{
	struct client_state *client;
	struct data_string ds;
	struct data_string ia;
	struct option_cache *oc;
	TIME elapsed;
	u_int32_t t1, t2;
	int idx, len, send_ret, code;

	client = input;

	/* In RFC3315 section 17.1.2, the retransmission timer is
	 * used as the selecting timer.
	 */
	if (client->advertised_leases != NULL) {
		start_selecting6(client);
		return;
	}

	if ((client->MRC != 0) && (client->txcount > client->MRC)) {
		log_info("Max retransmission count exceeded.");
		return;
	}

	elapsed = cur_time - client->start_time;
	if ((client->MRD != 0) && (elapsed > client->MRD)) {
		log_info("Max retransmission duration exceeded.");
		return;
	}

	memset(&ds, 0, sizeof(ds));
	if (!buffer_allocate(&ds.buffer, 4, MDL)) {
		log_error("Unable to allocate memory for SOLICIT.");
		return;
	}
	ds.data = ds.buffer->data;
	ds.len = 4;

	ds.buffer->data[0] = DHCPV6_SOLICIT;
	memcpy(ds.buffer->data + 1, client->dhcpv6_transaction_id, 3);

	/* Form an elapsed option. */
	if ((elapsed < 0) || (elapsed > 655))
		client->elapsed = 0xffff;
	else
		client->elapsed = elapsed * 100;

	log_debug("XMT: Forming Solicit, %u ms elapsed.",
		  (unsigned)client->elapsed);

	client->elapsed = htons(client->elapsed);

	make_client6_options(client, &client->sent_options, NULL);

	/* Fetch any configured 'sent' options (includes DUID) in wire format.
	 */
	dhcpv6_universe.encapsulate(&ds, NULL, NULL, client,
				    NULL, client->sent_options, &global_scope,
				    &dhcpv6_universe);

	/* Append an IA_NA. */
	/* XXX: maybe the IA_NA('s) should be put into the sent_options
	 * cache.  They'd have to be pulled down as they also contain
	 * different option caches in the same universe...
	 */
	memset(&ia, 0, sizeof(ia));
	if (!buffer_allocate(&ia.buffer, 12, MDL)) {
		log_error("Unable to allocate memory for IA_NA.");
		data_string_forget(&ds, MDL);
		return;
	}
	ia.data = ia.buffer->data;
	ia.len = 12;

	/* A simple IAID is the last 4 bytes of the hardware address. */
	if (client->interface->hw_address.hlen > 4) {
		idx = client->interface->hw_address.hlen - 4;
		len = 4;
	} else {
		idx = 0;
		len = client->interface->hw_address.hlen;
	}
	memcpy(ia.buffer->data, client->interface->hw_address.hbuf + idx, len);

	t1 = client->config->requested_lease / 2;
	t2 = t1 + (t1 / 2);
	putULong(ia.buffer->data+4, t1);
	putULong(ia.buffer->data+8, t2);

	log_debug("XMT:  X-- IA_NA %s", print_hex_1(4, ia.buffer->data, 55));
	log_debug("XMT:    X-- Request renew in  +%u", (unsigned)t1);
	log_debug("XMT:    X-- Request rebind in +%u", (unsigned)t2);

	append_option(&ds, &dhcpv6_universe, ia_na_option, &ia);
	data_string_forget(&ia, MDL);

	/* Transmit and wait. */

	log_info("XMT: Solicit on %s, interval %ld",
		 client->name ? client->name : client->interface->name,
		 client->RT);

	send_ret = send_packet6(client->interface,
				ds.data, ds.len, &DHCPv6DestAddr);
	if (send_ret != ds.len) {
		log_error("dhc6: send_packet6() sent %d of %d bytes",
			  send_ret, ds.len);
	}

	data_string_forget(&ds, MDL);

	add_timeout(cur_time + client->RT, do_init6, client, NULL, NULL);

	dhc6_retrans_advance(client);
}

/* status_log() just puts a status code into displayable form and logs it
 * to info level.
 */
static void
status_log(int code, char *scope, const char *additional, int len)
{
	char *msg = NULL;

	switch(code) {
	      case STATUS_Success:
		msg = "Succes";
		break;

	      case STATUS_UnspecFail:
		msg = "UnspecFail";
		break;
	      case STATUS_NoAddrsAvail:
		msg = "NoAddrsAvail";
		break;

	      case STATUS_NoBinding:
		msg = "NoBinding";
		break;

	      case STATUS_NotOnLink:
		msg = "NotOnLink";
		break;

	      case STATUS_UseMulticast:
		msg = "UseMulticast";
		break;

	      default:
		msg = "UNKNOWN";
		break;
	}

	if (len > 0)
		log_info("%s status code %s: %s", scope, msg,
			 print_hex_1(len, additional, 50));
	else
		log_info("%s status code %s.", scope, msg);
}

/* Look for status codes that are not SUCCESS status.
 *
 * XXX: We probably should instrument precisely what status code has been
 * found back to the caller.
 */
static isc_result_t
dhc6_check_status_code(struct option_state *options, char *scope)
{
	struct option_cache *oc;
	struct data_string ds;
	isc_result_t rval = ISC_R_SUCCESS;
	int code;

	memset(&ds, 0, sizeof(ds));

	oc = lookup_option(&dhcpv6_universe, options, D6O_STATUS_CODE);
	if (oc &&
	    evaluate_option_cache(&ds, NULL, NULL, NULL, options,
				  NULL, &global_scope, oc, MDL)) {
		if (ds.len < 2) {
			log_error("Invalid status code length %d.", ds.len);
			rval = ISC_R_FAILURE;
		} else {
			code = getUShort(ds.data);

			if (code != STATUS_Success) {
				status_log(code, scope, ds.data + 2,
					   ds.len - 2);
				rval = ISC_R_FAILURE;
			}
		}

		data_string_forget(&ds, MDL);
	}

	return rval;
}

/* Look in the packet, any IA's, and any IAADDR's within those IA's to find
 * status code options that are not SUCCESS.
 */
static isc_result_t
dhc6_check_all_status_codes(struct dhc6_lease *lease) {
	struct data_string ds;
	struct dhc6_ia *ia;
	struct dhc6_addr *addr;
	isc_result_t rval = ISC_R_SUCCESS;
	int code;

	memset(&ds, 0, sizeof(ds));

	if (dhc6_check_status_code(lease->options, "packet") != ISC_R_SUCCESS)
		rval = ISC_R_FAILURE;

	for (ia = lease->bindings ; ia != NULL ; ia = ia->next) {
		if (dhc6_check_status_code(ia->options,
					   "IA_NA") != ISC_R_SUCCESS)
			rval = ISC_R_FAILURE;

		for (addr = ia->addrs ; addr != NULL ; addr = addr->next) {
			if (dhc6_check_status_code(addr->options,
						   "IAADDR") != ISC_R_SUCCESS)
				rval = ISC_R_FAILURE;
		}
	}

	return rval;
}

/* While in init state, we only collect advertisements.  If there happens
 * to be an advertisement with a preference option of 255, that's an
 * automatic exit.  Otherwise, we collect advertisements until our timeout
 * expires (client->RT).
 */
void
init_handler(struct packet *packet, struct client_state *client)
{
	struct dhc6_lease *lease, **idx;

	/* In INIT state, we send solicits, we only expect to get
	 * advertises (we don't support rapid commit yet).
	 */
	if (packet->dhcpv6_msg_type != DHCPV6_ADVERTISE)
		return;

	/* RFC3315 section 15.3 validation (same as 15.10 since we
	 * always include a client id).
	 */
	if (!valid_reply(packet, client)) {
		log_error("Invalid Advertise - rejecting.");
		return;
	}

	lease = dhc6_leaseify(packet);

	if (dhc6_check_all_status_codes(lease) != ISC_R_SUCCESS) {
		dhc6_lease_destroy(lease, MDL);
		return;
	}

	insert_lease(&client->advertised_leases, lease);

	/* According to RFC3315 section 17.1.2, the client MUST wait for
	 * the first RT before selecting a lease.  But on the 400th RT,
	 * we dont' want to wait the full timeout if we finally get an
	 * advertise.  We could probably wait a second, but ohwell,
	 * RFC3315 doesn't say so.
	 *
	 * If the lease is highest possible preference, 255, RFC3315 claims
	 * we should continue immediately even on the first RT.
	 */
	if ((client->txcount > 1) || (lease->pref == 255)) {
		log_debug("RCV:  Advertisement immediately selected.");
		cancel_timeout(do_init6, client);
		start_selecting6(client);
	} else
		log_debug("RCV:  Advertisement recorded.");
}

/* Find the 'best' lease in the cache of advertised leases (usually).  In
 * strict terms, the DHCPv6 Preference Option is the way to decide this.
 * Higher values are more preferrential.  Absence of the option defaults to
 * zero.  In the event two leases have the same preference, however, break
 * the tie by comparing the server id's and selecting the lower value.
 */
static struct dhc6_lease *
dhc6_best_lease(struct dhc6_lease **head)
{
	struct dhc6_lease **rpos, *rval, **candp, *cand;

	if (head == NULL || *head == NULL)
		return NULL;

	log_debug("PRC: Considering best lease.");
	log_debug("PRC:  X-- Initial candidate %s (%u).",
		  print_hex_1((*head)->server_id.len,
			      (*head)->server_id.data, 40),
		  (unsigned)(*head)->pref);

	rpos = head;
	rval = *rpos;
	candp = &rval->next;
	cand = *candp;

	for (; cand != NULL ; candp = &cand->next, cand = *candp) {
		log_debug("PRC:  X-- Candidate %s (%u).",
			  print_hex_1(cand->server_id.len,
				      cand->server_id.data, 48),
			  (unsigned)cand->pref);

		/* Reject lower (but not equal or higher) pref's. */
		if (cand->pref < rval->pref) {
			log_debug("PRC:  | X-- Rejected, lower preference.");
			continue;
		}

		/* If the preference is higher that's an immediate win.
		 * If the preference is therefore equal, break the tie
		 * with the lowest digital server identifier.
		 *
		 * Since server id's are unique in this list, there is
		 * no further tie to break.
		 */
		if (cand->pref > rval->pref) {
			log_debug("PRC:  | X-- Selected, higher preference.");
			rpos = candp;
			rval = cand;
		} else if ((cand->server_id.len < rval->server_id.len) ||
			   ((cand->server_id.len == rval->server_id.len) &&
			    (memcmp(cand->server_id.data,
				    rval->server_id.data,
				    cand->server_id.len) < 0))) {
			log_debug("PRC:  | X-- Selected, equal preference, "
				  "binary lesser server ID (tiebreaker).");
			rpos = candp;
			rval = cand;
		} else
			log_debug("PRC:  | X-- Rejected, equal preference, "
				  "binary greater server ID (no tiebreaker).");
	}

	/* Remove the selected lease from the chain. */
	*rpos = rval->next;

	return rval;
}

/* Select a lease out of the advertised leases and setup state to try and
 * acquire that lease.
 */
void
start_selecting6(struct client_state *client)
{
	struct dhc6_lease *lease;
	struct data_string packet;

	if (client->advertised_leases == NULL) {
		log_error("Can not enter DHCPv6 SELECTING state with no "
			  "leases to select from!");
		return;
	}

	log_debug("PRC: Selecting best advertised lease.");
	client->state = S_SELECTING;

	lease = dhc6_best_lease(&client->advertised_leases);

	if (lease == NULL)
		log_fatal("Impossible error at %s:%d.", MDL);

	client->selected_lease = lease;

	/* Fetch a 24-bit transaction ID. */
	dhc6_new_xid(client);

	/* Set timers per RFC3315 section 18.1.1. */
	client->IRT = REQ_TIMEOUT;
	client->MRT = REQ_MAX_RT;
	client->MRC = REQ_MAX_RC;
	client->MRD = 0;

	dhc6_retrans_init(client);

	client->v6_handler = reply_handler;

	/* ("re")transmit the first packet. */
	do_select6(client);
}

/* Transmit a Request to select a lease offered in Advertisements.  In
 * the event of failure, either move on to the next-best advertised lease,
 * or head back to INIT state if there are none.
 */
void
do_select6(void *input)
{
	struct client_state *client;
	struct dhc6_lease *lease;
	struct dhc6_ia *ia;
	struct dhc6_addr *addr;
	struct option_cache *oc;
	struct data_string ds;
	struct data_string iads;
	struct data_string addrds;
	TIME elapsed, t1, t2;
	int abort = ISC_FALSE;
	int code, send_ret;

	client = input;

	/* 'lease' is fewer characters to type. */
	lease = client->selected_lease;
	if (lease == NULL || lease->bindings == NULL) {
		log_error("Illegal to attempt selection without selecting "
			  "a lease.");
		return;
	}

	if ((client->MRC != 0) && (client->txcount > client->MRC)) {
		log_info("Max retransmission count exceeded.");
		abort = ISC_TRUE;
	}

	elapsed = cur_time - client->start_time;
	if ((client->MRD != 0) && (elapsed > client->MRD)) {
		log_info("Max retransmission duration exceeded.");
		abort = ISC_TRUE;
	}

	if (abort) {
		log_debug("PRC: Lease %s failed.",
			  print_hex_1(lease->server_id.len,
				      lease->server_id.data, 56));

		/* Get rid of the lease that timed/counted out. */
		dhc6_lease_destroy(lease, MDL);
		client->selected_lease = NULL;

		/* If there are more leases great.  If not, get more. */
		if (client->advertised_leases != NULL)
			start_selecting6(client);
		else
			start_init6(client);

		return;
	}

	/* Now make a packet that looks suspiciously like the one we
	 * got from the server.  But different.
	 *
	 * XXX: I guess IAID is supposed to be something the client
	 * indicates and uses as a key to its internal state.  It is
	 * kind of odd to ask the server for IA's whose IAID the client
	 * did not manufacture.  We first need a formal dhclient.conf
	 * construct for the iaid, then we can delve into this matter
	 * more properly.  In the time being, this will work.
	 */
	memset(&ds, 0, sizeof(ds));
	if (!buffer_allocate(&ds.buffer, 4, MDL)) {
		log_error("Unable to allocate memory for REQUEST.");
		return;
	}
	ds.data = ds.buffer->data;
	ds.len = 4;

	ds.buffer->data[0] = DHCPV6_REQUEST;
	memcpy(ds.buffer->data + 1, client->dhcpv6_transaction_id, 3);

	/* Form an elapsed option. */
	if ((elapsed < 0) || (elapsed > 655))
		client->elapsed = 0xffff;
	else
		client->elapsed = elapsed * 100;

	log_debug("XMT: Forming Request, %u ms elapsed.",
		  (unsigned)client->elapsed);

	client->elapsed = htons(client->elapsed);

	make_client6_options(client, &client->sent_options, lease);

	/* Fetch any configured 'sent' options (includes DUID) in wire format.
	 */
	dhcpv6_universe.encapsulate(&ds, NULL, NULL, client,
				    NULL, client->sent_options, &global_scope,
				    &dhcpv6_universe);

	/* Now append any IA_NA's, and within them any IAADDRs. */
	if (dhc6_add_ia(client, &ds, lease) != ISC_R_SUCCESS) {
		data_string_forget(&ds, MDL);
		return;
	}

	log_info("XMT: Request on %s, interval %ld",
		 client->name ? client->name : client->interface->name,
		 client->RT);

	send_ret = send_packet6(client->interface,
				ds.data, ds.len, &DHCPv6DestAddr);
	if (send_ret != ds.len) {
		log_error("dhc6: send_packet6() sent %d of %d bytes",
			  send_ret, ds.len);
	}

	data_string_forget(&ds, MDL);

	add_timeout(cur_time + client->RT, do_select6, client, NULL, NULL);

	dhc6_retrans_advance(client);
}

/* For each IA in the lease, for each address in the IA, append that
 * information onto the packet-so-far in a "what I would like to have
 * please" fashion.
 */
static isc_result_t
dhc6_add_ia(struct client_state *client, struct data_string *packet,
	    struct dhc6_lease *lease)
{
	struct data_string iads;
	struct data_string addrds;
	struct dhc6_addr *addr;
	struct dhc6_ia *ia;
	isc_result_t rval = ISC_R_SUCCESS;
	TIME t1, t2;
	
        /* Now appended any IA_NA's, and within them any IAADDRs. */
        memset(&iads, 0, sizeof(iads));
        memset(&addrds, 0, sizeof(addrds));
        for (ia = lease->bindings ; ia ; ia = ia->next) {
                if (!buffer_allocate(&iads.buffer, 12, MDL)) {
                        log_error("Unable to allocate memory for IA.");
                        break;
                }
                iads.data = iads.buffer->data;
                iads.len = 12;

                memcpy(iads.buffer->data, ia->iaid, 4);

                t1 = client->config->requested_lease / 2;
                t2 = t1 + (t1 / 2);
#if MAX_TIME > 0xffffffff
		if (t1 > 0xffffffff)
			t1 = 0xffffffff;
		if (t2 > 0xffffffff)
			t2 = 0xffffffff;
#endif
                putULong(iads.buffer->data + 4, t1);
                putULong(iads.buffer->data + 8, t2);

                log_debug("XMT:  X-- IA_NA %s",
                          print_hex_1(4, iads.data, 59));
                log_debug("XMT:  | X-- Requested renew  +%u", (unsigned)t1);
                log_debug("XMT:  | X-- Requested rebind +%u", (unsigned)t2);

                for (addr = ia->addrs ; addr ; addr = addr->next) {
                        if (!buffer_allocate(&addrds.buffer, 24, MDL)) {
                                log_error("Unable to allocate memory for "
                                          "IAADDR.");
                                break;
                        }
                        addrds.data = addrds.buffer->data;
                        addrds.len = 24;

                        memcpy(addrds.buffer->data, addr->address.iabuf, 16);
			t1 = client->config->requested_lease;
			t2 = t1 + 300;
                        putULong(addrds.buffer->data + 16, t1);
                        putULong(addrds.buffer->data + 20, t2);

                        log_debug("XMT:  | | X-- IAADDR %s",
                                  piaddr(addr->address));
			log_debug("XMT:  | | | X-- Preferred lifetime +%u",
				  (unsigned)t1);
			log_debug("XMT:  | | | X-- Max lifetime +%u",
				  (unsigned)t2);

			append_option(&iads, &dhcpv6_universe, ia_addr_option,
				      &addrds);
			data_string_forget(&addrds, MDL);
		}

		/* It doesn't make sense to make a request without an
		 * address.
		 */
		if (ia->addrs != NULL) {
			log_debug("XMT:  V IA_NA appended.");
			append_option(packet, &dhcpv6_universe, ia_na_option,
				      &iads);
		} else {
			log_debug("!!!:  V IA_NA has no IAADDRs - removed.");
			rval = ISC_R_FAILURE;
		}

		data_string_forget(&iads, MDL);
	}

	return rval;
}

/* reply_handler() accepts a Reply while we're attempting Select or Renew or
 * Rebind.  Basically any Reply packet.
 */
void
reply_handler(struct packet *packet, struct client_state *client)
{
	struct dhc6_lease *lease, *old;

	if (packet->dhcpv6_msg_type != DHCPV6_REPLY)
		return;

	/* RFC3315 section 15.10 validation (same as 15.3 since we
	 * always include a client id).
	 */
	if (!valid_reply(packet, client)) {
		log_error("Invalid Advertise - rejecting.");
		return;
	}

	/* A matching xid reply means we're done. */
	cancel_timeout(do_select6, client);
	cancel_timeout(do_refresh6, client);

	dhc6_lease_destroy(client->selected_lease, MDL);
	client->selected_lease = NULL;

	lease = dhc6_leaseify(packet);

	/* This is an out of memory condition...just let it hang? */
	if (lease == NULL)
		return;

	if (dhc6_check_all_status_codes(lease) != ISC_R_SUCCESS) {
		dhc6_lease_destroy(lease, MDL);

		if (client->advertised_leases != NULL)
			start_selecting6(client);
		else
			start_init6(client);
		return;
	}

	/* Make this lease active and BIND to it. */
	if (client->active_lease != NULL)
		client->old_lease = client->active_lease;
	client->active_lease = lease;

	/* We're done with the ADVERTISEd leases, if any. */
	if (client->selected_lease != NULL) {
		dhc6_lease_destroy(client->selected_lease, MDL);
		client->selected_lease = NULL;
	}

	while(client->advertised_leases != NULL) {
		lease = client->advertised_leases;
		client->advertised_leases = lease->next;

		dhc6_lease_destroy(lease, MDL);
	}

	start_bound(client);
}

/* DHCPv6 packets are a little sillier than they needed to be - the root
 * packet contains options, then IA's which contain options, then within
 * that IAADDR's which contain options.
 *
 * To sort this out at dhclient-script time (which fetches config parameters
 * in environment variables), start_bound() iterates over each IAADDR, and
 * calls this function to marshall an environment variable set that includes
 * the most-specific option values related to that IAADDR in particular.
 *
 * To acheive this, we load environment variables for the root options space,
 * then the IA, then the IAADDR.  Any duplicate option names will be
 * over-written by the later versions.
 */
static void
dhc6_marshall_values(char *prefix, struct client_state *client,
		     struct dhc6_lease *lease, struct dhc6_ia *ia,
		     struct dhc6_addr *addr)
{
	/* Option cache contents, in descending order of
	 * scope.
	 */
	if ((lease != NULL) && (lease->options != NULL))
		script_write_params6(client, prefix, lease->options);
	if ((ia != NULL) && (ia->options != NULL))
		script_write_params6(client, prefix, ia->options);
	if ((addr != NULL) && (addr->options != NULL))
		script_write_params6(client, prefix, addr->options);

	/* addr fields. */
	if (addr != NULL) {
		/* Current practice is that all subnets are /64's, but
		 * some suspect this may not be permanent.
		 */
		client_envadd(client, prefix, "ip6_prefixlen", "%d", 64);
		client_envadd(client, prefix, "ip6_address", "%s",
			      piaddr(addr->address));
		client_envadd(client, prefix, "preferred_life", "%d",
			      (int)(addr->preferred_life));
		client_envadd(client, prefix, "max_life", "%d",
			      (int)(addr->max_life));
	}

	/* ia fields. */
	if (ia != NULL) {
		client_envadd(client, prefix, "iaid", "%s",
			      print_hex_1(4, ia->iaid, 12));
		client_envadd(client, prefix, "starts", "%d",
			      (int)(ia->starts));
		client_envadd(client, prefix, "renew", "%u", ia->renew);
		client_envadd(client, prefix, "rebind", "%u", ia->rebind);
	}
}

/* Look at where the client's active lease is sitting.  If it's looking to
 * time out on renew, rebind, depref, or expiration, do those things.
 */
static void
dhc6_check_times(struct client_state *client)
{
	struct dhc6_lease *lease;
	struct dhc6_ia *ia;
	struct dhc6_addr *addr;
	TIME renew=MAX_TIME, rebind=MAX_TIME, depref=MAX_TIME,
	     lo_expire=MAX_TIME, hi_expire=0, tmp;
	int has_addrs = ISC_FALSE;

	lease = client->active_lease;

	/* Bit spammy.  We should probably keep record of scheduled
	 * events instead.
	 */
	cancel_timeout(start_renew6, client);
	cancel_timeout(start_rebind6, client);
	cancel_timeout(do_depref, client);
	cancel_timeout(do_expire, client);

	for(ia = lease->bindings ; ia != NULL ; ia = ia->next) {
		for (addr = ia->addrs ; addr != NULL ; addr = addr->next) {
			if(!(addr->flags & DHC6_ADDR_DEPREFFED)) {
				if (addr->preferred_life == 0xffffffff)
					tmp = MAX_TIME;
				else
					tmp = ia->starts +
					      addr->preferred_life;

				if (tmp < depref)
					depref = tmp;
			}

			if (!(addr->flags & DHC6_ADDR_EXPIRED)) {
				if (addr->max_life == 0xffffffff)
					tmp = MAX_TIME;
				else
					tmp = ia->starts + addr->max_life;

				if (tmp > hi_expire)
					hi_expire = tmp;
				if (tmp < lo_expire)
					lo_expire = tmp;

				has_addrs = ISC_TRUE;
			}
		}

		if (ia->renew == 0) {
			if (lo_expire != MAX_TIME)
				tmp = (lo_expire - ia->starts) / 2;
			else
				tmp = client->config->requested_lease / 2;

			tmp += ia->starts;
		} else if(ia->renew == 0xffffffff)
			tmp = MAX_TIME;
		else
			tmp = ia->starts + ia->renew;

		if (tmp < renew)
			renew = tmp;

		if (ia->rebind == 0) {
			if (lo_expire != MAX_TIME)
				tmp = (lo_expire - ia->starts) / 2;
			else
				tmp = client->config->requested_lease / 2;

			tmp += ia->starts + (tmp / 2);
		} else if (ia->renew == 0xffffffff)
			tmp = MAX_TIME;
		else
			tmp = ia->starts + ia->rebind;

		if (tmp < rebind)
			rebind = tmp;
	}

	/* If there are no addresses, give up, go to INIT.
	 * Note that if an address is unexpired with a date in the past,
	 * we're scheduling an expiration event to ocurr in the past.  We
	 * could probably optimize this to expire now (but then there's
	 * recursion).
	 */
	if (has_addrs == ISC_FALSE) {
		dhc6_lease_destroy(client->active_lease, MDL);
		client->active_lease = NULL;

		/* Go back to the beginning. */
		start_init6(client);
		return;
	}

	switch(client->state) {
	      case S_BOUND:
		/* We'd like to hit renewing, but if rebinding has already
		 * passed (time warp), head straight there.
		 */
		if ((rebind > cur_time) && (renew < rebind)) {
			log_debug("PRC: Renewal event scheduled in %u seconds, "
				  "to run for %u seconds.",
				  (unsigned)(renew - cur_time),
				  (unsigned)(rebind - renew));
			client->MRD = rebind - cur_time;
			add_timeout(renew, start_renew6, client, NULL, NULL);

			break;
		}
		/* FALL THROUGH */
	      case S_RENEWING:
		if (rebind != MAX_TIME) {
			log_debug("PRC: Rebind event scheduled in %d seconds, "
				  "to run for %d seconds.",
				  (int)(rebind - cur_time),
				  (int)(hi_expire - rebind));
			client->MRD = hi_expire - cur_time;
			add_timeout(rebind, start_rebind6, client, NULL, NULL);
		}
		break;

	      case S_REBINDING:
		break;

	      default:
		log_fatal("Impossible condition at %s:%d.", MDL);
	}

	/* Separately, set a time at which we will depref and expire
	 * leases.  This might happen with multiple addresses while we
	 * keep trying to refresh.
	 */
	if (depref != MAX_TIME) {
		log_debug("PRC: Depreference scheduled in %d seconds.",
			  (int)(depref - cur_time));
		add_timeout(depref, do_depref, client, NULL, NULL);
	}
	if (lo_expire != MAX_TIME) {
		log_debug("PRC: Expiration scheduled in %d seconds.",
			  (int)(lo_expire - cur_time));
		add_timeout(lo_expire, do_expire, client, NULL, NULL);
	}
}

/* In a given IA chain, find the IA with the same 'iaid'. */
static struct dhc6_ia *
find_ia(struct dhc6_ia *head, char *id)
{
	struct dhc6_ia *ia;

	for (ia = head ; ia != NULL ; ia = ia->next) {
		if (memcmp(ia->iaid, id, 4) == 0)
			return ia;
	}

	return NULL;
}

/* In a given address chain, find a matching address. */
static struct dhc6_addr *
find_addr(struct dhc6_addr *head, struct iaddr *address)
{
	struct dhc6_addr *addr;

	for (addr = head ; addr != NULL ; addr = addr->next) {
		if ((addr->address.len == address->len) &&
		    (memcmp(addr->address.iabuf, address->iabuf,
			    address->len) == 0))
			return addr;
	}

	return NULL;
}

/* We've either finished selecting or succeeded in Renew or Rebinding our
 * lease.  In all cases we got a Reply.  Give dhclient-script a tickle
 * to inform it about the new values, and then lay in wait for the next
 * event.
 */
void
start_bound(struct client_state *client)
{
	struct dhc6_ia *ia, *oldia;
	struct dhc6_addr *addr, *oldaddr;
	struct dhc6_lease *lease, *old;
	char *reason;

	lease = client->active_lease;
	if (lease == NULL) {
		log_error("Cannot enter bound state unless an active lease "
			  "is selected.");
		return;
	}
	old = client->old_lease;

	client->v6_handler = bound_handler;

	switch (client->state) {
	      case S_SELECTING:
		reason = "BOUND6";
		break;

	      case S_RENEWING:
		reason = "RENEW6";
		break;

	      case S_REBINDING:
		reason = "REBIND6";
		break;

	      default:
		log_fatal("Impossible condition at %s:%d.", MDL);
	}

	log_debug("PRC: Bound to lease %s.",
		  print_hex_1(client->active_lease->server_id.len,
			      client->active_lease->server_id.data, 55));
	client->state = S_BOUND;

	for (ia = lease->bindings ; ia != NULL ; ia = ia->next) {
		if (old != NULL)
			oldia = find_ia(old->bindings, ia->iaid);

		/* XXX: If we ever get to information request, our IA's
		 * might not have addresses at all.
		 */
		for (addr = ia->addrs ; addr != NULL ; addr = addr->next) {
			if (oldia != NULL)
				oldaddr = find_addr(oldia->addrs,
						    &addr->address);
			else
				oldaddr = NULL;

			/* Shell out to setup the new binding. */
			script_init(client, reason, NULL);

			if (old != NULL)
				dhc6_marshall_values("old_", client, old,
						     oldia, oldaddr);
			dhc6_marshall_values("new_", client, lease, ia, addr);

			script_go(client);
		}
	}

	if (client->old_lease != NULL) {
		dhc6_lease_destroy(client->old_lease, MDL);
		client->old_lease = NULL;
	}

	/* Schedule events. */
	dhc6_check_times(client);
}

/* While bound, ignore packets.  In the future we'll want to answer
 * Reconfigure-Request messages and the like.
 */
void
bound_handler(struct packet *packet, struct client_state *client)
{
	log_debug("RCV: Input packets are ignored once bound.");
}

/* start_renew6() gets us all ready to go to start transmitting Renew packets.
 * Note that client->MRD must be set before entering this function - it must
 * be set to the time at which the client should start Rebinding.
 */
void
start_renew6(void *input)
{
	struct client_state *client;

	client = (struct client_state *)input;

	log_info("PRC: Renewing lease on %s.",
		 client->name ? client->name : client->interface->name);
	client->state = S_RENEWING;

	client->v6_handler = reply_handler;

	/* Times per RFC3315 section 18.1.3. */
	client->IRT = REN_TIMEOUT;
	client->MRT = REN_MAX_RT;
	client->MRC = 0;
	/* MRD is special in renew - it is bounded either by entry into
	 * REBIND or EXPIRE.  So it's set when the renew is scheduled (and
	 * the rebind or expire time is known).
	 */

	dhc6_retrans_init(client);

	client->refresh_type = DHCPV6_RENEW;
	do_refresh6(client);
}

/* do_refresh6() transmits one DHCPv6 packet, be it a Renew or Rebind, and
 * gives the retransmission state a bump for the next time.  Note that
 * client->refresh_type must be set before entering this function.
 */
void
do_refresh6(void *input)
{
	struct data_string ds;
	struct client_state *client;
	struct dhc6_lease *lease;
	TIME elapsed, next;
	int send_ret;

	client = (struct client_state *)input;

	lease = client->active_lease;
	if (lease == NULL) {
		log_error("Cannot renew without an active binding.");
		return;
	}

	/* Ensure we're emitting a valid message type. */
	switch (client->refresh_type) {
	      case DHCPV6_RENEW:
	      case DHCPV6_REBIND:
		break;

	      default:
		log_fatal("Internal inconsistency (%d) at %s:%d.",
			  client->refresh_type, MDL);
	}

	elapsed = cur_time - client->start_time;
	if (((client->MRC != 0) && (client->txcount > client->MRC)) ||
	    ((client->MRD != 0) && (elapsed >= client->MRD))) {
		/* We're done.  Move on to the next phase, if any. */
		dhc6_check_times(client);
		return;
	}

	/* Commence forming a renew packet. */
	memset(&ds, 0, sizeof(ds));
	if (!buffer_allocate(&ds.buffer, 4, MDL)) {
		log_error("Unable to allocate memory for packet.");
		return;
	}
	ds.data = ds.buffer->data;
	ds.len = 4;

	ds.buffer->data[0] = client->refresh_type;
	memcpy(ds.buffer->data + 1, client->dhcpv6_transaction_id, 3);

	if ((elapsed < 0) || (elapsed > 655))
		client->elapsed = 0xffff;
	else
		client->elapsed = elapsed * 100;

	log_debug("XMT: Forming %s, %u ms elapsed.",
		  dhcpv6_type_names[client->refresh_type],
		  (unsigned)client->elapsed);

	client->elapsed = htons(client->elapsed);

	make_client6_options(client, &client->sent_options, lease);

	/* Put in any options from the sent cache. */
	dhcpv6_universe.encapsulate(&ds, NULL, NULL, client, NULL,
				    client->sent_options, &global_scope,
				    &dhcpv6_universe);

	if (dhc6_add_ia(client, &ds, lease) != ISC_R_SUCCESS) {
		data_string_forget(&ds, MDL);
		return;
	}

	log_info("XMT: %s on %s, interval %ld",
		 dhcpv6_type_names[client->refresh_type],
		 client->name ? client->name : client->interface->name,
		 client->RT);

	send_ret = send_packet6(client->interface, ds.data, ds.len,
				&DHCPv6DestAddr);
	if (send_ret != ds.len) {
		log_error("dhc6: send_packet6() sent %d of %d bytes",
			  send_ret, ds.len);
	}

	data_string_forget(&ds, MDL);

	add_timeout(cur_time + client->RT, do_refresh6, client, NULL, NULL);

	dhc6_retrans_advance(client);
}

/* start_rebind6() gets us all set up to go and rebind a lease.  Note that
 * client->MRD must be set before entering this function.  In this case,
 * MRD must be set to the maximum time any address in the packet will
 * expire.
 */
void
start_rebind6(void *input)
{
	struct client_state *client;

	client = (struct client_state *)input;

	log_info("PRC: Rebinding lease on %s.",
		 client->name ? client->name : client->interface->name);
	client->state = S_REBINDING;

	client->v6_handler = reply_handler;

	/* Times per RFC3315 section 18.1.4. */
	client->IRT = REB_TIMEOUT;
	client->MRT = REB_MAX_RT;
	client->MRC = 0;
	/* MRD is special in rebind - it's bounded by the last time of
	 * expiration, so it's set by the caller.
	 */

	dhc6_retrans_init(client);

	client->refresh_type = DHCPV6_REBIND;
	do_refresh6(client);
}

/* do_depref() runs through a given lease's addresses, for each that has
 * not yet been depreffed, shells out to the dhclient-script to inform it
 * of the status change.  The dhclient-script should then do...something...
 * to encourage applications to move off the address and onto one of the
 * remaining 'preferred' addresses.
 */
void
do_depref(void *input)
{
	struct client_state *client;
	struct dhc6_lease *lease;
	struct dhc6_ia *ia;
	struct dhc6_addr *addr;

	client = (struct client_state *)input;

	lease = client->active_lease;
	if (lease == NULL)
		return;

	for (ia = lease->bindings ; ia != NULL ; ia = ia->next) {
		for (addr = ia->addrs ; addr != NULL ; addr = addr->next) {
			if (addr->flags & DHC6_ADDR_DEPREFFED)
				continue;

			if (ia->starts + addr->preferred_life <= cur_time) {
				script_init(client, "DEPREF6", NULL);
				dhc6_marshall_values("cur_", client, lease,
						     ia, addr);
				script_go(client);

				log_info("PRC: Address %s depreferred.",
					 print_hex_1(addr->address.len,
						     addr->address.iabuf,
						     50));


				addr->flags |= DHC6_ADDR_DEPREFFED;
			}
		}
	}

	dhc6_check_times(client);
}

/* do_expire() searches through all the addresses on a given lease, and
 * expires/removes any addresses that are no longer valid.
 */
void
do_expire(void *input)
{
	struct client_state *client;
	struct dhc6_lease *lease;
	struct dhc6_ia *ia;
	struct dhc6_addr *addr;
	int has_addrs = ISC_FALSE;

	client = (struct client_state *)input;

	lease = client->active_lease;
	if (lease == NULL)
		return;

	for (ia = lease->bindings ; ia != NULL ; ia = ia->next) {
		for (addr = ia->addrs ; addr != NULL ; addr = addr->next) {
			if (addr->flags & DHC6_ADDR_EXPIRED)
				continue;

			if (ia->starts + addr->max_life <= cur_time) {
				script_init(client, "EXPIRE6", NULL);
				dhc6_marshall_values("old_", client, lease,
						     ia, addr);
				script_go(client);

				addr->flags |= DHC6_ADDR_EXPIRED;

				log_info("PRC: Address %s expired.",
					 print_hex_1(addr->address.len,
						     addr->address.iabuf,
						     50));

				continue;
			}

			has_addrs = ISC_TRUE;
		}
	}

	/* Clean up empty leases. */
	if (has_addrs == ISC_FALSE) {
		log_info("PRC: Bound lease is devoid of active addresses."
			 "  Re-initializing.");

		dhc6_lease_destroy(lease, MDL);
		client->active_lease = NULL;

		start_init6(client);
		return;
	}

	/* Schedule the next run through. */
	dhc6_check_times(client);
}

/* make_client6_options() fetches option caches relevant to the client's
 * scope and places them into the sent_options cache.  This cache is later
 * used to populate DHCPv6 output packets with options.
 */
static void
make_client6_options(struct client_state *client, struct option_state **op,
		     struct dhc6_lease *lease)
{
	int code;
	struct option_cache *oc;

	if ((op == NULL) || (client == NULL))
		return;

	if (*op)
		option_state_dereference(op, MDL);

	option_state_allocate(op, MDL);

	code = D6O_ELAPSED_TIME;
	oc = NULL;
	if (option_cache_allocate(&oc, MDL)) {
		const unsigned char *cdata;

		cdata = (unsigned char *)&client->elapsed;

		if (make_const_data(&oc->expression, cdata, 2, 0, 0, MDL) &&
		    option_code_hash_lookup(&oc->option,
					    dhcpv6_universe.code_hash,
					    &code, 0, MDL)) {
			save_option(&dhcpv6_universe, *op, oc);
		}

		option_cache_dereference(&oc, MDL);
	}

	/* Put the default DUID in the state cache. */
	if (client->default_duid != NULL)
		save_option(&dhcpv6_universe, *op, client->default_duid);

	/* In cases where we're responding to a server, put the server's
	 * id in the response.
	 */
	if (lease != NULL) {
		oc = lookup_option(&dhcpv6_universe, lease->options,
				   D6O_SERVERID);
		if (oc != NULL)
			save_option(&dhcpv6_universe, *op, oc);
	}

	if (client->config->on_transmission)
		execute_statements_in_scope(NULL, NULL, NULL, client,
					    lease ? lease->options : NULL,
					    *op, &global_scope,
					    client->config->on_transmission,
					    NULL);

	/* RFC3315 says we MUST inclue an ORO in requests.  If we have it
	 * in the cache for one, we have it for both, so it's fatal either
	 * way.
	 */
	if (lookup_option(&dhcpv6_universe, *op, D6O_ORO) == NULL)
		log_fatal("You must configure a dhcp6.oro!");
}

/* A clone of the DHCPv4 script_write_params() minus the DHCPv4-specific
 * filename, server-name, etc specifics.
 *
 * Simply, store all values present in all universes of the option state
 * (probably derived from a DHCPv6 packet) into environment variables
 * named after the option names (and universe names) but with the 'prefix'
 * prepended.
 *
 * Later, dhclient-script may compare for example "new_time_servers" and
 * "old_time_servers" for differences, and only upon detecting a change
 * bother to rewrite ntp.conf and restart it.  Or something along those
 * generic lines.
 */
static void
script_write_params6(struct client_state *client, char *prefix,
		     struct option_state *options)
{
	struct envadd_state es;
	int i;

	if (options == NULL)
		return;

	es.client = client;
	es.prefix = prefix;

	for (i = 0 ; i < options->universe_count ; i++) {
		option_space_foreach(NULL, NULL, client, NULL, options,
				     &global_scope, universes[i], &es,
				     client_option_envadd);
	}
}

