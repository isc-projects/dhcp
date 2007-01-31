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
"$Id: dhc6.c,v 1.1.4.2 2007/01/31 20:46:31 dhankins Exp $ Copyright (c) 2006 Internet Systems Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

struct sockaddr_in6 DHCPv6DestAddr;
struct option *ia_na_option = NULL;
struct option *ia_addr_option = NULL;

static isc_result_t dhc6_parse_ia_na(struct dhc6_ia **pia,
				     struct packet *packet,
				     struct option_state *options);

static void dhc6_lease_destroy(struct dhc6_lease *lease, char *file, int line);
static isc_result_t dhc6_parse_ia_na(struct dhc6_ia **pia,
				     struct packet *packet,
				     struct option_state *options);
static isc_result_t dhc6_parse_addrs(struct dhc6_addr **paddr,
				     struct packet *packet,
				     struct option_state *options);
void init_handler(struct packet *packet, struct client_state *client);
void do_init6(void *input);
void selecting_handler(struct packet *packet, struct client_state *client);
void do_select6(void *input);
static void start_bound(struct client_state *client);
void bound_handler(struct packet *packet, struct client_state *client);
static void make_client6_options(struct client_state *client,
				 struct option_state **op,
				 struct dhc6_lease *lease);
void script_write_params6(struct client_state *client, char *prefix,
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
 * -0.1 and 0.1 non-inclusive, we implement it as an integer from -10% to
 * +10%, inclusive, of the base.
 *
 * XXX: for this to make sense, we really need to do timing on a
 * XXX: usec scale..
 */
static TIME
dhc6_rand(TIME base)
{
	TIME rval;
	TIME range;

	if (base < 0)
		log_fatal("Impossible condition at %s:%d.", MDL);

	/* The range is 20% of the base.  If we % a random number by this,
	 * we actually get a number between 0 and 19.99% repeating of the
	 * base, integer rounding excepted.  (foo % x is no greater than
	 * x-1).  So if we subtract half the range from the resulting modulus,
	 * we get a number between -10% and 10% of the base non-inclusive.
	 * Modulo integer rounding.
	 */
	range = (base / 5) + 1;

	if (range == 0)
		return 0;

	rval = random();

	rval %= range;
	rval -= (range + 1) / 2;

	return rval;
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
	unsigned renew, rebind;
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
			renew = getULong(ds.data + 4);
			ia->renew = cur_time + renew;
			rebind = getULong(ds.data + 8);
			ia->rebind = cur_time + rebind;

			log_debug("RCV:  X-- IA_NA %s",
				  print_hex_1(4, ia->iaid, 59));
			/* XXX: This should be the printed time I think. */
			log_debug("RCV:  | X-- starts %u",
				  (unsigned)ia->starts);
			log_debug("RCV:  | X-- renew  +%u", renew);
			log_debug("RCV:  | X-- rebind +%u", rebind);

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
				(unsigned)addr->preferred_life);
			log_debug("RCV:  | | | X-- Max lifetime %u.",
				  (unsigned)addr->max_life);

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
	int xid;

	log_debug("Soliciting for leases.");

	/* Fetch a 24-bit transaction ID. */
	if (RAND_MAX >= 0x00ffffff)
		xid = random();
	else if (RAND_MAX >= 0x0000ffff)
		xid = (random() << 16) | random();
	else
		xid = (random() << 24) | (random() << 16) | random();

	client->dhcpv6_transaction_id[0] = (xid >> 16) & 0xff;
	client->dhcpv6_transaction_id[1] = (xid >>  8) & 0xff;
	client->dhcpv6_transaction_id[2] =  xid        & 0xff;

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
		log_info("%s status code %s: %.*s", scope, msg, len,
			 additional);
	else
		log_info("%s status code %s.", scope, msg);
}

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
	}

	insert_lease(&client->advertised_leases, lease);

	/* If the lease is highest possible preference, RFC3315 claims we
	 * should exit immediately.
	 */
	if (lease->pref == 255) {
		log_debug("RCV:  Advertisement immediately selected.");
		cancel_timeout(do_init6, client);
		start_selecting6(client);
	} else
		log_debug("RCV:  Advertisement recorded.");
}

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

void
start_selecting6(struct client_state *client)
{
	struct dhc6_lease *lease;
	struct data_string packet;
	int xid;

	if (client->advertised_leases == NULL) {
		log_error("Can not enter DHCPv6 SELECTING state with no "
			  "leases to select from!");
		return;
	}

	log_debug("PRC: Selecting best advertised lease.");

	lease = dhc6_best_lease(&client->advertised_leases);

	if (lease == NULL)
		log_fatal("Impossible error at %s:%d.", MDL);

	client->selected_lease = lease;

	/* Fetch a 24-bit transaction ID. */
	xid = random();
	client->dhcpv6_transaction_id[0] = (xid >> 16) & 0xff;
	client->dhcpv6_transaction_id[1] = (xid >>  8) & 0xff;
	client->dhcpv6_transaction_id[2] =  xid        & 0xff;

	/* Set timers per RFC3315 section 18.1.1. */
	client->IRT = REQ_TIMEOUT;
	client->MRT = REQ_MAX_RT;
	client->MRC = REQ_MAX_RC;
	client->MRD = 0;

	dhc6_retrans_init(client);

	client->v6_handler = selecting_handler;

	/* ("re")transmit the first packet. */
	do_select6(client);
}

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

	/* Now appended any IA_NA's, and within them any IAADDRs. */
	memset(&iads, 0, sizeof(iads));
	memset(&addrds, 0, sizeof(addrds));
	abort = ISC_TRUE;
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
			putULong(addrds.buffer->data + 16,
				 client->config->requested_lease);
			putULong(addrds.buffer->data + 20,
				 client->config->requested_lease + 300);

			log_debug("XMT:  | | X-- IAADDR %s",
				  piaddr(addr->address));

			append_option(&iads, &dhcpv6_universe, ia_addr_option,
				      &addrds);
			data_string_forget(&addrds, MDL);
		}

		/* It doesn't make sense to make a request without an
		 * address.
		 */
		if (ia->addrs != NULL) {
			log_debug("XMT:  V IA_NA appended.");
			append_option(&ds, &dhcpv6_universe, ia_na_option,
				      &iads);
			abort = ISC_FALSE;
		} else
			log_debug("!!!:  V IA_NA has no IAADDRs - removed.");

		data_string_forget(&iads, MDL);
	}

	if (abort) {
		log_error("Attempt to request for no addresses.");
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

void
selecting_handler(struct packet *packet, struct client_state *client)
{
	struct dhc6_lease *lease;

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
	client->active_lease = lease;

	/* We're done with the ADVERTISEd leases. */
	dhc6_lease_destroy(client->selected_lease, MDL);
	client->selected_lease = NULL;

	while(client->advertised_leases != NULL) {
		lease = client->advertised_leases;
		client->advertised_leases = lease->next;

		dhc6_lease_destroy(lease, MDL);
	}

	start_bound(client);
}

void
start_bound(struct client_state *client)
{
	struct dhc6_ia *ia;
	struct dhc6_addr *addr;
	struct dhc6_lease *lease;

	lease = client->active_lease;
	if (lease == NULL) {
		log_error("Cannot enter bound state unless an active lease "
			  "is selected.");
		return;
	}

	client->v6_handler = bound_handler;

	log_debug("PRC: Bound to lease %s.",
		  print_hex_1(client->active_lease->server_id.len,
			      client->active_lease->server_id.data, 55));

	for (ia = lease->bindings ; ia != NULL ; ia = ia->next) {
		for (addr = ia->addrs ; addr != NULL ; addr = addr->next) {
			script_init(client, "BOUND6", NULL);

			/* Option cache contents, in descending order of
			 * scope.
			 */
			script_write_params6(client, "new_", lease->options);
			script_write_params6(client, "new_", ia->options);
			script_write_params6(client, "new_", addr->options);

			/* addr fields. */
			client_envadd(client, "new_", "ip6_address", "%s",
				      piaddr(addr->address));
			client_envadd(client, "new_", "preferred_life", "%d",
				      (int)(addr->preferred_life));
			client_envadd(client, "new_", "max_life", "%d",
				      (int)(addr->max_life));

			/* ia fields. */
			client_envadd(client, "", "iaid", "%s",
				      print_hex_1(4, ia->iaid, 12));
			client_envadd(client, "new_", "starts", "%d",
				      (int)(ia->starts));
			client_envadd(client, "new_", "renew", "%d",
				      (int)(ia->renew));
			client_envadd(client, "new_", "rebind", "%d",
				      (int)(ia->rebind));

			script_go(client);
		}
	}
}

void
bound_handler(struct packet *packet, struct client_state *client)
{
	log_debug("RCV: Input packets are ignored once bound.");
}

void
renew_handler(struct packet *packet, struct client_state *client)
{
}

void
rebind_handler(struct packet *packet, struct client_state *client)
{
}

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

void
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

