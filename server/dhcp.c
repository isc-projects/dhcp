/* dhcp.c

   DHCP Protocol engine. */

/*
 * Copyright (c) 1995, 1996, 1997, 1998 The Internet Software Consortium.
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
"$Id: dhcp.c,v 1.64 1998/06/25 03:56:24 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

int outstanding_pings;

static char dhcp_message [256];

void dhcp (packet)
	struct packet *packet;
{
	if (!locate_network (packet) && packet -> packet_type != DHCPREQUEST)
		return;

	switch (packet -> packet_type) {
	      case DHCPDISCOVER:
		dhcpdiscover (packet);
		break;

	      case DHCPREQUEST:
		dhcprequest (packet);
		break;

	      case DHCPRELEASE:
		dhcprelease (packet);
		break;

	      case DHCPDECLINE:
		dhcpdecline (packet);
		break;

	      case DHCPINFORM:
		dhcpinform (packet);
		break;

	      default:
		break;
	}
}

void dhcpdiscover (packet)
	struct packet *packet;
{
	struct lease *lease;
	struct host_decl *hp;

	/* Classify the client. */
	classify_client (packet);

	note ("DHCPDISCOVER from %s via %s",
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      packet -> raw -> giaddr.s_addr
	      ? inet_ntoa (packet -> raw -> giaddr)
	      : packet -> interface -> name);

	lease = find_lease (packet, packet -> shared_network, 0);

	/* Sourceless packets don't make sense here. */
	if (!packet -> shared_network) {
		note ("Packet from unknown subnet: %s",
		      inet_ntoa (packet -> raw -> giaddr));
		return;
	}

	/* If we didn't find a lease, try to allocate one... */
	if (!lease) {
		lease = packet -> shared_network -> last_lease;

		/* If there are no leases in that subnet that have
		   expired, we have nothing to offer this client. */
		if (!lease || lease -> ends > cur_time) {
			note ("no free leases on subnet %s",
			      packet -> shared_network -> name);
			return;
		}

		/* If we find an abandoned lease, take it, but print a
		   warning message, so that if it continues to lose,
		   the administrator will eventually investigate. */
		if (lease -> flags & ABANDONED_LEASE) {
			warn ("Reclaiming abandoned IP address %s.\n",
			      piaddr (lease -> ip_addr));
			lease -> flags &= ~ABANDONED_LEASE;
		}

		/* Try to find a host_decl that matches the client
		   identifier or hardware address on the packet, and
		   has no fixed IP address.   If there is one, hang
		   it off the lease so that its option definitions
		   can be used. */
		if (((packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].len
		      != 0) &&
		     ((hp = find_hosts_by_uid
		       (packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].data,
			packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].len))
		      != (struct host_decl *)0)) ||
		    ((hp = find_hosts_by_haddr (packet -> raw -> htype,
						packet -> raw -> chaddr,
						packet -> raw -> hlen))
		     != (struct host_decl *)0)) {
			for (; hp; hp = hp -> n_ipaddr) {
				if (!hp -> fixed_addr) {
					lease -> host = hp;
					break;
				}
			}
		} else {
			lease -> host = (struct host_decl *)0;
		}
	}

	ack_lease (packet, lease, DHCPOFFER, cur_time + 120);
}

void dhcprequest (packet)
	struct packet *packet;
{
	struct lease *lease;
	struct iaddr cip;
	struct subnet *subnet;
	int ours = 0;

	if (packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len) {
		cip.len = 4;
		memcpy (cip.iabuf,
			packet -> options [DHO_DHCP_REQUESTED_ADDRESS].data,
			4);
	} else {
		cip.len = 4;
		memcpy (cip.iabuf, &packet -> raw -> ciaddr.s_addr, 4);
	}
	subnet = find_subnet (cip);

	/* Find the lease that matches the address requested by the
	   client. */

	if (subnet)
		lease = find_lease (packet, subnet -> shared_network, &ours);
	else
		lease = (struct lease *)0;

	note ("DHCPREQUEST for %s from %s via %s",
	      piaddr (cip),
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      packet -> raw -> giaddr.s_addr
	      ? inet_ntoa (packet -> raw -> giaddr)
	      : packet -> interface -> name);

	/* If a client on a given network REQUESTs a lease on an
	   address on a different network, NAK it.  If the Requested
	   Address option was used, the protocol says that it must
	   have been broadcast, so we can trust the source network
	   information.

	   If ciaddr was specified and Requested Address was not, then
	   we really only know for sure what network a packet came from
	   if it came through a BOOTP gateway - if it came through an
	   IP router, we'll just have to assume that it's cool.

	   If we don't think we know where the packet came from, it
	   came through a gateway from an unknown network, so it's not
	   from a RENEWING client.  If we recognize the network it
	   *thinks* it's on, we can NAK it even though we don't
	   recognize the network it's *actually* on; otherwise we just
	   have to ignore it.

	   We don't currently try to take advantage of access to the
	   raw packet, because it's not available on all platforms.
	   So a packet that was unicast to us through a router from a
	   RENEWING client is going to look exactly like a packet that
	   was broadcast to us from an INIT-REBOOT client.

	   Since we can't tell the difference between these two kinds
	   of packets, if the packet appears to have come in off the
	   local wire, we have to treat it as if it's a RENEWING
	   client.  This means that we can't NAK a RENEWING client on
	   the local wire that has a bogus address.  The good news is
	   that we won't ACK it either, so it should revert to INIT
	   state and send us a DHCPDISCOVER, which we *can* work with.

	   Because we can't detect that a RENEWING client is on the
	   wrong wire, it's going to sit there trying to renew until
	   it gets to the REBIND state, when we *can* NAK it because
	   the packet will get to us through a BOOTP gateway.  We
	   shouldn't actually see DHCPREQUEST packets from RENEWING
	   clients on the wrong wire anyway, since their idea of their
	   local router will be wrong.  In any case, the protocol
	   doesn't really allow us to NAK a DHCPREQUEST from a
	   RENEWING client, so we can punt on this issue. */

	if (!packet -> shared_network ||
	    (packet -> raw -> ciaddr.s_addr &&
	     packet -> raw -> giaddr.s_addr) ||
	    packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len) {
		
		/* If we don't know where it came from but we do know
		   where it claims to have come from, it didn't come
		   from there.   Fry it. */
		if (!packet -> shared_network) {
			if (subnet) {
				nak_lease (packet, &cip);
				return;
			}
			/* Otherwise, ignore it. */
			return;
		}

		/* If we do know where it came from and it asked for an
		   address that is not on that shared network, nak it. */
		subnet = find_grouped_subnet (packet -> shared_network, cip);
		if (!subnet) {
			nak_lease (packet, &cip);
			return;
		}
	}

	/* If we found a lease for the client but it's not the one the
	   client asked for, don't send it - some other server probably
	   made the cut. */
	if (lease && !addr_eq (lease -> ip_addr, cip)) {
		/* If we found the address the client asked for, but
                   it wasn't what got picked, the lease belongs to us,
                   so we can tenuously justify NAKing it. */
		if (ours)
			nak_lease (packet, &cip);
		return;
	}

	/* If the address the client asked for is ours, but it wasn't
           available for the client, NAK it. */
	if (!lease && ours) {
		nak_lease (packet, &cip);
		return;
	}

	/* If we own the lease that the client is asking for,
	   and it's already been assigned to the client, ack it. */
	if (lease &&
	    ((lease -> uid_len && lease -> uid_len == 
	      packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].len &&
	      !memcmp (packet -> options
		       [DHO_DHCP_CLIENT_IDENTIFIER].data,
		       lease -> uid, lease -> uid_len)) ||
	     (lease -> hardware_addr.hlen == packet -> raw -> hlen &&
	      lease -> hardware_addr.htype == packet -> raw -> htype &&
	      !memcmp (lease -> hardware_addr.haddr,
		       packet -> raw -> chaddr,
		       packet -> raw -> hlen)))) {
		ack_lease (packet, lease, DHCPACK, 0);
		return;
	}
}

void dhcprelease (packet)
	struct packet *packet;
{
	struct lease *lease;
	struct iaddr cip;
	int i;

	/* DHCPRELEASE must not specify address in requested-address
           option, but old protocol specs weren't explicit about this,
           so let it go. */
	if (packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len) {
		note ("DHCPRELEASE from %s specified requested-address.",
		      print_hw_addr (packet -> raw -> htype,
				     packet -> raw -> hlen,
				     packet -> raw -> chaddr));
	}

	i = DHO_DHCP_CLIENT_IDENTIFIER;
	if (packet -> options [i].len) {
		lease = find_lease_by_uid (packet -> options [i].data,
					   packet -> options [i].len);
	} else
		lease = (struct lease *)0;

	/* The client is supposed to pass a valid client-identifier,
	   but the spec on this has changed historically, so try the
	   IP address in ciaddr if the client-identifier fails. */
	if (!lease) {
		cip.len = 4;
		memcpy (cip.iabuf, &packet -> raw -> ciaddr, 4);
		lease = find_lease_by_ip_addr (cip);
	}


	note ("DHCPRELEASE of %s from %s via %s (%sfound)",
	      inet_ntoa (packet -> raw -> ciaddr),
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      packet -> raw -> giaddr.s_addr
	      ? inet_ntoa (packet -> raw -> giaddr)
	      : packet -> interface -> name,
	      lease ? "" : "not ");

	/* If we found a lease, release it. */
	if (lease) {
		release_lease (lease);
	}
}

void dhcpdecline (packet)
	struct packet *packet;
{
	struct lease *lease;
	struct iaddr cip;

	/* DHCPDECLINE must specify address. */
	if (!packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len) {
		return;
	}

	cip.len = 4;
	memcpy (cip.iabuf,
		packet -> options [DHO_DHCP_REQUESTED_ADDRESS].data, 4);
	lease = find_lease_by_ip_addr (cip);

	note ("DHCPDECLINE on %s from %s via %s",
	      piaddr (cip),
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      packet -> raw -> giaddr.s_addr
	      ? inet_ntoa (packet -> raw -> giaddr)
	      : packet -> interface -> name);

	/* If we found a lease, mark it as unusable and complain. */
	if (lease) {
		abandon_lease (lease, "declined.");
	}
}

void dhcpinform (packet)
	struct packet *packet;
{
	note ("DHCPINFORM from %s",
	      inet_ntoa (packet -> raw -> ciaddr));
}

void nak_lease (packet, cip)
	struct packet *packet;
	struct iaddr *cip;
{
	struct sockaddr_in to;
	struct in_addr from;
	int result;
	struct dhcp_packet raw;
	unsigned char nak = DHCPNAK;
	struct packet outgoing;
	struct hardware hto;
	int i;

	struct option_state options;

	memset (&options, 0, sizeof options);
	memset (&outgoing, 0, sizeof outgoing);
	memset (&raw, 0, sizeof raw);
	outgoing.raw = &raw;

	/* Set DHCP_MESSAGE_TYPE to DHCPNAK */
	i = DHO_DHCP_MESSAGE_TYPE;
	options.dhcp_options [i] =
		option_cache (make_const_data (&nak, sizeof nak, 0, 0),
			      dhcp_universe.options [i]);

	/* Set DHCP_MESSAGE to whatever the message is */
	i = DHO_DHCP_MESSAGE;
	options.server_options [i] =
		option_cache (make_const_data (dhcp_message,
					       strlen (dhcp_message),
					       1, 0),
			      dhcp_universe.options [i]);
	
	/* Do not use the client's requested parameter list. */
	packet -> options [DHO_DHCP_PARAMETER_REQUEST_LIST].len = 0;
	packet -> options [DHO_DHCP_PARAMETER_REQUEST_LIST].data =
		(unsigned char *)0;

	/* Set up the option buffer... */
	outgoing.packet_length =
		cons_options (packet, outgoing.raw, 0, &options, 0, 0, 0);

/*	memset (&raw.ciaddr, 0, sizeof raw.ciaddr);*/
	raw.siaddr = packet -> interface -> primary_address;
	raw.giaddr = packet -> raw -> giaddr;
	memcpy (raw.chaddr, packet -> raw -> chaddr, sizeof raw.chaddr);
	raw.hlen = packet -> raw -> hlen;
	raw.htype = packet -> raw -> htype;

	raw.xid = packet -> raw -> xid;
	raw.secs = packet -> raw -> secs;
	raw.flags = packet -> raw -> flags | htons (BOOTP_BROADCAST);
	raw.hops = packet -> raw -> hops;
	raw.op = BOOTREPLY;

	/* Report what we're sending... */
	note ("DHCPNAK on %s to %s via %s",
	      piaddr (*cip),
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      packet -> raw -> giaddr.s_addr
	      ? inet_ntoa (packet -> raw -> giaddr)
	      : packet -> interface -> name);



#ifdef DEBUG_PACKET
	dump_packet (packet);
	dump_raw ((unsigned char *)packet -> raw, packet -> packet_length);
	dump_packet (&outgoing);
	dump_raw ((unsigned char *)&raw, outgoing.packet_length);
#endif

	hto.htype = packet -> raw -> htype;
	hto.hlen = packet -> raw -> hlen;
	memcpy (hto.haddr, packet -> raw -> chaddr, hto.hlen);

	/* Set up the common stuff... */
	to.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	to.sin_len = sizeof to;
#endif
	memset (to.sin_zero, 0, sizeof to.sin_zero);

	from = packet -> interface -> primary_address;

	/* Make sure that the packet is at least as big as a BOOTP packet. */
	if (outgoing.packet_length < BOOTP_MIN_LEN)
		outgoing.packet_length = BOOTP_MIN_LEN;

	/* If this was gatewayed, send it back to the gateway.
	   Otherwise, broadcast it on the local network. */
	if (raw.giaddr.s_addr) {
		to.sin_addr = raw.giaddr;
		to.sin_port = local_port;

#ifdef USE_FALLBACK
		result = send_fallback (&fallback_interface,
					packet, &raw, outgoing.packet_length,
					from, &to, &hto);
		if (result < 0)
			warn ("send_fallback: %m");
		return;
#endif
	} else {
		to.sin_addr.s_addr = htonl (INADDR_BROADCAST);
		to.sin_port = remote_port;
	}

	errno = 0;
	result = send_packet (packet -> interface,
			      packet, &raw, outgoing.packet_length,
			      from, &to, (struct hardware *)0);
	if (result < 0)
		warn ("send_packet: %m");
}

void ack_lease (packet, lease, offer, when)
	struct packet *packet;
	struct lease *lease;
	unsigned int offer;
	TIME when;
{
	struct lease lt;
	struct lease_state *state;
	TIME lease_time;
	TIME offered_lease_time;
	struct data_string d1;
	TIME comp_lease_time;

	int i;
	int val;

	/* If we're already acking this lease, don't do it again. */
	if (lease -> state) {
		note ("already acking lease %s", piaddr (lease -> ip_addr));
		return;
	}

	/* XXX Process class restrictions. */

	/* Allocate a lease state structure... */
	state = new_lease_state ("ack_lease");
	if (!state)
		error ("unable to allocate lease state!");
	memset (state, 0, sizeof *state);

	/* Replace the old lease hostname with the new one, if it's changed. */
	if (packet -> options [DHO_HOST_NAME].len &&
	    lease -> client_hostname &&
	    (strlen (lease -> client_hostname) ==
	     packet -> options [DHO_HOST_NAME].len) &&
	    !memcmp (lease -> client_hostname,
		     packet -> options [DHO_HOST_NAME].data,
		     packet -> options [DHO_HOST_NAME].len)) {
	} else if (packet -> options [DHO_HOST_NAME].len) {
		if (lease -> client_hostname)
			free (lease -> client_hostname);
		lease -> client_hostname =
			malloc (packet -> options [DHO_HOST_NAME].len + 1);
		if (!lease -> client_hostname)
			error ("no memory for client hostname.\n");
		memcpy (lease -> client_hostname,
			packet -> options [DHO_HOST_NAME].data,
			packet -> options [DHO_HOST_NAME].len);
		lease -> client_hostname
			[packet -> options [DHO_HOST_NAME].len] = 0;
	} else if (lease -> client_hostname) {
		free (lease -> client_hostname);
		lease -> client_hostname = 0;
	}

	/* Process all of the executable statements associated with
	   this lease. */
	memset (&state -> options, 0, sizeof state -> options);
	
	/* Steal the agent options from the packet. */
	if (packet -> agent_options) {
		state -> options.agent_options = packet -> agent_options;
		packet -> agent_options = (struct agent_options *)0;
	}

	/* Execute the subnet statements. */
	execute_statements_in_scope (packet, &state -> options,
				     lease -> subnet -> group,
				     (struct group *)0);

	/* Vendor and user classes are only supported for DHCP clients. */
	if (state -> offer) {
		/* XXX process class stuff here. */
	}

	/* If we have a host_decl structure, run the options associated
	   with its group. */
	if (lease -> host)
		execute_statements_in_scope (packet, &state -> options,
					     lease -> host -> group,
					     lease -> subnet -> group);

	/* Make sure this packet satisfies the configured minimum
	   number of seconds. */
	if (state -> options.server_options [SV_MIN_SECS]) {
		d1 = evaluate_data_expression
			(packet,
			 (state -> options.server_options
			  [SV_MIN_SECS] -> expression));
		if (d1.len && packet -> raw -> secs < d1.data [0])
			return;
	}

	/* Drop the request if it's not allowed for this client. */
	if (!lease -> host &&
	    state -> options.server_options [SV_BOOT_UNKNOWN_CLIENTS]) {
		d1 = evaluate_data_expression
			(packet, (state -> options.server_options
				  [SV_BOOT_UNKNOWN_CLIENTS] -> expression));
		if (d1.len && !d1.data [0]) {
			note ("Ignoring unknown client %s",
			      print_hw_addr (packet -> raw -> htype,
					     packet -> raw -> hlen,
					     packet -> raw -> chaddr));
			return;
		}
	} 

	/* Drop the request if it's not allowed for this client. */
	if (!offer &&
	    state -> options.server_options [SV_ALLOW_BOOTP]) {
		d1 = evaluate_data_expression
			(packet, (state -> options.server_options
				  [SV_ALLOW_BOOTP] -> expression));
		if (d1.len && !d1.data [0]) {
			note ("Ignoring BOOTP client %s",
			      print_hw_addr (packet -> raw -> htype,
					     packet -> raw -> hlen,
					     packet -> raw -> chaddr));
			return;
		}
	} 

	if (state -> options.server_options [SV_ALLOW_BOOTING]) {
		d1 = evaluate_data_expression
			(packet, (state -> options.server_options
				  [SV_ALLOW_BOOTING] -> expression));
		if (d1.len && !d1.data [0]) {
			note ("Declining to boot client %s",
			      lease -> host -> name
			      ? lease -> host -> name
			      : print_hw_addr (packet -> raw -> htype,
					       packet -> raw -> hlen,
					       packet -> raw -> chaddr));
			return;
		}
	}

	/* Figure out the filename. */
	if (state -> options.server_options [SV_FILENAME])
		state -> filename =
			(evaluate_data_expression
			 (packet,
			  (state -> options.
			   server_options [SV_FILENAME] -> expression)));

	/* Choose a server name as above. */
	if (state -> options.server_options [SV_SERVER_NAME])
		state -> server_name =
			(evaluate_data_expression
			 (packet,
			  (state -> options.
			   server_options [SV_SERVER_NAME] -> expression)));

	/* At this point, we have a lease that we can offer the client.
	   Now we construct a lease structure that contains what we want,
	   and call supersede_lease to do the right thing with it. */

	memset (&lt, 0, sizeof lt);

	/* Use the ip address of the lease that we finally found in
	   the database. */
	lt.ip_addr = lease -> ip_addr;

	/* Start now. */
	lt.starts = cur_time;

	/* Figure out how long a lease to assign.    If this is a
	   dynamic BOOTP lease, its duration must be infinite. */
	if (offer) {
		if (packet -> options [DHO_DHCP_LEASE_TIME].len ==
		    sizeof (u_int32_t)) {
			lease_time = getULong
				(packet -> options [DHO_DHCP_LEASE_TIME].data);	
			comp_lease_time = DEFAULT_MAX_LEASE_TIME;
			i = SV_MAX_LEASE_TIME;
			if (state ->
			    options.server_options [i]) {
				d1 = evaluate_data_expression
					(packet,
					 state -> options.
					 server_options [i] -> expression);
				if (d1.len == sizeof (u_int32_t))
					comp_lease_time = getULong (d1.data);
			}

			/* Enforce the maximum lease length. */
			if (lease_time > comp_lease_time)
				lease_time = comp_lease_time;
			
		} else {
			i = SV_DEFAULT_LEASE_TIME;
			lease_time = DEFAULT_DEFAULT_LEASE_TIME;
			if (state ->
			    options.server_options [i]) {
				d1 = evaluate_data_expression
					(packet,
					 state -> options.
					 server_options [i] -> expression);
				if (d1.len == sizeof (u_int32_t))
					lease_time = getULong (d1.data);
			}
		}
		
		i = SV_MIN_LEASE_TIME;
		comp_lease_time = DEFAULT_MIN_LEASE_TIME;
		if (state -> options.server_options [i]) {
			d1 = evaluate_data_expression
					(packet,
					 state -> options.
					 server_options [i] -> expression);
			if (d1.len == sizeof (u_int32_t))
				comp_lease_time = getULong (d1.data);
		}

		if (lease_time < comp_lease_time)
			lease_time = comp_lease_time;

		state -> offered_expiry = cur_time + lease_time;
		if (when)
			lt.ends = when;
		else
			lt.ends = state -> offered_expiry;
	} else {
		lease_time = MAX_TIME - cur_time;

		i = SV_BOOTP_LEASE_LENGTH;
		if (state -> options.server_options [i]) {
			d1 = evaluate_data_expression
					(packet,
					 state -> options.
					 server_options [i] -> expression);
			if (d1.len == sizeof (u_int32_t))
				lease_time = getULong (d1.data);
		}

		i = SV_BOOTP_LEASE_CUTOFF;
		if (state -> options.server_options [i]) {
			d1 = evaluate_data_expression
					(packet,
					 state -> options.
					 server_options [i] -> expression);
			if (d1.len == sizeof (u_int32_t))
				lease_time = getULong (d1.data) - cur_time;
		}

		lt.ends = state -> offered_expiry = cur_time + lease_time;
		lt.flags = BOOTP_LEASE;
	}

	lt.timestamp = cur_time;

	/* Record the uid, if given... */
	i = DHO_DHCP_CLIENT_IDENTIFIER;
	if (packet -> options [i].len) {
		if (packet -> options [i].len <= sizeof lt.uid_buf) {
			memcpy (lt.uid_buf, packet -> options [i].data,
				packet -> options [i].len);
			lt.uid = lt.uid_buf;
			lt.uid_max = sizeof lt.uid_buf;
			lt.uid_len = packet -> options [i].len;
		} else {
			lt.uid_max = lt.uid_len = packet -> options [i].len;
			lt.uid = (unsigned char *)malloc (lt.uid_max);
			if (!lt.uid)
				error ("can't allocate memory for large uid.");
			memcpy (lt.uid,
				packet -> options [i].data, lt.uid_len);
		}
	}

	lt.host = lease -> host;
	lt.subnet = lease -> subnet;
	lt.shared_network = lease -> shared_network;

	/* Don't call supersede_lease on a mocked-up lease. */
	if (lease -> flags & STATIC_LEASE) {
		/* Copy the hardware address into the static lease
		   structure. */
		lease -> hardware_addr.hlen = packet -> raw -> hlen;
		lease -> hardware_addr.htype = packet -> raw -> htype;
		memcpy (lease -> hardware_addr.haddr, packet -> raw -> chaddr,
			sizeof packet -> raw -> chaddr); /* XXX */
	} else {
		/* Record the hardware address, if given... */
		lt.hardware_addr.hlen = packet -> raw -> hlen;
		lt.hardware_addr.htype = packet -> raw -> htype;
		memcpy (lt.hardware_addr.haddr, packet -> raw -> chaddr,
			sizeof packet -> raw -> chaddr);

		/* Install the new information about this lease in the
		   database.  If this is a DHCPACK or a dynamic BOOTREPLY
		   and we can't write the lease, don't ACK it (or BOOTREPLY
		   it) either. */

		if (!(supersede_lease (lease, &lt, !offer || offer == DHCPACK)
		      || (offer && offer != DHCPACK)))
			return;
	}

	/* Remember the interface on which the packet arrived. */
	state -> ip = packet -> interface;

	/* Set a flag if this client is a lame Microsoft client that NUL
	   terminates string options and expects us to do likewise. */
	if (packet -> options [DHO_HOST_NAME].data &&
	    packet -> options [DHO_HOST_NAME].data
	    [packet -> options [DHO_HOST_NAME].len - 1] == '\0')
		lease -> flags |= MS_NULL_TERMINATION;
	else
		lease -> flags &= ~MS_NULL_TERMINATION;

	/* Remember the giaddr, xid, secs, flags and hops. */
	state -> giaddr = packet -> raw -> giaddr;
	state -> ciaddr = packet -> raw -> ciaddr;
	state -> xid = packet -> raw -> xid;
	state -> secs = packet -> raw -> secs;
	state -> bootp_flags = packet -> raw -> flags;
	state -> hops = packet -> raw -> hops;
	state -> offer = offer;

	/* Get the Maximum Message Size option from the packet, if one
	   was sent. */
	if (packet -> options [DHO_DHCP_MAX_MESSAGE_SIZE].data) {
		state -> max_message_size =
			getUShort (packet ->
				   options [DHO_DHCP_MAX_MESSAGE_SIZE].data);
	}

	/* Now, if appropriate, put in DHCP-specific options that
           override those. */
	if (state -> offer) {
		i = DHO_DHCP_MESSAGE_TYPE;
		state -> options.dhcp_options [i] =
			option_cache (make_const_data (&state -> offer,
						       sizeof state -> offer,
						       0, 0),
				      dhcp_universe.options [i]);

		i = DHO_DHCP_SERVER_IDENTIFIER;
		if (!state -> options.dhcp_options [i]) {
			state -> options.dhcp_options [i] =
				(option_cache
				 (make_const_data
				  ((unsigned char *)
				   &state -> ip -> primary_address,
				   sizeof state -> ip -> primary_address,
				   0, 0),
				  dhcp_universe.options [i]));
		}

		offered_lease_time =
			state -> offered_expiry - cur_time;

		putULong ((unsigned char *)&state -> expiry,
			  offered_lease_time);
		i = DHO_DHCP_LEASE_TIME;
		if (state -> options.dhcp_options [i])
			warn ("dhcp-lease-time option for %s overridden.",
			      inet_ntoa (state -> ciaddr));
		state -> options.dhcp_options [i] =
			option_cache (make_const_data ((unsigned char *)
						       &state -> expiry,
						       sizeof state -> expiry,
						       0, 0),
				      dhcp_universe.options [i]);

		/* Renewal time is lease time * 0.5. */
		offered_lease_time /= 2;
		putULong ((unsigned char *)&state -> renewal,
			  offered_lease_time);
		i = DHO_DHCP_RENEWAL_TIME;
		if (state -> options.dhcp_options [i])
			warn ("dhcp-renewal-time option for %s overridden.",
			      inet_ntoa (state -> ciaddr));
		state -> options.dhcp_options [i] =
			option_cache (make_const_data ((unsigned char *)
						       &state -> renewal,
						       sizeof state -> renewal,
						       0, 0),
				      dhcp_universe.options [i]);

		/* Rebinding time is lease time * 0.875. */
		offered_lease_time += (offered_lease_time / 2
				       + offered_lease_time / 4);
		putULong ((unsigned char *)&state -> rebind,
			  offered_lease_time);
		i = DHO_DHCP_REBINDING_TIME;
		if (state -> options.dhcp_options [i])
			warn ("dhcp-rebinding-time option for %s overridden.",
			      inet_ntoa (state -> ciaddr));
		state -> options.dhcp_options [i] =
			option_cache (make_const_data ((unsigned char *)
						       &state -> rebind,
						       sizeof state -> rebind,
						       0, 0),
				      dhcp_universe.options [i]);
	}

	/* Use the subnet mask from the subnet declaration if no other
	   mask has been provided. */
	i = DHO_SUBNET_MASK;
	if (!state -> options.dhcp_options [i]) {
		state -> options.dhcp_options [i] =
			(option_cache
			 (make_const_data (lease -> subnet -> netmask.iabuf,
					   lease -> subnet -> netmask.len,
					   0, 0),
			  dhcp_universe.options [i]));
	}

	/* Use the hostname from the host declaration if there is one
	   and no hostname has otherwise been provided, and if the 
	   use-host-decl-name flag is set. */
	i = DHO_HOST_NAME;
	if (!state -> options.dhcp_options [i] &&
	    lease -> host && lease -> host -> name) {
		d1 = evaluate_data_expression
			(packet, (state -> options.server_options
				  [SV_USE_HOST_DECL_NAMES] -> expression));
		if (d1.len && d1.data [0]) {
			state -> options.dhcp_options [i] =
				(option_cache
				 (make_const_data (lease -> host -> name,
						   strlen (lease ->
							   host -> name),
						   1, 0),
				  dhcp_universe.options [i]));
		}
	}

	/* If we don't have a hostname yet, and we've been asked to do
	   a reverse lookup to find the hostname, do it. */
	if (!state -> options.dhcp_options [i]
	    && state -> options.server_options [SV_GET_LEASE_HOSTNAMES]) {
		d1 = evaluate_data_expression
			(packet, (state -> options.server_options
				  [SV_GET_LEASE_HOSTNAMES] -> expression));
		if (d1.len && d1.data [0]) {
			struct in_addr ia;
			struct hostent *h;

			memcpy (&ia, lease -> ip_addr.iabuf, 4);

			h = gethostbyaddr ((char *)&ia, sizeof ia, AF_INET);
			if (!h)
				warn ("No hostname for %s", inet_ntoa (ia));
			else {
				state -> options.dhcp_options [i] =
					option_cache
						(make_const_data
						 (h -> h_name,
						  strlen (h -> h_name) + 1,
						  1, 1),
						 dhcp_universe.options [i]);
			}
		}
	}

	/* If so directed, use the leased IP address as the router address.
	   This supposedly makes Win95 machines ARP for all IP addresses,
	   so if the local router does proxy arp, you win. */

	i = SV_USE_LEASE_ADDR_FOR_DEFAULT_ROUTE;
	if (state -> options.server_options [i]) {
		d1 = evaluate_data_expression
			(packet,
			 state -> options.server_options [i] -> expression);
		if (d1.len && d1.data) {
			i = DHO_ROUTERS;
			
			state -> options.dhcp_options [i] =
				option_cache (make_const_data
					      (lease -> ip_addr.iabuf,
					       lease -> ip_addr.len, 0, 0),
					      dhcp_universe.options [i]);
		}
	}

#ifdef DEBUG_PACKET
	dump_packet (packet);
	dump_raw ((unsigned char *)packet -> raw, packet -> packet_length);
#endif

	lease -> state = state;

	/* If this is a DHCPOFFER, ping the lease address before actually
	   sending the offer. */
	if (offer == DHCPOFFER && !(lease -> flags & STATIC_LEASE)) {
		icmp_echorequest (&lease -> ip_addr);
		add_timeout (cur_time + 1, lease_ping_timeout, lease);
		++outstanding_pings;
	} else {
		dhcp_reply (lease);
	}
}

void dhcp_reply (lease)
	struct lease *lease;
{
	int bufs = 0;
	int packet_length;
	struct dhcp_packet raw;
	struct sockaddr_in to;
	struct in_addr from;
	struct hardware hto;
	int result;
	int i;
	struct lease_state *state = lease -> state;
	int nulltp, bootpp;
	struct agent_options *a, *na;
	struct option_tag *ot, *not;
	struct data_string d1;

	if (!state)
		error ("dhcp_reply was supplied lease with no state!");

	/* Compose a response for the client... */
	memset (&raw, 0, sizeof raw);

	/* Copy in the filename if given; otherwise, flag the filename
	   buffer as available for options. */
	if (state -> filename.len && state -> filename.data) {
		memcpy (raw.file,
			state -> filename.data,
			state -> filename.len > sizeof raw.file
			? sizeof raw.file : state -> filename.len);
		if (sizeof raw.file > state -> filename.len)
			memset (&raw.file [state -> filename.len], 0,
				(sizeof raw.file) - state -> filename.len);
	} else
		bufs |= 1;

	/* Copy in the server name if given; otherwise, flag the
	   server_name buffer as available for options. */
	if (state -> server_name.len && state -> server_name.data) {
		memcpy (raw.sname,
			state -> server_name.data,
			state -> server_name.len > sizeof raw.sname
			? sizeof raw.sname : state -> server_name.len);
		if (sizeof raw.sname > state -> server_name.len)
			memset (&raw.sname [state -> server_name.len], 0,
				(sizeof raw.sname) - state -> server_name.len);
	} else
		bufs |= 2; /* XXX */

	memcpy (raw.chaddr, lease -> hardware_addr.haddr, sizeof raw.chaddr);
	raw.hlen = lease -> hardware_addr.hlen;
	raw.htype = lease -> hardware_addr.htype;

	/* See if this is a Microsoft client that NUL-terminates its
	   strings and expects us to do likewise... */
	if (lease -> flags & MS_NULL_TERMINATION)
		nulltp = 1;
	else
		nulltp = 0;

	/* See if this is a bootp client... */
	if (state -> offer)
		bootpp = 0;
	else
		bootpp = 1;

	/* Insert such options as will fit into the buffer. */
	packet_length = cons_options ((struct packet *)0, &raw,
				      state -> max_message_size,
				      &state -> options,
				      bufs, nulltp, bootpp);

	/* Having done the cons_options(), we can release the tree_cache
	   entries. */
	for (i = 0; i < 256; i++) {
		if (state -> options.dhcp_options [i])
			free_option_cache (state -> options.dhcp_options [i],
					   "dhcp_reply");
		if (state -> options.server_options [i])
			free_option_cache (state -> options.dhcp_options [i],
					   "dhcp_reply");
		
	}

	/* We can also release the agent options, if any... */
	for (a = state -> options.agent_options; a; a = na) {
		na = a -> next;
		for (ot = a -> first; ot; ot = not) {
			not = ot -> next;
			free (ot);
		}
	}

	memcpy (&raw.ciaddr, &state -> ciaddr, sizeof raw.ciaddr);
	memcpy (&raw.yiaddr, lease -> ip_addr.iabuf, 4);

	/* Figure out the address of the next server. */
	raw.siaddr = state -> ip -> primary_address;
	if (state -> options.server_options [SV_NEXT_SERVER]) {
		d1 = evaluate_data_expression
			((struct packet *)0,
			 (state -> options.
			  server_options [SV_NEXT_SERVER] -> expression));
		/* If there was more than one answer, take the first. */
		if (d1.len >= 4 && d1.data)
			memcpy (&raw.siaddr, d1.data, 4);
	}

	raw.giaddr = state -> giaddr;

	raw.xid = state -> xid;
	raw.secs = state -> secs;
	raw.flags = state -> bootp_flags;
	raw.hops = state -> hops;
	raw.op = BOOTREPLY;

	/* Say what we're doing... */
	note ("%s on %s to %s via %s",
	      (state -> offer
	       ? (state -> offer == DHCPACK ? "DHCPACK" : "DHCPOFFER")
	       : "BOOTREPLY"),
	      piaddr (lease -> ip_addr),
	      print_hw_addr (lease -> hardware_addr.htype,
			     lease -> hardware_addr.hlen,
			     lease -> hardware_addr.haddr),
	      state -> giaddr.s_addr
	      ? inet_ntoa (state -> giaddr)
	      : state -> ip -> name);

	/* Set up the hardware address... */
	hto.htype = lease -> hardware_addr.htype;
	hto.hlen = lease -> hardware_addr.hlen;
	memcpy (hto.haddr, lease -> hardware_addr.haddr, hto.hlen);

	to.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	to.sin_len = sizeof to;
#endif
	memset (to.sin_zero, 0, sizeof to.sin_zero);

	from = state -> ip -> primary_address;

#ifdef DEBUG_PACKET
	dump_raw ((unsigned char *)&raw, packet_length);
#endif

	/* Make sure outgoing packets are at least as big
	   as a BOOTP packet. */
	if (packet_length < BOOTP_MIN_LEN)
		packet_length = BOOTP_MIN_LEN;

	/* If this was gatewayed, send it back to the gateway... */
	if (raw.giaddr.s_addr) {
		to.sin_addr = raw.giaddr;
		to.sin_port = local_port;

#ifdef USE_FALLBACK
		result = send_fallback (&fallback_interface,
					(struct packet *)0,
					&raw, packet_length,
					raw.siaddr, &to, &hto);
		if (result < 0)
			warn ("send_fallback: %m");

		free_lease_state (state, "dhcp_reply fallback 1");
		lease -> state = (struct lease_state *)0;
		return;
#endif

	/* If it comes from a client who already knows its address and
	   is not requesting a broadcast response, sent it directly to
	   that client. */
	} else if (raw.ciaddr.s_addr && state -> offer == DHCPACK &&
		   !(raw.flags & htons (BOOTP_BROADCAST))) {
		to.sin_addr = state -> ciaddr;
		to.sin_port = remote_port; /* XXX */

#ifdef USE_FALLBACK
		result = send_fallback (&fallback_interface,
					(struct packet *)0,
					&raw, packet_length,
					raw.siaddr, &to, &hto);
		if (result < 0)
			warn ("send_fallback: %m");
		free_lease_state (state, "dhcp_reply fallback 1");
		lease -> state = (struct lease_state *)0;
		return;
#endif

	/* Otherwise, broadcast it on the local network. */
	} else {
		to.sin_addr.s_addr = htonl (INADDR_BROADCAST);
		to.sin_port = remote_port; /* XXX */
	}


	result = send_packet (state -> ip,
			      (struct packet *)0, &raw, packet_length,
			      raw.siaddr, &to, &hto);
	if (result < 0)
		warn ("sendpkt: %m");

	free_lease_state (state, "dhcp_reply");
	lease -> state = (struct lease_state *)0;
}

struct lease *find_lease (packet, share, ours)
	struct packet *packet;
	struct shared_network *share;
	int *ours;
{
	struct lease *uid_lease, *ip_lease, *hw_lease;
	struct lease *lease = (struct lease *)0;
	struct iaddr cip;
	struct host_decl *hp, *host = (struct host_decl *)0;
	struct lease *fixed_lease;
	int i;

	/* Try to find a host or lease that's been assigned to the
	   specified unique client identifier. */
	if (packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].len) {
		/* First, try to find a fixed host entry for the specified
		   client identifier... */
		hp = find_hosts_by_uid (packet -> options
					[DHO_DHCP_CLIENT_IDENTIFIER].data,
					packet -> options
					[DHO_DHCP_CLIENT_IDENTIFIER].len);
		if (hp) {
			host = hp;
			fixed_lease = mockup_lease (packet, share, hp);
			uid_lease = (struct lease *)0;
		} else {
			uid_lease = find_lease_by_uid
				(packet -> options
				 [DHO_DHCP_CLIENT_IDENTIFIER].data,
				 packet -> options
				 [DHO_DHCP_CLIENT_IDENTIFIER].len);
			/* Find the lease matching this uid that's on the
			   network the packet came from (if any). */
			for (; uid_lease; uid_lease = uid_lease -> n_uid)
				if (uid_lease -> shared_network == share)
					break;
			fixed_lease = (struct lease *)0;
			if (uid_lease &&
			    (uid_lease -> flags & ABANDONED_LEASE))
				uid_lease = (struct lease *)0;
		}
	} else {
		uid_lease = (struct lease *)0;
		fixed_lease = (struct lease *)0;
	}

	/* If we didn't find a fixed lease using the uid, try doing
	   it with the hardware address... */
	if (!fixed_lease) {
		hp = find_hosts_by_haddr (packet -> raw -> htype,
					  packet -> raw -> chaddr,
					  packet -> raw -> hlen);
		if (hp) {
			host = hp; /* Save it for later. */
			fixed_lease = mockup_lease (packet, share, hp);
		}
	}

	/* Try to find a lease that's been attached to the client's
	   hardware address... */
	hw_lease = find_lease_by_hw_addr (packet -> raw -> chaddr,
					  packet -> raw -> hlen);
	/* Find the lease that's on the network the packet came from
	   (if any). */
	for (; hw_lease; hw_lease = hw_lease -> n_hw) {
		if (hw_lease -> shared_network == share) {
			if (hw_lease -> flags & ABANDONED_LEASE)
				continue;
			if (packet -> packet_type)
				break;
			if (hw_lease -> flags &
			    (BOOTP_LEASE | DYNAMIC_BOOTP_OK))
				break;
		}
	}

	/* Try to find a lease that's been allocated to the client's
	   IP address. */
	if (packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len &&
	    packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len == 4) {
		cip.len = 4;
		memcpy (cip.iabuf,
			packet -> options [DHO_DHCP_REQUESTED_ADDRESS].data,
			cip.len);
		ip_lease = find_lease_by_ip_addr (cip);
	} else if (packet -> raw -> ciaddr.s_addr) {
		cip.len = 4;
		memcpy (cip.iabuf, &packet -> raw -> ciaddr, 4);
		ip_lease = find_lease_by_ip_addr (cip);
	} else
		ip_lease = (struct lease *)0;

	/* If ip_lease is valid at this point, set ours to one, so that
	   even if we choose a different lease, we know that the address
	   the client was requesting was ours, and thus we can NAK it. */
	if (ip_lease && ours)
		*ours = 1;

	/* If the requested IP address isn't on the network the packet
	   came from, or if it's been abandoned, don't use it. */
	if (ip_lease && (ip_lease -> shared_network != share ||
			 (ip_lease -> flags & ABANDONED_LEASE)))
		ip_lease = (struct lease *)0;

	/* Toss ip_lease if it hasn't yet expired and the uid doesn't
	   match */
	if (ip_lease &&
	    ip_lease -> ends >= cur_time &&
	    ip_lease -> uid && ip_lease != uid_lease) {
		int i = DHO_DHCP_CLIENT_IDENTIFIER;
		/* If for some reason the client has more than one lease
		   on the subnet that matches its uid, pick the one that
		   it asked for. */
		if (packet -> options [i].data &&
		    ip_lease -> uid_len ==  packet -> options [i].len &&
		    !memcmp (packet -> options [i].data,
			     ip_lease -> uid, ip_lease -> uid_len)) {
			if (uid_lease -> ends > cur_time)
				warn ("client %s has duplicate leases on %s",
				      print_hw_addr (packet -> raw -> htype,
						     packet -> raw -> hlen,
						     packet -> raw -> chaddr),
				      ip_lease -> shared_network -> name);

			/* If the client is REQUESTing the lease, it shouldn't
			   still be using the old one, so we can free it for
			   allocation.   This is only true if the duplicate
			   lease is on the same network, of course. */

			if (packet -> packet_type == DHCPREQUEST &&
			    share == uid_lease -> shared_network)
				dissociate_lease (uid_lease);

			uid_lease = ip_lease;
		}
		ip_lease = (struct lease *)0;
	}

	/* Toss hw_lease if it hasn't yet expired and the uid doesn't
	   match, except that if the hardware address matches and the
	   client is now doing dynamic BOOTP (and thus hasn't provided
	   a uid) we let the client get away with it. */
	if (hw_lease &&
	    hw_lease -> ends >= cur_time &&
	    hw_lease -> uid &&
	    packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].len &&
	    hw_lease != uid_lease)
		hw_lease = (struct lease *)0;

	/* Toss extra pointers to the same lease... */
	if (ip_lease == hw_lease)
		ip_lease = (struct lease *)0;
	if (hw_lease == uid_lease)
		hw_lease = (struct lease *)0;
	if (ip_lease == uid_lease)
		ip_lease = (struct lease *)0;

	/* If we got an ip address lease, make sure it isn't assigned to
	   some *other* client!   If it was assigned to this client, we'd
	   have zeroed it out above, so the only way we can take it at this
	   point is if some other client had it but it's timed out, or if no
	   other client has ever had it. */
	if (ip_lease &&
	    ip_lease -> ends >= cur_time)
		ip_lease = (struct lease *)0;

	/* If we've already eliminated the lease, it wasn't there to
	   begin with.   If we have come up with a matching lease,
	   set the message to bad network in case we have to throw it out. */
	if (!ip_lease && !hw_lease && !uid_lease) {
		strcpy (dhcp_message, "requested address not available");
	} else {
		strcpy (dhcp_message, "requested address on bad subnet");
	}

	/* Now eliminate leases that are on the wrong network... */
	if (ip_lease &&
	    (share != ip_lease -> shared_network)) {
		release_lease (ip_lease);
		ip_lease = (struct lease *)0;
	}
	if (uid_lease &&
	    (share != uid_lease -> shared_network)) {
		release_lease (uid_lease);
		uid_lease = (struct lease *)0;
	}
	if (hw_lease &&
	    (share != hw_lease -> shared_network)) {
		release_lease (hw_lease);
		hw_lease = (struct lease *)0;
	}

	/* At this point, if fixed_lease is nonzero, we can assign it to
	   this client. */
	if (fixed_lease) {
		lease = fixed_lease;
	}

	/* If we got a lease that matched the ip address and don't have
	   a better offer, use that; otherwise, release it. */
	if (ip_lease) {
		if (lease) {
			if (packet -> packet_type == DHCPREQUEST)
				release_lease (ip_lease);
		} else {
			lease = ip_lease;
			lease -> host = (struct host_decl *)0;
		}
	}

	/* If we got a lease that matched the client identifier, we may want
	   to use it, but if we already have a lease we like, we must free
	   the lease that matched the client identifier. */
	if (uid_lease) {
		if (lease) {
			if (packet -> packet_type == DHCPREQUEST)	
				dissociate_lease (uid_lease);
		} else {
			lease = uid_lease;
			lease -> host = (struct host_decl *)0;
		}
	}

	/* The lease that matched the hardware address is treated likewise. */
	if (hw_lease) {
		if (lease) {
			if (packet -> packet_type == DHCPREQUEST)	
				dissociate_lease (hw_lease);
		} else {
			lease = hw_lease;
			lease -> host = (struct host_decl *)0;
		}
	}

	/* If we found a host_decl but no matching address, try to
	   find a host_decl that has no address, and if there is one,
	   hang it off the lease so that we can use the supplied
	   options. */
	if (lease && host && !lease -> host) {
		for (; host; host = host -> n_ipaddr) {
			if (!host -> fixed_addr) {
				lease -> host = host;
				break;
			}
		}
	}

	return lease;
}

/* Search the provided host_decl structure list for an address that's on
   the specified shared network.  If one is found, mock up and return a
   lease structure for it; otherwise return the null pointer. */

struct lease *mockup_lease (packet, share, hp)
	struct packet *packet;
	struct shared_network *share;
	struct host_decl *hp;
{
	static struct lease mock;
	
	mock.subnet = find_host_for_network (&hp, &mock.ip_addr, share);
	if (!mock.subnet)
		return (struct lease *)0;
	mock.next = mock.prev = (struct lease *)0;
	mock.shared_network = mock.subnet -> shared_network;
	mock.host = hp;
	mock.uid = hp -> client_identifier.data;
	mock.uid_len = hp -> client_identifier.len;
	mock.hardware_addr = hp -> interface;
	mock.starts = mock.timestamp = mock.ends = MIN_TIME;
	mock.flags = STATIC_LEASE;
	return &mock;
}
