/* bootp.c

   BOOTP Protocol support. */

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
"$Id: bootp.c,v 1.51 1999/07/06 17:07:12 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

void bootp (packet)
	struct packet *packet;
{
	int result;
	struct host_decl *hp;
	struct host_decl *host = (struct host_decl *)0;
	struct packet outgoing;
	struct dhcp_packet raw;
	struct sockaddr_in to;
	struct in_addr from;
	struct hardware hto;
	struct option_state *options = (struct option_state *)0;
	struct subnet *subnet;
	struct lease *lease;
	struct iaddr ip_address;
	int i;
	struct data_string d1;
	struct option_cache *oc;
	char msgbuf [1024];

	if (packet -> raw -> op != BOOTREQUEST)
		return;

	sprintf (msgbuf, "BOOTREQUEST from %s via %s",
		 print_hw_addr (packet -> raw -> htype,
				packet -> raw -> hlen,
				packet -> raw -> chaddr),
		 packet -> raw -> giaddr.s_addr
		 ? inet_ntoa (packet -> raw -> giaddr)
		 : packet -> interface -> name);



	if (!locate_network (packet)) {
		log_info ("%s: network unknown", msgbuf);
		return;
	}

	hp = find_hosts_by_haddr (packet -> raw -> htype,
				  packet -> raw -> chaddr,
				  packet -> raw -> hlen);

	lease = find_lease (packet, packet -> shared_network, 0);

	/* Find an IP address in the host_decl that matches the
	   specified network. */
	if (hp)
		subnet = find_host_for_network (&hp, &ip_address,
						packet -> shared_network);
	else
		subnet = (struct subnet *)0;

	if (!subnet) {
		/* We didn't find an applicable host declaration.
		   Just in case we may be able to dynamically assign
		   an address, see if there's a host declaration
		   that doesn't have an ip address associated with it. */
		if (hp) {
			for (; hp; hp = hp -> n_ipaddr) {
				if (!hp -> fixed_addr) {
					host = hp;
					break;
				}
			}
		}

		/* If a lease has already been assigned to this client,
		   use it. */
		if (lease) {
			ack_lease (packet, lease, 0, 0, msgbuf);
			return;
		}

		/* Otherwise, try to allocate one. */
		lease = allocate_lease (packet,
					packet -> shared_network -> pools, 0);
		if (lease) {
			lease -> host = host;
			ack_lease (packet, lease, 0, 0, msgbuf);
			return;
		}
		log_info ("%s: no available leases", msgbuf);
		return;
	}

	/* Run the executable statements to compute the client and server
	   options. */
	option_state_allocate (&options, "bootrequest");
	
	/* Execute the subnet statements. */
	execute_statements_in_scope (packet, lease, packet -> options, options,
				     lease -> subnet -> group,
				     (struct group *)0);
	
	/* Execute statements from class scopes. */
	for (i = packet -> class_count; i > 0; i--) {
		execute_statements_in_scope
			(packet, lease, packet -> options, options,
			 packet -> classes [i - 1] -> group,
			 lease -> subnet -> group);
	}

	/* Execute the host statements. */
	execute_statements_in_scope (packet, lease, packet -> options, options,
				     hp -> group, subnet -> group);
	
	/* Drop the request if it's not allowed for this client. */
	if (evaluate_boolean_option_cache (packet, options, lease,
					   lookup_option (&server_universe,
							  options,
							  SV_ALLOW_BOOTP))) {
		log_info ("%s: bootp disallowed", msgbuf);
		option_state_dereference (&options, "bootrequest");
		return;
	} 

	if (evaluate_boolean_option_cache (packet, options, lease,
					   lookup_option (&server_universe,
							  options,
							  SV_ALLOW_BOOTING))) {
		log_info ("%s: booting disallowed", msgbuf);
		option_state_dereference (&options, "bootrequest");
		return;
	}

	/* Set up the outgoing packet... */
	memset (&outgoing, 0, sizeof outgoing);
	memset (&raw, 0, sizeof raw);
	outgoing.raw = &raw;

	/* If we didn't get a known vendor magic number on the way in,
	   just copy the input options to the output. */
	if (!packet -> options_valid &&
	    !(evaluate_boolean_option_cache
	      (packet, options, lease,
	       lookup_option (&server_universe, options,
			      SV_ALWAYS_REPLY_RFC1048)))) {
		memcpy (outgoing.raw -> options,
			packet -> raw -> options, DHCP_OPTION_LEN);
		outgoing.packet_length = BOOTP_MIN_LEN;
	} else {

		/* Use the subnet mask from the subnet declaration if no other
		   mask has been provided. */

		oc = (struct option_cache *)0;
		i = DHO_SUBNET_MASK;
		if (!lookup_option (&dhcp_universe, options, i)) {
			if (option_cache_allocate (&oc, "ack_lease")) {
				if (make_const_data
				    (&oc -> expression,
				     lease -> subnet -> netmask.iabuf,
				     lease -> subnet -> netmask.len, 0, 0)) {
					oc -> option =
						dhcp_universe.options [i];
					save_option (&dhcp_universe,
						     options, oc);
				}
				option_cache_dereference (&oc, "ack_lease");
			}
		}

		/* Pack the options into the buffer.  Unlike DHCP, we
		   can't pack options into the filename and server
		   name buffers. */

		outgoing.packet_length =
			cons_options (packet, outgoing.raw, lease, 0, options,
				      0, 0, 1, (struct data_string *)0);
		if (outgoing.packet_length < BOOTP_MIN_LEN)
			outgoing.packet_length = BOOTP_MIN_LEN;
	}

	/* Take the fields that we care about... */
	raw.op = BOOTREPLY;
	raw.htype = packet -> raw -> htype;
	raw.hlen = packet -> raw -> hlen;
	memcpy (raw.chaddr, packet -> raw -> chaddr, sizeof raw.chaddr);
	raw.hops = packet -> raw -> hops;
	raw.xid = packet -> raw -> xid;
	raw.secs = packet -> raw -> secs;
	raw.flags = packet -> raw -> flags;
	raw.ciaddr = packet -> raw -> ciaddr;
	memcpy (&raw.yiaddr, ip_address.iabuf, sizeof raw.yiaddr);

	/* If we're always supposed to broadcast to this client, set
	   the broadcast bit in the bootp flags field. */
	if ((oc = lookup_option (&server_universe,
				options, SV_ALWAYS_BROADCAST)) &&
	    evaluate_boolean_option_cache (packet, packet -> options,
					   lease, oc))
		raw.flags |= htons (BOOTP_BROADCAST);

	/* Figure out the address of the next server. */
	memset (&d1, 0, sizeof d1);
	oc = lookup_option (&server_universe, options, SV_NEXT_SERVER);
	if (oc &&
	    evaluate_option_cache (&d1, packet, options, lease, oc)) {
		/* If there was more than one answer, take the first. */
		if (d1.len >= 4 && d1.data)
			memcpy (&raw.siaddr, d1.data, 4);
		data_string_forget (&d1, "bootrequest");
	} else {
		if (lease -> subnet -> shared_network -> interface)
			raw.siaddr = (lease -> subnet -> shared_network ->
				      interface -> primary_address);
		else
			raw.siaddr = packet -> interface -> primary_address;
	}

	raw.giaddr = packet -> raw -> giaddr;

	/* Figure out the filename. */
	oc = lookup_option (&server_universe, options, SV_FILENAME);
	if (oc &&
	    evaluate_option_cache (&d1, packet, options, lease, oc)) {
		memcpy (raw.file, d1.data,
			d1.len > sizeof raw.file ? sizeof raw.file : d1.len);
		if (sizeof raw.file > d1.len)
			memset (&raw.file [d1.len],
				0, (sizeof raw.file) - d1.len);
		data_string_forget (&d1, "bootrequest");
	} else
		memcpy (raw.file, packet -> raw -> file, sizeof raw.file);

	/* Choose a server name as above. */
	oc = lookup_option (&server_universe, options, SV_SERVER_NAME);
	if (oc &&
	    evaluate_option_cache (&d1, packet, options, lease, oc)) {
		memcpy (raw.sname, d1.data,
			d1.len > sizeof raw.sname ? sizeof raw.sname : d1.len);
		if (sizeof raw.sname > d1.len)
			memset (&raw.sname [d1.len],
				0, (sizeof raw.sname) - d1.len);
		data_string_forget (&d1, "bootrequest");
	}

	/* We're done with the option state. */
	option_state_dereference (&options, "bootrequest");

	/* Set up the hardware destination address... */
	hto.htype = packet -> raw -> htype;
	hto.hlen = packet -> raw -> hlen;
	memcpy (hto.haddr, packet -> raw -> chaddr, hto.hlen);

	from = packet -> interface -> primary_address;

	/* Report what we're doing... */
	log_info ("%s", msgbuf);
	log_info ("BOOTREPLY for %s to %s (%s) via %s",
	      piaddr (ip_address), hp -> name,
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      packet -> raw -> giaddr.s_addr
	      ? inet_ntoa (packet -> raw -> giaddr)
	      : packet -> interface -> name);

	/* Set up the parts of the address that are in common. */
	to.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	to.sin_len = sizeof to;
#endif
	memset (to.sin_zero, 0, sizeof to.sin_zero);

	/* If this was gatewayed, send it back to the gateway... */
	if (raw.giaddr.s_addr) {
		to.sin_addr = raw.giaddr;
		to.sin_port = local_port;

		if (fallback_interface) {
			result = send_packet (fallback_interface,
					      (struct packet *)0,
					      &raw, outgoing.packet_length,
					      from, &to, &hto);
			return;
		}
	/* Otherwise, broadcast it on the local network. */
	} else {
		to.sin_addr = limited_broadcast;
		to.sin_port = remote_port; /* XXX */
	}

	errno = 0;
	result = send_packet (packet -> interface,
			      packet, &raw, outgoing.packet_length,
			      from, &to, &hto);
}
