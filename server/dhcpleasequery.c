/*
 * Copyright (C) 2006-2007 by Internet Systems Consortium, Inc. ("ISC")
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

#include "dhcpd.h"

/*
 * TODO: RFC4388 specifies that the server SHOULD store the
 *       vendor-class-id.
 *
 * TODO: RFC4388 specifies that the server SHOULD return the same
 *       options it would for a DHCREQUEST message, if no Parameter
 *       Request List option (option 55) is passed. We do not do that.
 *
 * TODO: RFC4388 specifies the creation of a "non-sensitive options"
 *       configuration list, and that these SHOULD be returned. We
 *       have no such list.
 *
 * TODO: RFC4388 says the server SHOULD use RFC3118, "Authentication
 *       for DHCP Messages".
 *
 * TODO: RFC4388 specifies that you SHOULD insure that you cannot be
 *       DoS'ed by DHCPLEASEQUERY message.
 */

/* 
 * If you query by hardware address or by client ID, then you may have
 * more than one IP address for your query argument. We need to do two
 * things:
 *
 *   1. Find the most recent lease.
 *   2. Find all additional IP addresses for the query argument.
 *
 * We do this by looking through all of the leases associated with a
 * given hardware address or client ID. We use the cltt (client last
 * transaction time) of the lease, which only has a resolution of one
 * second, so we might not actually give the very latest IP.
 */

static struct lease*
next_hw(const struct lease *lease) {
	/* INSIST(lease != NULL); */
	return lease->n_hw;
}

static struct lease*
next_uid(const struct lease *lease) {
	/* INSIST(lease != NULL); */
	return lease->n_uid;
}

void
get_newest_lease(struct lease **retval,
		 struct lease *lease,
		 struct lease *(*next)(const struct lease *)) {

	struct lease *p;
	struct lease *newest;

	/* INSIST(newest != NULL); */
	/* INSIST(next != NULL); */

	*retval = NULL;

	if (lease == NULL) {
		return;
	}

	newest = lease;
	for (p=next(lease); p != NULL; p=next(p)) {
		if (newest->binding_state == FTS_ACTIVE) {
			if ((p->binding_state == FTS_ACTIVE) && 
		    	(p->cltt > newest->cltt)) {
				newest = p;
			}
		} else {
			if (p->ends > newest->ends) {
				newest = p;
			}
		}
	}

	lease_reference(retval, newest, MDL);
}

static int
get_associated_ips(const struct lease *lease,
		   struct lease *(*next)(const struct lease *), 
		   const struct lease *newest,
		   u_int32_t *associated_ips,
		   unsigned int associated_ips_size) {

	const struct lease *p;
	int cnt;

	/* INSIST(next != NULL); */
	/* INSIST(associated_ips != NULL); */

	if (lease == NULL) {
		return 0;
	}

	cnt = 0;
	for (p=lease; p != NULL; p=next(p)) {
		if ((p->binding_state == FTS_ACTIVE) && (p != newest)) {
			if (cnt < associated_ips_size) {
				memcpy(&associated_ips[cnt],
				       p->ip_addr.iabuf,
				       sizeof(associated_ips[cnt]));
			}
			cnt++;
		}
	}
	return cnt;
}


void 
dhcpleasequery(struct packet *packet, int ms_nulltp) {
	char msgbuf[256];
	char dbg_info[128];
	struct iaddr cip;
	struct iaddr gip;
	struct data_string uid;
	struct hardware h;
	struct lease *tmp_lease;
	struct lease *lease;
	int want_associated_ip;
	int assoc_ip_cnt;
	u_int32_t assoc_ips[40];  /* XXXSK: arbitrary maximum number of IPs */
	const int nassoc_ips = sizeof(assoc_ips) / sizeof(assoc_ips[0]);

	unsigned char dhcpMsgType;
	const char *dhcp_msg_type_name;
	struct subnet *subnet;
	struct option_state *options;
	struct option_cache *oc;
	int allow_leasequery;
	int ignorep;
	u_int32_t lease_duration;
	u_int32_t time_renewal;
	u_int32_t time_rebinding;
	u_int32_t time_expiry;
	u_int32_t client_last_transaction_time;
	struct sockaddr_in to;
	struct in_addr siaddr;
	struct data_string prl;
	struct data_string *prl_ptr;

	int i;
	struct interface_info *interface;

	/* INSIST(packet != NULL); */

	/*
	 * Prepare log information.
	 */
	snprintf(msgbuf, sizeof(msgbuf), 
		"DHCPLEASEQUERY from %s", inet_ntoa(packet->raw->giaddr));

	/* 
	 * We can't reply if there is no giaddr field.
	 */
	if (!packet->raw->giaddr.s_addr) {
		log_info("%s: missing giaddr, ciaddr is %s, no reply sent", 
			 msgbuf, inet_ntoa(packet->raw->ciaddr));
		return;
	}

	/* 
	 * Set up our options, scope, and, um... stuff.
	 * This is basically copied from dhcpinform() in dhcp.c.
	 */
	gip.len = sizeof(packet->raw->giaddr);
	memcpy(gip.iabuf, &packet->raw->giaddr, sizeof(packet->raw->giaddr));

	subnet = NULL;
	find_subnet(&subnet, gip, MDL);
	if (subnet == NULL) {
		log_info("%s: unknown subnet for address %s", 
			 msgbuf, piaddr(gip));
		return;
	}

	options = NULL;
	if (!option_state_allocate(&options, MDL)) {
		subnet_dereference(&subnet, MDL);
		log_error("No memory for option state.");
		log_info("%s: out of memory, no reply sent", msgbuf);
		return;
	}

	execute_statements_in_scope(NULL,
				    packet,
				    NULL,
				    NULL,
				    packet->options,
				    options,
				    &global_scope,
				    subnet->group,
				    NULL);
	for (i=packet->class_count-1; i>=0; i--) {
		execute_statements_in_scope(NULL,
					    packet,
					    NULL,
					    NULL,
					    packet->options,
					    options,
					    &global_scope,
					    packet->classes[i]->group,
					    subnet->group);
	}

	subnet_dereference(&subnet, MDL);

	/* 
	 * Because LEASEQUERY has some privacy concerns, default to deny.
	 */
	allow_leasequery = 0;

	/*
	 * See if we are authorized to do LEASEQUERY.
	 */
	oc = lookup_option(&server_universe, options, SV_LEASEQUERY);
	if (oc != NULL) {
		allow_leasequery = evaluate_boolean_option_cache(&ignorep,
					 packet, NULL, NULL, packet->options,
					 options, &global_scope, oc, MDL);
	}

	if (!allow_leasequery) {
		log_info("%s: LEASEQUERY not allowed, query ignored", msgbuf);
		option_state_dereference(&options, MDL);
		return;
	}
	    

	/* 
	 * Copy out the client IP address.
	 */
	cip.len = sizeof(packet->raw->ciaddr);
	memcpy(cip.iabuf, &packet->raw->ciaddr, sizeof(packet->raw->ciaddr));

	/* 
	 * If the client IP address is valid (not all zero), then we 
	 * are looking for information about that IP address.
	 */
	assoc_ip_cnt = 0;
	lease = tmp_lease = NULL;
	if (memcmp(cip.iabuf, "\0\0\0", 4)) {

		want_associated_ip = 0;

		snprintf(dbg_info, sizeof(dbg_info), "IP %s", piaddr(cip));
		find_lease_by_ip_addr(&lease, cip, MDL);


	} else {

		want_associated_ip = 1;

		/*
		 * If the client IP address is all zero, then we will
		 * either look up by the client identifier (if we have
		 * one), or by the MAC address.
		 */

		memset(&uid, 0, sizeof(uid));
		if (get_option(&uid, 
			       &dhcp_universe,
			       packet,
			       NULL,
			       NULL,
			       packet->options,
			       NULL,
			       packet->options, 
			       &global_scope,
			       DHO_DHCP_CLIENT_IDENTIFIER,
			       MDL)) {

			snprintf(dbg_info, 
				 sizeof(dbg_info), 
				 "client-id %s",
				 print_hex_1(uid.len, uid.data, 60));

			find_lease_by_uid(&tmp_lease, uid.data, uid.len, MDL);
			data_string_forget(&uid, MDL);
			get_newest_lease(&lease, tmp_lease, next_uid);
			assoc_ip_cnt = get_associated_ips(tmp_lease,
							  next_uid, 
							  lease,
							  assoc_ips, 
							  nassoc_ips);

		} else {

			if (packet->raw->hlen+1 > sizeof(h.hbuf)) {
				log_info("%s: hardware length too long, "
					 "no reply sent", msgbuf);
				option_state_dereference(&options, MDL);
				return;
			}

			h.hlen = packet->raw->hlen + 1;
			h.hbuf[0] = packet->raw->htype;
			memcpy(&h.hbuf[1], 
			       packet->raw->chaddr, 
			       packet->raw->hlen);

			snprintf(dbg_info, 
				 sizeof(dbg_info), 
				 "MAC address %s",
				 print_hw_addr(h.hbuf[0], 
					       h.hlen - 1, 
					       &h.hbuf[1]));

			find_lease_by_hw_addr(&tmp_lease, h.hbuf, h.hlen, MDL);
			get_newest_lease(&lease, tmp_lease, next_hw);
			assoc_ip_cnt = get_associated_ips(tmp_lease,
							  next_hw, 
							  lease,
							  assoc_ips, 
							  nassoc_ips);

		}

		lease_dereference(&tmp_lease, MDL);

		if (lease != NULL) {
			memcpy(&packet->raw->ciaddr, 
			       lease->ip_addr.iabuf,
			       sizeof(packet->raw->ciaddr));
		}

		/*
		 * Log if we have too many IP addresses associated
		 * with this client.
		 */
		if (want_associated_ip && (assoc_ip_cnt > nassoc_ips)) {
			log_info("%d IP addresses associated with %s, "
				 "only %d sent in reply.",
				 assoc_ip_cnt, dbg_info, nassoc_ips);
		}
	}

	/*
	 * We now know the query target too, so can report this in 
	 * our log message.
	 */
	snprintf(msgbuf, sizeof(msgbuf), 
		"DHCPLEASEQUERY from %s for %s",
		inet_ntoa(packet->raw->giaddr), dbg_info);

	/*
	 * Figure our our return type.
	 */
	if (lease == NULL) {
		dhcpMsgType = DHCPLEASEUNKNOWN;
		dhcp_msg_type_name = "DHCPLEASEUNKNOWN";
	} else {
		if (lease->binding_state == FTS_ACTIVE) {
			dhcpMsgType = DHCPLEASEACTIVE;
			dhcp_msg_type_name = "DHCPLEASEACTIVE";
		} else {
			dhcpMsgType = DHCPLEASEUNASSIGNED;
			dhcp_msg_type_name = "DHCPLEASEUNASSIGNED";
		}
	}

	/* 
	 * Set options that only make sense if we have an active lease.
	 */

	if (dhcpMsgType == DHCPLEASEACTIVE)
	{

		/* 
		 * Set the hardware address fields.
		 */

		packet->raw->hlen = lease->hardware_addr.hlen - 1;
		packet->raw->htype = lease->hardware_addr.hbuf[0];
		memcpy(packet->raw->chaddr, 
		       &lease->hardware_addr.hbuf[1], 
		       sizeof(packet->raw->chaddr));

		/*
		 * Set client identifier option.
		 */
		if (lease->uid_len > 0) {
			if (!add_option(options,
					DHO_DHCP_CLIENT_IDENTIFIER,
					lease->uid,
					lease->uid_len)) {
				option_state_dereference(&options, MDL);
				lease_dereference(&lease, MDL);
				log_info("%s: out of memory, no reply sent",
					 msgbuf);
				return;
			}
		}


		/*
		 * Calculate T1 and T2, the times when the client
		 * tries to extend its lease on its networking
		 * address.
		 * These seem to be hard-coded in ISC DHCP, to 0.5 and
		 * 0.875 of the lease time.
		 */

		lease_duration = lease->ends - lease->starts;
		time_renewal = lease->starts + 
			(lease_duration / 2);
		time_rebinding = lease->starts + 
			(lease_duration / 2) +
			(lease_duration / 4) +
			(lease_duration / 8);

		if (time_renewal > cur_time) {
			time_renewal = htonl(time_renewal - cur_time);
			if (!add_option(options, 
					DHO_DHCP_RENEWAL_TIME,
					&time_renewal, 
					sizeof(time_renewal))) {
				option_state_dereference(&options, MDL);
				lease_dereference(&lease, MDL);
				log_info("%s: out of memory, no reply sent",
					 msgbuf);
				return;
			}
		}

		if (time_rebinding > cur_time) {
			time_rebinding = htonl(time_rebinding - cur_time);
			if (!add_option(options, 
					DHO_DHCP_REBINDING_TIME,
					&time_rebinding, 
					sizeof(time_rebinding))) {
				option_state_dereference(&options, MDL);
				lease_dereference(&lease, MDL);
				log_info("%s: out of memory, no reply sent",
					 msgbuf);
				return;
			}
		}

		if (lease->ends > cur_time) {
			time_expiry = htonl(lease->ends - cur_time);
			if (!add_option(options, 
					DHO_DHCP_LEASE_TIME,
					&time_expiry, 
					sizeof(time_expiry))) {
				option_state_dereference(&options, MDL);
				lease_dereference(&lease, MDL);
				log_info("%s: out of memory, no reply sent",
					 msgbuf);
				return;
			}
		}


		/*
		 * Set the relay agent info.
		 */

		if (lease->agent_options != NULL) {
			int idx = agent_universe.index;
			struct option_chain_head **tmp1 = 
				(struct option_chain_head **)
				&(options->universes[idx]);
				struct option_chain_head *tmp2 = 
				(struct option_chain_head *)
				lease->agent_options;

			option_chain_head_reference(tmp1, tmp2, MDL);
		}

		/* 
	 	 * Set the client last transaction time.
		 * We check to make sure we have a timestamp. For
		 * lease files that were saved before running a 
		 * timestamp-aware version of the server, this may
		 * not be set.
	 	 */

		if (lease->cltt != MIN_TIME) {
			if (cur_time > lease->cltt) {
				client_last_transaction_time = 
					htonl(cur_time - lease->cltt);
			} else {
				client_last_transaction_time = htonl(0);
			}
			if (!add_option(options, 
					DHO_CLIENT_LAST_TRANSACTION_TIME,
					&client_last_transaction_time,
		     			sizeof(client_last_transaction_time))) {
				option_state_dereference(&options, MDL);
				lease_dereference(&lease, MDL);
				log_info("%s: out of memory, no reply sent",
					 msgbuf);
				return;
			}
		}

		/*
	 	 * Set associated IPs, if requested and there are some.
	 	 */
		if (want_associated_ip && (assoc_ip_cnt > 0)) {
			if (!add_option(options, 
					DHO_ASSOCIATED_IP,
					assoc_ips,
					assoc_ip_cnt * sizeof(assoc_ips[0]))) {
				option_state_dereference(&options, MDL);
				lease_dereference(&lease, MDL);
				log_info("%s: out of memory, no reply sent",
					 msgbuf);
				return;
			}
		}
	}

	/* 
	 * Set the message type.
	 */

	packet->raw->op = BOOTREPLY;

	/*
	 * Set DHCP message type.
	 */
	if (!add_option(options, 
		        DHO_DHCP_MESSAGE_TYPE,
		        &dhcpMsgType, 
			sizeof(dhcpMsgType))) {
		option_state_dereference(&options, MDL);
		lease_dereference(&lease, MDL);
		log_info("%s: error adding option, no reply sent", msgbuf);
		return;
	}

	/*
	 * Log the message we've received.
	 */
	log_info("%s", msgbuf);

	/*
	 * Figure out which address to use to send from.
	 */
	get_server_source_address(&siaddr, options, packet);

	/* 
	 * Set up the option buffer.
	 */

	memset(&prl, 0, sizeof(prl));
	oc = lookup_option(&dhcp_universe, options, 
			   DHO_DHCP_PARAMETER_REQUEST_LIST);
	if (oc != NULL) {
		evaluate_option_cache(&prl, 
				      packet, 
				      NULL,
				      NULL,
				      packet->options,
				      options,
				      &global_scope,
				      oc,
				      MDL);
	}
	if (prl.len > 0) {
		prl_ptr = &prl;
	} else {
		prl_ptr = NULL;
	}

	packet->packet_length = cons_options(packet, 
					     packet->raw, 
					     lease,
					     NULL,
					     0,
					     packet->options,
					     options,
					     &global_scope,
					     0,
					     0,
					     0, 
					     prl_ptr,
					     NULL);

	data_string_forget(&prl, MDL);	/* SK: safe, even if empty */
	option_state_dereference(&options, MDL);
	lease_dereference(&lease, MDL);

	to.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	to.sin_len = sizeof(to);
#endif
	memset(to.sin_zero, 0, sizeof(to.sin_zero));

	/* 
	 * Leasequery packets are be sent to the gateway address.
	 */
	to.sin_addr = packet->raw->giaddr;
	if (packet->raw->giaddr.s_addr != htonl(INADDR_LOOPBACK)) {
		to.sin_port = local_port;
	} else {
		to.sin_port = remote_port; /* XXXSK: For debugging. */
	}

	/* 
	 * The fallback_interface lets us send with a real IP
	 * address. The packet interface sends from all-zeros.
	 */
	if (fallback_interface != NULL) {
		interface = fallback_interface;
	} else {
		interface = packet->interface;
	}

	/*
	 * Report what we're sending.
	 */
	log_info("%s to %s for %s (%d associated IPs)",
		dhcp_msg_type_name, 
		inet_ntoa(to.sin_addr), dbg_info, assoc_ip_cnt);

	send_packet(interface,
		    NULL,
		    packet->raw, 
		    packet->packet_length,
		    siaddr,
		    &to,
		    NULL);
}

