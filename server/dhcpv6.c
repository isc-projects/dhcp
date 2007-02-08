/*
 * Copyright (C) 2006-2007  Internet Systems Consortium, Inc. ("ISC")
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
 * XXX: RFC 3315 section 15 states:
 *    A server MUST discard any Solicit, Confirm, Rebind or
 *    Information-request messages it receives with a unicast destination
 *    address.
 * We currently use a single socket for receiving unicast and multicast 
 * packets, and have no way to know what address the packet was sent to.
 * This will need to be fixed, but requires a bit of refactoring. -Shane
 */

/*
 * We use print_hex_1() to output DUID values. We could actually output 
 * the DUID with more information... MAC address if using type 1 or 3, 
 * and so on. However, RFC 3315 contains Grave Warnings against actually 
 * attempting to understand a DUID.
 */

/* 
 * TODO: gettext() or other method of localization for the messages
 *       for status codes (and probably for log formats eventually)
 * TODO: refactoring (simplify, simplify, simplify)
 * TODO: simplify server ID
 */

/* 
 * Prototypes local to this file.
 */
static void build_dhcpv6_reply(struct data_string *, struct packet *);

/*
 * DUID time starts 2000-01-01.
 * This constant is the number of seconds since 1970-01-01,
 * when the Unix epoch began.
 */
#define DUID_TIME_EPOCH 946684800

/*
 * This function returns the time since DUID time start for the
 * given time_t value.
 */
static u_int32_t
duid_time(time_t when) {
	/*
	 * This time is modulo 2^32.
	 */
	while ((when - DUID_TIME_EPOCH) > 4294967295u) {
		/* use 2^31 to avoid spurious compiler warnings */
		when -= 2147483648u;
		when -= 2147483648u;
	}

	return when - DUID_TIME_EPOCH;
}


/* 
 * Server DUID.
 */
static struct data_string duid;

/*
 * Set the server DUID.
 * This must remain the same for the lifetime of this server, because
 * clients return the server DUID that we sent them in Request packets.
 * 
 * TODO: Allow users to configure DUID in dhcpd.conf. This means 
 *       specifying type 1 or 3, and maybe specifying which MAC 
 *       address to use. Users who want type 2 are be able to 
 *       enter in the actual bytes of the DUID.
 */
isc_result_t
set_server_duid(void) {
	struct interface_info *p;
	u_int32_t time_val;
	struct option_state *opt_state;
	struct option_cache *oc;
	static int called = 0;

	/*
	 * We only want to set the DUID once.
	 */
	if (called) {
		return ISC_R_SUCCESS;
	}
	called = 1;

	/*
	 * First, see if the DUID is set by an option.
	 */
	opt_state = NULL;
	if (!option_state_allocate(&opt_state, MDL)) {
		log_fatal("No memory for server DUID.");
	}

	execute_statements_in_scope(NULL, NULL, NULL, NULL, NULL,
				    opt_state, &global_scope, root_group, NULL);

	oc = lookup_option(&dhcpv6_universe, opt_state, D6O_SERVERID);
	if (oc != NULL) {
		if (!evaluate_option_cache(&duid, NULL, NULL, NULL, opt_state, 
					   NULL, &global_scope, oc, MDL)) {
			memset(&duid, 0, sizeof(duid));
		}
	}

	option_state_dereference(&opt_state, MDL);

	if (duid.len != 0) {
		return ISC_R_SUCCESS;
	}

	/*
	 * If the DUID is not set, we will generate one.
	 */

	time_val = htonl(duid_time(time(NULL)));
	for (p = interfaces; p != NULL; p = p->next) {
		if (p->hw_address.hlen > 0) {
			break;
		}
	}
	if (p == NULL) {
		return ISC_R_UNEXPECTED;
	}

	duid.data = dmalloc(8 + p->hw_address.hlen - 1, MDL);
	if (duid.data == NULL) {
		log_fatal("No memory for server DUID.");
	}

	/* 
	 * DUID layout as defined in RFC 3315, section 9.2.
	 */
	*(char *)duid.data = '\x00';
	*(char *)(duid.data+1) = '\x01';
	*(char *)(duid.data+2) = '\x00';
	*(char *)(duid.data+3) = p->hw_address.hbuf[0];
	memcpy((char *)(duid.data+4), &time_val, 4);
	memcpy((char *)(duid.data+8), 
	       p->hw_address.hbuf+1, p->hw_address.hlen-1);
	duid.len = 8 + p->hw_address.hlen - 1;

	return ISC_R_SUCCESS;
}

/*
 * Message validation, defined in RFC 3315, sections 15.2, 15.5, 15.7:
 *
 *    Servers MUST discard any Solicit messages that do not include a
 *    Client Identifier option or that do include a Server Identifier
 *    option.
 */
int
valid_client_msg(struct packet *packet, struct data_string *client_id) {
	int ret_val;
	struct option_cache *oc;
	struct data_string data;

	ret_val = 0;
	memset(client_id, 0, sizeof(*client_id));
	memset(&data, 0, sizeof(data));

	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_CLIENTID);
	if (oc == NULL) {
		log_debug("Discarding %s from %s; "
			  "client identifier missing", 
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr));
		goto exit;
	}
	if (!evaluate_option_cache(client_id, packet, NULL, NULL, 
				   packet->options, NULL,
				   &global_scope, oc, MDL)) {
		log_error("Error processing %s from %s; "
			  "unable to evaluate Client Identifier",
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr));
		goto exit;
	}

	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_SERVERID);
	if (oc != NULL) {
		if (evaluate_option_cache(&data, packet, NULL, NULL,
		                          packet->options, NULL, 
					  &global_scope, oc, MDL)) {
			log_debug("Discarding %s from %s; " 
				  "server identifier found "
				  "(CLIENTID %s, SERVERID %s)", 
				  dhcpv6_type_names[packet->dhcpv6_msg_type],
				  piaddr(packet->client_addr),
				  print_hex_1(client_id->len, 
				  	      client_id->data, 60),
				  print_hex_2(data.len,
				  	      data.data, 60));
		} else {
			log_debug("Discarding %s from %s; " 
				  "server identifier found "
				  "(CLIENTID %s)", 
				  dhcpv6_type_names[packet->dhcpv6_msg_type],
				  print_hex_1(client_id->len, 
				  	      client_id->data, 60),
				  piaddr(packet->client_addr));
		}
		goto exit;
	}

	/* looks good */
	ret_val = 1;

exit:
	if (data.len > 0) {
		data_string_forget(&data, MDL);
	}
	if (!ret_val) {
		if (client_id->len > 0) {
			data_string_forget(client_id, MDL);
		}
	}
	return ret_val;
}

/*
 * Response validation, defined in RFC 3315, sections 15.4, 15.6, 15.8, 
 * 15.9 (slightly different wording, but same meaning):
 *
 *   Servers MUST discard any received Request message that meet any of
 *   the following conditions:
 *
 *   -  the message does not include a Server Identifier option.
 *   -  the contents of the Server Identifier option do not match the
 *      server's DUID.
 *   -  the message does not include a Client Identifier option.
 */
int
valid_client_resp(struct packet *packet,
		  struct data_string *client_id,
		  struct data_string *server_id) {
	int ret_val;
	struct option_cache *oc;

	/* INSIST((duid.data != NULL) && (duid.len > 0)); */

	ret_val = 0;
	memset(client_id, 0, sizeof(*client_id));
	memset(server_id, 0, sizeof(*server_id));

	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_CLIENTID);
	if (oc == NULL) {
		log_debug("Discarding %s from %s; "
			  "client identifier missing", 
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr));
		goto exit;
	}
	if (!evaluate_option_cache(client_id, packet, NULL, NULL, 
				   packet->options, NULL,
				   &global_scope, oc, MDL)) {
		log_error("Error processing %s from %s; "
			  "unable to evaluate Client Identifier",
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr));
		goto exit;
	}

	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_SERVERID);
	if (oc == NULL) {
		log_debug("Discarding %s from %s: "
			  "server identifier missing (CLIENTID %s)", 
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr),
			  print_hex_1(client_id->len, client_id->data, 60));
		goto exit;
	}
	if (!evaluate_option_cache(server_id, packet, NULL, NULL, 
				   packet->options, NULL,
				   &global_scope, oc, MDL)) {
		log_error("Error processing %s from %s; "
			  "unable to evaluate Server Identifier (CLIENTID %s)",
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr),
			  print_hex_1(client_id->len, client_id->data, 60));
		goto exit;
	}
	if ((duid.len != server_id->len) || 
	    (memcmp(duid.data, server_id->data, duid.len) != 0)) {
		log_debug("Discarding %s from %s; " 
			  "not our server identifier "
			  "(CLIENTID %s, SERVERID %s, server DUID %s)", 
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr),
			  print_hex_1(client_id->len, client_id->data, 60),
			  print_hex_2(server_id->len, server_id->data, 60),
			  print_hex_3(duid.len, duid.data, 60));
		goto exit;
	}

	/* looks good */
	ret_val = 1;

exit:
	if (!ret_val) {
		if (server_id->len > 0) {
			data_string_forget(server_id, MDL);
		}
		if (client_id->len > 0) {
			data_string_forget(client_id, MDL);
		}
	}
	return ret_val;
}

/*
 * Information request validation, defined in RFC 3315, section 15.12:
 *
 *   Servers MUST discard any received Information-request message that
 *   meets any of the following conditions:
 *
 *   -  The message includes a Server Identifier option and the DUID in
 *      the option does not match the server's DUID.
 *
 *   -  The message includes an IA option.
 */
int
valid_client_info_req(struct packet *packet, struct data_string *server_id) {
	int ret_val;
	struct option_cache *oc;

	/* INSIST((duid.data != NULL) && (duid.len > 0)); */

	ret_val = 0;
	memset(server_id, 0, sizeof(*server_id));

	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_NA);
	if (oc != NULL) {
		log_debug("Discarding %s from %s; "
			  "IA_NA option present", 
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr));
		goto exit;
	}
	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_TA);
	if (oc != NULL) {
		log_debug("Discarding %s from %s; "
			  "IA_TA option present", 
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr));
		goto exit;
	}

	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_SERVERID);
	if (oc != NULL) {
		if (!evaluate_option_cache(server_id, packet, NULL, NULL, 
					   packet->options, NULL,
					   &global_scope, oc, MDL)) {
			log_error("Error processing %s from %s; "
				  "unable to evaluate Server Identifier",
				  dhcpv6_type_names[packet->dhcpv6_msg_type],
				  piaddr(packet->client_addr));
			goto exit;
		}
		if ((duid.len != server_id->len) || 
		    (memcmp(duid.data, server_id->data, duid.len) != 0)) {
			log_debug("Discarding %s from %s; " 
				  "not our server identifier "
				  "(SERVERID %s, server DUID %s)", 
				  dhcpv6_type_names[packet->dhcpv6_msg_type],
				  piaddr(packet->client_addr),
				  print_hex_1(server_id->len, 
				  	      server_id->data, 60),
				  print_hex_2(duid.len, duid.data, 60));
			goto exit;
		}
	}

	/* looks good */
	ret_val = 1;

exit:
	if (!ret_val) {
		if (server_id->len > 0) {
			data_string_forget(server_id, MDL);
		}
	}
	return ret_val;
}

/* 
 * Options that we want to send, in addition to what was requested
 * via the ORO.
 */
static const int required_opts[] = {
	D6O_CLIENTID,
	D6O_SERVERID,
	D6O_STATUS_CODE,
	0
};
static const int required_opts_solicit[] = {
	D6O_CLIENTID,
	D6O_SERVERID,
	D6O_IA_NA,
	D6O_IA_TA,
	D6O_RAPID_COMMIT,
	D6O_ORO,
	D6O_STATUS_CODE,
	D6O_VENDOR_OPTS,
	D6O_RECONF_ACCEPT,
	0
};
static const int required_opts_IA_NA[] = {
	D6O_IAADDR,
	D6O_ORO,
	D6O_STATUS_CODE,
	D6O_VENDOR_OPTS,
	0
};
static const int required_opts_STATUS_CODE[] = {
	D6O_STATUS_CODE,
	0
};

/*
 * Creates an option state and data string, based on the packet contents,
 * and the specific option defined in the option cache.
 */
static int
get_encapsulated_IA_state(struct option_state **enc_opt_state, 
			  struct data_string *enc_opt_data,
			  struct packet *packet,
			  struct option_cache *oc) {

	/* 
	 * Get the raw data for the encapsulated options.
	 */
	memset(enc_opt_data, 0, sizeof(*enc_opt_data));
	if (!evaluate_option_cache(enc_opt_data, packet,
				   NULL, NULL, packet->options, NULL,
				   &global_scope, oc, MDL)) {
		log_error("get_encapsulated_IA_state: "
			  "error evaluating raw option.");
		return 0;
	}
	if (enc_opt_data->len < 12) {
		log_error("get_encapsulated_IA_state: raw option too small.");
		data_string_forget(enc_opt_data, MDL);
		return 0;
	}

	/*
	 * Now create the option state structure, and pass it to the 
	 * function that parses options.
	 */
	*enc_opt_state = NULL;
	if (!option_state_allocate(enc_opt_state, MDL)) {
		log_error("get_encapsulated_IA_state: no memory for options.");
		data_string_forget(enc_opt_data, MDL);
		return 0;
	}
	if (!parse_option_buffer(*enc_opt_state, 
				 enc_opt_data->data+12, 
				 enc_opt_data->len-12,
				 &dhcpv6_universe)) {
		log_error("get_encapsulated_IA_state: error parsing options.");
		option_state_dereference(enc_opt_state, MDL);
		data_string_forget(enc_opt_data, MDL);
		return 0;
	}

	return 1;
}

static int
set_status_code(u_int16_t status_code, const char *status_message,
		struct option_state *opt_state) {
	struct data_string d;
	int ret_val;

	memset(&d, 0, sizeof(d));
	d.len = sizeof(status_code) + strlen(status_message);
	if (!buffer_allocate(&d.buffer, d.len, MDL)) {
		log_fatal("set_status_code: no memory for status code.");
	}
	d.data = d.buffer->data;
	memcpy((char *)d.data, &status_code, sizeof(status_code));
	memcpy((char *)(d.data + sizeof(status_code)), 
			status_message, d.len - sizeof(status_code));
	if (!save_option_buffer(&dhcpv6_universe, opt_state, 
				d.buffer, (char *)d.data, d.len, 
				D6O_STATUS_CODE, 0)) {
		log_error("set_status_code: error saving status code.");
		ret_val = 0;
	} else {
		ret_val = 1;
	}
	data_string_forget(&d, MDL);
	return ret_val;
}

/*
 * We have a set of operations we do to set up the reply packet, which
 * is the same for many message types.
 */
static int
start_reply(struct packet *packet,
	    const struct data_string *client_id, 
	    const struct data_string *server_id,
	    struct option_state **opt_state,
	    int rapid_commit,
	    struct dhcpv6_packet *reply) {
	struct option_cache *oc;
	struct data_string server_oro;
	char *server_id_data;
	int server_id_len;

	reply->msg_type = DHCPV6_REPLY;

	/* 
	 * Use the client's transaction identifier for the reply.
	 */
	memcpy(reply->transaction_id, packet->dhcpv6_transaction_id, 
	       sizeof(reply->transaction_id));

	/*
	 * Build our option state for reply.
	 */
	*opt_state = NULL;
	if (!option_state_allocate(opt_state, MDL)) {
		log_error("start_reply: no memory for option_state.");
		return 0;
	}
	execute_statements_in_scope(NULL, packet, NULL, NULL, 
				    packet->options, *opt_state, 
				    &global_scope, root_group, NULL);

	/* 
	 * RFC 3315, section 18.2 says we need server identifier and
	 * client identifier.
	 *
	 * If the server ID is defined via the configuration file, then
	 * it will already be presnet in the option state at this point, 
	 * so we don't need to set it.
	 *
	 * If we have a server ID passed in from the caller, 
	 * use that, otherwise use the global DUID.
	 */
	oc = lookup_option(&dhcpv6_universe, *opt_state, D6O_SERVERID);
	if (oc == NULL) {
		if (server_id == NULL) {
			server_id_data = (char *)duid.data;
			server_id_len = duid.len;
		} else {
			server_id_data = (char *)server_id->data;
			server_id_len = server_id->len;
		}
		if (!save_option_buffer(&dhcpv6_universe, *opt_state, 
					NULL, server_id_data, server_id_len,
					D6O_SERVERID, 0)) {
				log_error("start_reply: "
					  "error saving server identifier.");
				return 0;
		}
	}

	if (!save_option_buffer(&dhcpv6_universe, *opt_state, 
				client_id->buffer, 
				(unsigned char *)client_id->data, 
				client_id->len, 
				D6O_CLIENTID, 0)) {
		log_error("start_reply: error saving client identifier.");
		return 0;
	}

	/*
	 * If the client accepts reconfiguration, let it know that we
	 * will send them.
	 *
	 * Note: we don't actually do this yet, but DOCSIS requires we
	 *       claim to.
	 */
	oc = lookup_option(&dhcpv6_universe, packet->options,
			   D6O_RECONF_ACCEPT);
	if (oc != NULL) {
		if (!save_option_buffer(&dhcpv6_universe, *opt_state,
					NULL, "", 0, D6O_RECONF_ACCEPT, 0)) {
			log_error("start_reply: "
				  "error saving RECONF_ACCEPT option.");
			option_state_dereference(opt_state, MDL);
			return 0;
		}
	}

	/*
	 * Save rapid commit option, if we want to.
	 */
	if (rapid_commit) {
		if (!save_option_buffer(&dhcpv6_universe, *opt_state,
					NULL, "", 0, D6O_RAPID_COMMIT, 0)) {
			log_error("start_reply: error saving "
				  "RAPID_COMMIT option.");
			option_state_dereference(opt_state, MDL);
			return 0;
		}
	}

	/*
	 * Set the ORO for the main packet.
	 */
	build_server_oro(&server_oro, *opt_state, MDL);
	if (!save_option_buffer(&dhcpv6_universe, *opt_state,
				server_oro.buffer, (char *)server_oro.data,
				server_oro.len, D6O_ORO, 0)) {
		log_error("start_reply: error saving server ORO.");
		data_string_forget(&server_oro, MDL);
		option_state_dereference(opt_state, MDL);
		return 0;
	}
	data_string_forget(&server_oro, MDL);

	return 1;
}

/* TODO: IA_TA */
/* TODO: look at client hints for lease times */
/* XXX: need to add IA_NA to our ORO? */
static void
lease_to_client(struct data_string *reply_ret,
		struct packet *packet, 
		const struct data_string *client_id,
		const struct data_string *server_id,
		int msg_type) {
	struct option_cache *oc;
	struct data_string packet_oro;
	struct host_decl *packet_host;
	struct data_string server_oro;
	int matched_packet_host;
	struct option_cache *ia;
	int rapid_commit;
	char reply_data[65536];
	struct dhcpv6_packet *reply = (struct dhcpv6_packet *)reply_data;
	int reply_ofs = (int)((char *)reply->options - (char *)reply);
	struct option_state *opt_state;
	struct data_string oro;
	struct host_decl *host;
	struct option_state *host_opt_state;
	/* cli_enc_... variables come from the IA_NA/IA_TA options */
	struct data_string cli_enc_opt_data;
	struct option_state *cli_enc_opt_state;
	u_int32_t preferred_lifetime;
	u_int32_t valid_lifetime;
	struct data_string iaaddr;
	struct data_string fixed_addr;
	struct data_string d;
	u_int16_t len;
	u_int32_t t1, t2;
	struct host_decl *save_host;
	char zeros[24];
	struct ipv6_pool *pool;
	struct iaaddr *lease;
	struct group *group;
	u_int32_t iaid;
	struct ia_na *ia_na;
	struct ia_na *existing_ia_na;
	int i;

	/*
	 * Initialize to empty values, in case we have to exit early.
	 */
	opt_state = NULL;
	memset(&packet_oro, 0, sizeof(packet_oro));
	memset(&oro, 0, sizeof(oro));
	memset(&cli_enc_opt_data, 0, sizeof(cli_enc_opt_data));
	cli_enc_opt_state = NULL;
	host_opt_state = NULL;
	memset(&fixed_addr, 0, sizeof(fixed_addr));
	memset(&iaaddr, 0, sizeof(iaaddr));
	ia_na = NULL;
	lease = NULL;

	/*
	 * If the client requests a rapid commit, then we will send a Reply,
	 * otherwise we will send an Advertise.
	 *
	 * TODO: make this configurable on the server side
	 */
	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_RAPID_COMMIT);
	if (oc == NULL) {
		rapid_commit = 0;
	} else {
		rapid_commit = 1;
	}

	/* 
	 * Set up reply.
	 */
	if (!start_reply(packet, client_id, NULL, 
			 &opt_state, rapid_commit, reply)) {
		goto exit;
	}

	/* 
	 * Set the message type.
	 */
	reply->msg_type = msg_type;

	/*
	 * Get the ORO from the packet, if any.
	 */
	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_ORO);
	if (oc != NULL) {
		if (!evaluate_option_cache(&packet_oro, packet, 
					   NULL, NULL, 
					   packet->options, NULL,
					   &global_scope, oc, MDL)) {
			log_error("lease_to_client: error evaluating ORO.");
			goto exit;
		}
	}

	/* 
	 * Find the host record that matches from the packet, if any.
	 */
	packet_host = NULL;
	if (!find_hosts_by_option(&packet_host, packet, packet->options, MDL)) {
		packet_host = NULL;
		/*
		 * If we don't have a match from the packet contents, 
		 * see if we can match by UID.
		 */
		if (!find_hosts_by_uid(&packet_host, 
				       client_id->data, client_id->len, MDL)) {
			packet_host = NULL;
		} 
	}
	matched_packet_host = 0;

	/* 
	 * Add our options that are not associated with any IA_NA or IA_TA. 
	 */
	reply_ofs += store_options6(reply_data+reply_ofs,
				    sizeof(reply_data)-reply_ofs, 
				    opt_state, packet,
				    required_opts_solicit, &packet_oro);

	/* 
	 * Now loop across each IA_NA that we have.
	 */
	ia = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_NA);
	while (ia != NULL) {
		/* 
		 * T1 and T2, set to 0 means the client can choose.
		 * 
		 * We will adjust this based on preferred and valid 
		 * times if we have an address.
		 */
		t1 = 0;
		t2 = 0;

		if (!get_encapsulated_IA_state(&cli_enc_opt_state,
					       &cli_enc_opt_data,
					       packet, ia)) {
			goto exit;
		}

		/*
		 * Create an IA_NA structure.
		 */
		iaid = getULong(cli_enc_opt_data.data+4);
		ia_na = NULL;
		if (ia_na_allocate(&ia_na, iaid, client_id->data, 
				   client_id->len, MDL) != ISC_R_SUCCESS) {
			log_fatal("lease_to_client: no memory for ia_na.");
		}

		/*
		 * Get the encapsulated ORO, if any. Otherwise use the
		 * ORO from the packet.
		 */
		oc = lookup_option(&dhcpv6_universe, cli_enc_opt_state, 
				   D6O_ORO);
		if (oc == NULL) {
			data_string_copy(&oro, &packet_oro, MDL);
		} else {
			if (!evaluate_option_cache(&oro, NULL, NULL, 
						   NULL, NULL, NULL, 
						   &global_scope, oc, MDL)) {
				log_error("lease_to_client: error "
					  "evaluating IA_NA ORO.");

				goto exit;
			}
		}

		/*
		 * Create state for this IA_NA.
		 */
		host_opt_state = NULL;
		if (!option_state_allocate(&host_opt_state, MDL)) {
			log_error("lease_to_client: out of memory "
				  "allocating option_state.");
			goto exit;
		}

		/* 
		 * See if this NA has an address. If so, we use it
		 * when trying to find a matching host record.
		 */
		memset(&iaaddr, 0, sizeof(iaaddr));
		oc = lookup_option(&dhcpv6_universe, cli_enc_opt_state, 
				   D6O_IAADDR);
		if (oc != NULL) {
			/*
			 * TODO: Check that the address is on one of
			 *       the networks that we have, and issue
			 *       NotOnLink if not (for Solicit/Request),
			 *       or remember to set the address lifetime
			 *       to 0 (for Renew/Rebind).
			 */
			if (!evaluate_option_cache(&iaaddr, packet, 
						   NULL, NULL, 
						   packet->options, 
						   NULL, &global_scope,
						   oc, MDL)) {
				log_error("lease_to_client: "
			  		  "error evaluating IAADDR.");
				goto exit;
			}
			/* 
			 * XXX: Clients *love* to send :: as an address,
			 *      which is *never* what we want.
			 */
			memset(zeros, 0, sizeof(zeros));
			if ((iaaddr.len == 24) && 
			    !memcmp(iaaddr.data, zeros, 16)) {
			    	log_info("Ignoring IAADDR :: from client.");
				data_string_forget(&iaaddr, MDL);
			}
		}

		/* 
		 * Now we need to figure out which host record matches
		 * this IA_NA.
		 * 
		 * We first try matching the encapsulated option state. 
		 * If nothing is there, then we will use the host entry 
		 * matched from the non-encapsulated option state, if 
		 * there was one.
		 * 
		 * We will only use this host entry for one of the
		 * IA_NA in the packet, to avoid having the same address
		 * on multiple interfaces.
		 */
		host = NULL;
		if (!find_hosts_by_option(&host, packet, 
					  cli_enc_opt_state, MDL)) { 
			if ((packet_host != NULL) && !matched_packet_host) {
				matched_packet_host = 1;
				host = packet_host;
			} else {
				host = NULL;
			}
		}

		if (iaaddr.len == 0) {
			/* 
			 * Client did not specify the IAADDR to use.
			 *
			 * If we are renewing, this is a problem. Set
			 * to no host, and this will cause the appropriate
			 * response to be sent.
			 * 
			 * Otherwise, we simply find the first matching host.
			 */
			if (packet->dhcpv6_msg_type == DHCPV6_RENEW) {
				host = NULL;
			} else {
				while ((host != NULL) && 
				       (host->fixed_addr == NULL)) {
					host = host->n_ipaddr;
				}
			}
		} else {
			/* 
			 * Client wanted a specific IAADDR, so we will
			 * only accept a host entry that matches. 
			 */
			save_host = host;
			for (; host != NULL; host = host->n_ipaddr) {
				if (host->fixed_addr == NULL) {
					continue;
				} 
				if (!evaluate_option_cache(&fixed_addr, NULL, 
							   NULL, NULL, NULL, 
							   NULL, &global_scope,
							   host->fixed_addr, 
							   MDL)) {
					log_error("lease_to_client: error "
						  "evaluating host address.");
					goto exit;
				}
				if ((iaaddr.len >= 16) &&
				    !memcmp(fixed_addr.data, iaaddr.data, 16)) {
					data_string_forget(&fixed_addr, MDL);
					break;
				}
				data_string_forget(&fixed_addr, MDL);
			}
			/* 
			 * If we got a Solicit and don't have a matching 
			 * host record, have gotten a bad hint.
			 * Pick a host record.
			 */
			if ((host == NULL) && 
			    (packet->dhcpv6_msg_type == DHCPV6_SOLICIT)) {
			    	host = save_host;
				while ((host != NULL) && 
				       (host->fixed_addr == NULL)) {
					host = host->n_ipaddr;
				}
			}
		}

		/*
		 * At this point, if we don't have a host entry,
		 * try to find the appropriate pool for this IA.
		 */
		group = NULL;
		lease = NULL;
		if (host != NULL) {
			group = host->group;
		} else if ((num_pools > 0) && 
			   (packet->dhcpv6_msg_type == DHCPV6_SOLICIT)) {
			/* 
			 * For Solicit, we don't bother to check for 
			 * existing IA_NA records.
			 */
			struct in6_addr *in6_addr;
			if (iaaddr.len == 0) {
				/* 
				 * Hard to know what pool to use for
				 * clients. Pick the first IPv6 address
				 * we use on the interface?
				 * 
				 * XXX: we should probably iterate through
				 *      these until we find a matching pool...
				 */
				in6_addr = &packet->interface->v6addresses[0];
			} else {
				in6_addr = (struct in6_addr *)iaaddr.data;
			}
			pool = NULL;
			if (find_ipv6_pool(&pool, in6_addr) == ISC_R_SUCCESS) {
				if (activate_lease6(pool, &lease, 
						    client_id, 0) ==
				    ISC_R_SUCCESS) {
				    	group = pool->subnet->group;
				}
			}
		} else if (num_pools > 0) {
			/* 
			 * For all other message types, we require 
			 * existing IA_NA records.
			 */
			struct iaaddr *tmp;
			struct in6_addr *in6_addr;
			/*
			 * Find existing IA_NA.
			 */
			existing_ia_na = NULL;
			if (ia_na_hash_lookup(&existing_ia_na, ia_active, 
					      (char *)ia_na->iaid_duid.data,
					      ia_na->iaid_duid.len, MDL) == 0) {
				existing_ia_na = NULL;
			}
			/*
			 * If there are no addresses, we'll ignore this IA_NA.
			 */
			if ((existing_ia_na != NULL) && 
			    (existing_ia_na->num_iaaddr == 0)) {
				existing_ia_na = NULL;
			}
			if ((iaaddr.len == 0) && (existing_ia_na != NULL)) {
				/* 
				 * If the client doesn't ask for a specific
				 * address (weird), we're cool.
				 */
				tmp = existing_ia_na->iaaddr[0];
				pool = NULL;
				ipv6_pool_reference(&pool, tmp->ipv6_pool, MDL);
				iaaddr_reference(&lease, tmp, MDL);
			} else if (existing_ia_na != NULL) {
				/* 
				 * Make sure this address is in the IA_NA.
				 */
				pool = NULL;
				for (i=0; i<existing_ia_na->num_iaaddr; i++) {
					tmp = existing_ia_na->iaaddr[i];
					in6_addr = &tmp->addr;
					if (memcmp(in6_addr, 
						   iaaddr.data, 16) == 0) {
						ipv6_pool_reference(&pool, 
							tmp->ipv6_pool, MDL);
						iaaddr_reference(&lease,
								 tmp, MDL);
						break;
				        }
				}
			}
		}

		/*
		 * Get the lease time from the group.
		 */
		if (group != NULL) {
			/*
			 * Execute statements for the host's group.
			 */
			execute_statements_in_scope(NULL, packet, NULL, NULL, 
				    		    packet->options, 
						    host_opt_state, 
						    &global_scope, 
						    group, root_group);
			/* 
			 * Get our lease time. Note that "preferred lifetime"
			 * and "valid lifetime" are defined in RFC 2462.
			 */
			oc = lookup_option(&server_universe, opt_state, 
					   SV_DEFAULT_LEASE_TIME);
			valid_lifetime = DEFAULT_DEFAULT_LEASE_TIME;
			if (oc != NULL) {
				memset(&d, 0, sizeof(d));
				if (!evaluate_option_cache(&d, packet, NULL, 
							   NULL, 
							   packet->options,
							   opt_state,
							   &global_scope,
							   oc, MDL)) {
					log_error("lease_to_client: error "
						  "getting lease time, "
						  "using default.");
				} else {
					/* INSIST(d.len == 4); */
					valid_lifetime = getULong(d.data);
					data_string_forget(&d, MDL);
				}
			}

			/*
			 * T1: RENEW time.
			 * T2: REBIND time.
			 * preferred: 'deprecate' address.
			 * valid: address expires.
			 *
			 * Values are required for valid and preferred
			 * lifetimes.  T1 and T2, if zero, will allow
			 * the client to select their own behaviour.
			 */
			t1 = t2 = 0;
			/* XXX: This is more than a little weird. */
			oc = lookup_option(&dhcp_universe, opt_state,
					   DHO_DHCP_RENEWAL_TIME);
			if (oc != NULL) {
				memset(&d, 0, sizeof(d));
				if (!evaluate_option_cache(&d, packet, NULL,
							   NULL,
							   packet->options,
							   opt_state,
							   &global_scope,
							   oc, MDL)) {
					/* XXX: I think there are already log
					 * lines by this point.
					 */
					log_error("lease_to_client: error "
						  "evaluating renew time, "
						  "defaulting to 0");
				} else {
					t1 = getULong(d.data);
					data_string_forget(&d, MDL);
				}
			}

			oc = lookup_option(&dhcp_universe, opt_state,
					   DHO_DHCP_REBINDING_TIME);
			if (oc != NULL) {
				memset(&d, 0, sizeof(d));
				if (!evaluate_option_cache(&d, packet, NULL,
							   NULL,
							   packet->options,
							   opt_state,
							   &global_scope,
							   oc, MDL)) {
					/* XXX: I think there are already log
					 * lines by this point.
					 */
					log_error("lease_to_client: error "
						  "evaluating rebinding "
						  "time, defaulting to 0");
				} else {
					t2 = getULong(d.data);
					data_string_forget(&d, MDL);
				}
			}

			preferred_lifetime = t1 + t2;

			if (preferred_lifetime == 0 ||
			    preferred_lifetime >= valid_lifetime)
				preferred_lifetime = (valid_lifetime / 2) +
						     (valid_lifetime / 4);

			oc = lookup_option(&server_universe, opt_state,
					   SV_PREFER_LIFETIME);
			if (oc != NULL) {
				memset(&d, 0, sizeof(d));
				if (!evaluate_option_cache(&d, packet, NULL,
							   NULL,
							   packet->options,
							   opt_state,
							   &global_scope,
							   oc, MDL)) {
					/* XXX: I think there are already log
					 * lines by this point.
					 */
					log_error("lease_to_client: error "
						  "evaluating preferred "
						  "lifetime, defaulting to "
						  "%d", preferred_lifetime);
				} else {
					preferred_lifetime = getULong(d.data);
					data_string_forget(&d, MDL);
				}
			}
		}

		/*
		 * Shift the lease to the right place, based on our timeout.
		 */
		if (lease != NULL) {
			lease->valid_lifetime_end_time = valid_lifetime + 
							 cur_time;
			renew_lease6(pool, lease);
		}

		/*
		 * Get the address.
		 */
		memset(&fixed_addr, 0, sizeof(fixed_addr));
		if (host != NULL) {
			if (!evaluate_option_cache(&fixed_addr, NULL, NULL, 
						   NULL, NULL, NULL, 
						   &global_scope,
						   host->fixed_addr, MDL)) {
				log_error("lease_to_client: error "
					  "evaluating host address.");
				goto exit;
			}
			if (fixed_addr.len != 16) {
				log_error("lease_to_client: invalid address "
				          "length (%d)", fixed_addr.len);
				goto exit;
			}
		} else if (lease != NULL) {
			fixed_addr.len = 16;
			if (!buffer_allocate(&fixed_addr.buffer, 16, MDL)) {
				log_fatal("lease_to_client: no memory for "
				          "address information.");
			}
			fixed_addr.data = fixed_addr.buffer->data;
			memcpy((void *)fixed_addr.data, &lease->addr, 16);
		}

		if (fixed_addr.len == 16) {
			struct iaaddr *store_iaaddr;

			/*
			 * Store the address.
			 *
			 * XXX: This should allow multiple addresses, rather
			 *      than only a single one!
			 */
			memset(&d, 0, sizeof(d));
			d.len = 24;	/* From RFC 3315, section 22.6 */
			if (!buffer_allocate(&d.buffer, d.len, MDL)) {
				log_fatal("lease_to_client: no memory for "
				          "address information.");
			}
			d.data = d.buffer->data;
			memcpy((char *)d.data, fixed_addr.data, 16);
			putULong((char *)d.data+16, preferred_lifetime);
			putULong((char *)d.data+20, valid_lifetime);
			data_string_forget(&fixed_addr, MDL);
			if (!save_option_buffer(&dhcpv6_universe, 
						host_opt_state, 
						d.buffer, 
						(char *)d.data, 
						d.len, D6O_IAADDR, 0)) {
				log_error("lease_to_client: error saving "
					  "IAADDR.");
				data_string_forget(&d, MDL);
				goto exit;
			}
			data_string_forget(&d, MDL);

			/* 
			 * Store in IA_NA.
			 */
#if 0
			store_iaaddr = NULL;
			if (iaaddr_allocate(&store_iaaddr, 
					    MDL) != ISC_R_SUCCESS) {
				log_fatal("lease_to_client: no memory for "
					  "iaaddr information.");

			}
			store_iaaddr->state = FTS_ACTIVE;
			store_iaaddr->valid_lifetime_end_time = valid_lifetime;
			ipv6_pool_reference(&store_iaaddr->ipv6_pool, 
					    pool, MDL);
			if (ia_na_add_iaaddr(ia_na, store_iaaddr, 
					     MDL) != ISC_R_SUCCESS) {
				log_fatal("lease_to_client: error storing "
					  "iaaddr information.");
			}
#endif /* 0 */
				
		}

		if ((host != NULL) || (lease != NULL)) {
			
			/*
			 * Figure out what ORO we recommend to clients.
			 */
			build_server_oro(&server_oro, host_opt_state, MDL);
			if (!save_option_buffer(&dhcpv6_universe, 
						host_opt_state, 
						server_oro.buffer, 
						(char *)server_oro.data, 
						server_oro.len, D6O_ORO, 0)) {
				log_error("lease_to_client: error saving "
					  "server ORO.");
				data_string_forget(&server_oro, MDL);
				goto exit;
			}
			data_string_forget(&server_oro, MDL);

			/*
			 * Remember the client identifier so we can look
			 * it up later.
			 */
			if (host != NULL) {
				change_host_uid(host, client_id->data, 
						client_id->len);
			} 
			/*
			 * Otherwise save the IA_NA, for the same reason.
			 */
			else {
				ia_na_hash_delete(ia_active, 
						  (char *)ia_na->iaid_duid.data,
						  ia_na->iaid_duid.len, MDL);
				if (ia_na_add_iaaddr(ia_na, lease, 
						     MDL) != ISC_R_SUCCESS) {
					log_fatal("lease_to_client: out of "
						  "memory adding IAADDR");
				}
				ia_na_hash_add(ia_active, 
					       (char *)ia_na->iaid_duid.data,
				               ia_na->iaid_duid.len, 
					       ia_na, MDL);
				write_ia_na(ia_na);
			}

		} else {

			/*
			 * We send slightly different errors, depending on
			 * whether the client is asking for a new address, or
			 * attempting to renew an address it thinks it has.
			 */
			if (packet->dhcpv6_msg_type == DHCPV6_REBIND) {
				if (iaaddr.len == 24) {
					/* 
				 	 * If the we have a client address, 
					 * tell the client it is invalid.
					 */
					memset(&d, 0, sizeof(d));
					d.len = 24; 
					if (!buffer_allocate(&d.buffer, 
							     d.len, MDL)) {
						log_fatal("lease_to_client: "
							  "no memory for "
							  "address "
							  "information.");
					}
					d.data = d.buffer->data;
					memcpy((char *)d.data, iaaddr.data, 16);
					putULong((char *)d.data+16, 0);
					putULong((char *)d.data+20, 0);
					if (!save_option_buffer(
						              &dhcpv6_universe, 
							      host_opt_state, 
							      d.buffer, 
						              (char *)d.data, 
							      d.len, 
							      D6O_IAADDR, 0)) {
						log_error("lease_to_client: "
						          "error saving "
							  "IAADDR.");
						data_string_forget(&d, MDL);
						goto exit;
					}
					data_string_forget(&d, MDL);
				} else {
					/* 
				 	 * Otherwise, this is an error.
					 * 
					 * XXX: The other possibility is to
					 *      not say anything for this
					 *      IA, which might be more 
					 *      correct. RFC 3315 does not 
					 *      address this case.
					 */
					if (!set_status_code(STATUS_UnspecFail, 
						     "Rebind requested without "
						     "including an addresses.", 
						     host_opt_state)) {
						goto exit;
					}
				}
			} else if (packet->dhcpv6_msg_type == DHCPV6_RENEW) {
				if (!set_status_code(STATUS_NoBinding, 
						     "Address not bound "
						     "to this interface.", 
						     host_opt_state)) {
					goto exit;
				}
			} else if ((iaaddr.len == 24) &&
				   (packet->dhcpv6_msg_type == DHCPV6_REQUEST)){
				if (!set_status_code(STATUS_NotOnLink, 
					     	     "Address not for "
						     "use on this link.", 
						     host_opt_state)) {
					goto exit;
				}
			} else {
				if (!set_status_code(STATUS_NoAddrsAvail, 
						     "No addresses available "
						     "for this interface.", 
						     host_opt_state)) {
					goto exit;
				}
			}

		}

		/*
		 * Insure we have enough space
		 */
		if (sizeof(reply_data) < (reply_ofs + 16)) {
			log_error("lease_to_client: "
			          "out of space for reply packet.");
			goto exit;
		}

		/*
		 * Store the encapsulated option data for this IA_NA into
		 * our reply packet.
		 */
		len = store_options6(reply_data+reply_ofs+16, 
				     sizeof(reply_data)-reply_ofs-16, 
				     host_opt_state, packet,
				     required_opts_IA_NA, &oro);

		/*
		 * Store the non-encapsulated option data for this IA_NA 
		 * into our reply packet. Defined in RFC 3315, section 22.4.
		 */
		/* option number */
		putShort(reply_data+reply_ofs, D6O_IA_NA);
		/* option length */
		putUShort(reply_data+reply_ofs+2, len + 12);
		/* IA_NA, copied from the client */
		memcpy(reply_data+reply_ofs+4, cli_enc_opt_data.data, 4);
		/* T1 and T2, set previously */
		putULong(reply_data+reply_ofs+8, t1);
		putULong(reply_data+reply_ofs+12, t2);

		/*
		 * Get ready for next IA_NA.
		 */
		reply_ofs += (len + 16);

		/*
		 * Bit of cleanup.
		 */
		if (lease != NULL) {
			iaaddr_dereference(&lease, MDL);
		}
		ia_na_dereference(&ia_na, MDL);
		if (iaaddr.data != NULL) {
			data_string_forget(&iaaddr, MDL);
		}
		option_state_dereference(&host_opt_state, MDL);
		option_state_dereference(&cli_enc_opt_state, MDL);
		data_string_forget(&oro, MDL);
		data_string_forget(&cli_enc_opt_data, MDL);
		/* XXX: */ break;
		/* ia = next_option(&dhcpv6_universe, packet->options, ia); */
	}

	/* 
	 * Return our reply to the caller.
	 */
	reply_ret->len = reply_ofs;
	reply_ret->buffer = NULL;
	if (!buffer_allocate(&reply_ret->buffer, reply_ofs, MDL)) {
		log_fatal("No memory to store reply.");
	}
	reply_ret->data = reply_ret->buffer->data;
	memcpy((char *)reply_ret->data, reply, reply_ofs);
	
exit:
	if (lease != NULL) {
		iaaddr_dereference(&lease, MDL);
	}
	if (ia_na != NULL) {
		ia_na_dereference(&ia_na, MDL);
	}
	if (iaaddr.buffer != NULL) {
		data_string_forget(&iaaddr, MDL);
	}
	if (fixed_addr.buffer != NULL) {
		data_string_forget(&fixed_addr, MDL);
	}
	if (host_opt_state != NULL) {
		option_state_dereference(&host_opt_state, MDL);
	}
	if (cli_enc_opt_state != NULL) {
		option_state_dereference(&cli_enc_opt_state, MDL);
	}
	if (cli_enc_opt_data.buffer != NULL) {
		data_string_forget(&cli_enc_opt_data, MDL);
	}
	if (oro.buffer != NULL) {
		data_string_forget(&oro, MDL);
	}
	if (packet_oro.buffer != NULL) {
		data_string_forget(&packet_oro, MDL);
	}
	if (opt_state != NULL) {
		option_state_dereference(&opt_state, MDL);
	}
}

/*
 * Solicit is how a client starts requesting addresses.
 *
 * If the client asks for rapid commit, and we support it, we will 
 * allocate the addresses and reply.
 *
 * Otherwise we will send an advertise message.
 */

/* TODO: discard unicast messages */
static void
dhcpv6_solicit(struct data_string *reply_ret, struct packet *packet) {
	struct data_string client_id;
	struct option_cache *oc;

	/* 
	 * Validate our input.
	 */
	if (!valid_client_msg(packet, &client_id)) {
		return;
	}

	/*
	 * If the client requests a rapid commit, then we will send a Reply,
	 * otherwise we will send an Advertise.
	 *
	 * TODO: make this configurable on the server side
	 */
	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_RAPID_COMMIT);
	if (oc == NULL) {
		lease_to_client(reply_ret, packet, 
				&client_id, NULL, DHCPV6_ADVERTISE);
	} else {
		lease_to_client(reply_ret, packet, 
				&client_id, NULL, DHCPV6_REPLY);
	}

	/*
	 * Clean up.
	 */
	data_string_forget(&client_id, MDL);
}

/*
 * Request is how a client actually requests addresses.
 *
 * Very similar to Solicit handling, except the server DUID is required.
 */

/* TODO: discard unicast messages, unless we set unicast option */
static void
dhcpv6_request(struct data_string *reply_ret, struct packet *packet) {
	struct data_string client_id;
	struct data_string server_id;

	/*
	 * Validate our input.
	 */
	if (!valid_client_resp(packet, &client_id, &server_id)) {
		return;
	}

	/*
	 * Issue our lease.
	 */
	lease_to_client(reply_ret, packet, &client_id, 
			&server_id, DHCPV6_REPLY);

	/*
	 * Cleanup.
	 */
	data_string_forget(&client_id, MDL);
	data_string_forget(&server_id, MDL);
}

/*
 * When a client thinks it might be on a new link, it sends a 
 * Confirm message.
 */

/* TODO: discard unicast messages, unless we set unicast option */
static void
dhcpv6_confirm(struct data_string *reply_ret, struct packet *packet) {
	struct data_string client_id;
	struct option_state *opt_state;
	char reply_data[65536];
	struct dhcpv6_packet *reply = (struct dhcpv6_packet *)reply_data;
	int reply_ofs = (int)((char *)reply->options - (char *)reply);
	struct option_cache *ia;
	struct option_cache *oc;
	/* cli_enc_... variables come from the IA_NA/IA_TA options */
	struct data_string cli_enc_opt_data;
	struct option_state *cli_enc_opt_state;
	struct data_string iaaddr;
	struct host_decl *host;
	int num_ia;
	int num_addr;
	struct data_string fixed_addr;
	struct data_string packet_oro;

	/* 
	 * Validate the message.
	 */
	if (!valid_client_msg(packet, &client_id)) {
		return;
	}

	/* 
	 * Bit of variable initialization.
	 */
	memset(&iaaddr, 0, sizeof(iaaddr));
	num_ia = 0;
	num_addr = 0;
	memset(&fixed_addr, 0, sizeof(fixed_addr));
	memset(&packet_oro, 0, sizeof(packet_oro));

	/* 
	 * Set up reply.
	 */
	if (!start_reply(packet, &client_id, NULL, &opt_state, 0, reply)) {
		goto exit;
	}

	/* 
	 * Search each IA to make sure we know about it.
	 */
	ia = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_NA);
	for (; ia != NULL;
	     /* XXX: */ ia = NULL) {
	     /* ia = next_option(&dhcpv6_universe, packet->options, ia) */

		num_ia++;

		if (!get_encapsulated_IA_state(&cli_enc_opt_state,
					       &cli_enc_opt_data,
					       packet, ia)) {
			goto exit;
		}

		memset(&iaaddr, 0, sizeof(iaaddr));
		oc = lookup_option(&dhcpv6_universe, cli_enc_opt_state, 
				   D6O_IAADDR);
		if (oc == NULL) {
			/* 
			 * No address with this IA, check next.
			 */
			continue;
		}

		if (!evaluate_option_cache(&iaaddr, packet, 
					   NULL, NULL, 
					   packet->options, 
					   NULL, &global_scope,
					   oc, MDL)) {
			log_error("dhcpv6_confirm: "
		  		  "error evaluating IAADDR.");
			goto exit;
		}

		host = NULL;
		if (!find_hosts_by_uid(&host, 
				       client_id.data, client_id.len, MDL)) {
			/*
			 * RFC 3315, section 18.2.2 implies that when the
			 * server doesn't know about the client it should
			 * not send a reply.
			 */
			goto exit;
		}

		/* 
		 * Find the matching host entry, if any.
		 */
		for (; host != NULL; host = host->n_ipaddr) {
			if (host->fixed_addr == NULL) {
				continue;
			} 
			if (!evaluate_option_cache(&fixed_addr, NULL, 
						   NULL, NULL, NULL, 
						   NULL, &global_scope,
						   host->fixed_addr, 
						   MDL)) {
				log_error("dhcpv6_confirm: error "
					  "evaluating host address.");
				goto exit;
			}
			if ((iaaddr.len >= 16) &&
			    !memcmp(fixed_addr.data, iaaddr.data, 16)) {
				data_string_forget(&fixed_addr, MDL);
				break;
			}
			data_string_forget(&fixed_addr, MDL);
		}

		/* 
		 * No matching entry found, so this is a bad address.
		 */
		if (host != NULL) {
			num_addr++;
		}

	}

	/* 
	 * If we have no addresses from the client, we don't send a reply.
	 */
	if (num_addr == 0) {
		goto exit;
	}

	/* 
	 * Set our status.
	 */
	if (num_addr < num_ia) {
		if (!set_status_code(STATUS_NotOnLink, 
				     "Some of the addresses are not on link.",
				     opt_state)) {
			goto exit;
		}
	} else {
		if (!set_status_code(STATUS_Success, 
				     "All addresses still on link.",
				     opt_state)) {
			goto exit;
		}
	}

	/* 
	 * Only one option: add it.
	 */
	reply_ofs += store_options6(reply_data+reply_ofs,
				    sizeof(reply_data)-reply_ofs, 
				    opt_state, packet,
				    required_opts, &packet_oro);

	/* 
	 * Return our reply to the caller.
	 */
	reply_ret->len = reply_ofs;
	reply_ret->buffer = NULL;
	if (!buffer_allocate(&reply_ret->buffer, reply_ofs, MDL)) {
		log_fatal("No memory to store reply.");
	}
	reply_ret->data = reply_ret->buffer->data;
	memcpy((char *)reply_ret->data, reply, reply_ofs);

exit:
	if (iaaddr.buffer != NULL) {
		data_string_forget(&iaaddr, MDL);
	}
	if (fixed_addr.buffer != NULL) {
		data_string_forget(&fixed_addr, MDL);
	}
	data_string_forget(&client_id, MDL);
}

/*
 * Renew is when a client wants to extend its lease, at time T1.
 *
 * We handle this the same as if the client wants a new lease, except
 * for the error code of when addresses don't match.
 */

/* TODO: discard unicast messages, unless we set unicast option */
static void
dhcpv6_renew(struct data_string *reply, struct packet *packet) {
	struct data_string client_id;
	struct data_string server_id;

	/* 
	 * Validate the request.
	 */
	if (!valid_client_resp(packet, &client_id, &server_id)) {
		return;
	}

	/*
	 * Renew our lease.
	 */
	lease_to_client(reply, packet, &client_id, &server_id, DHCPV6_REPLY);

	/*
	 * Cleanup.
	 */
	data_string_forget(&server_id, MDL);
	data_string_forget(&client_id, MDL);
}

/*
 * Rebind is when a client wants to extend its lease, at time T2.
 *
 * We handle this the same as if the client wants a new lease, except
 * for the error code of when addresses don't match.
 */

/* TODO: discard unicast messages, unless we set unicast option */
static void
dhcpv6_rebind(struct data_string *reply, struct packet *packet) {
	struct data_string client_id;

	if (!valid_client_msg(packet, &client_id)) {
		return;
	}

        lease_to_client(reply, packet, &client_id, NULL, DHCPV6_REPLY);

	data_string_forget(&client_id, MDL);
}

static void
ia_na_match_decline(const struct data_string *client_id,
		    const struct data_string *iaaddr,
		    struct iaaddr *lease) {
	char tmp_addr[INET6_ADDRSTRLEN];

	log_error("Client %s reports address %s is "
		  "already in use by another host!",
		  print_hex_1(client_id->len, client_id->data, 60),
		  inet_ntop(AF_INET6, iaaddr->data, 
		  	    tmp_addr, sizeof(tmp_addr)));
	if (lease != NULL) {
		decline_lease6(lease->ipv6_pool, lease);
		write_ia_na(lease->ia_na);
	}
}

static void
ia_na_nomatch_decline(const struct data_string *client_id,
		      const struct data_string *iaaddr,
		      u_int32_t *ia_na_id,
		      struct packet *packet,
		      char *reply_data,
		      int *reply_ofs,
		      int reply_len) {
	char tmp_addr[INET6_ADDRSTRLEN];
	struct option_state *host_opt_state;
	struct data_string oro;
	int len;

	log_info("Client %s declines address %s, which is not offered to it.",
		 print_hex_1(client_id->len, client_id->data, 60),
		 inet_ntop(AF_INET6, iaaddr->data, tmp_addr, sizeof(tmp_addr)));

	/*
	 * Create state for this IA_NA.
	 */
	host_opt_state = NULL;
	if (!option_state_allocate(&host_opt_state, MDL)) {
		log_error("ia_na_nomatch_decline: out of memory "
			  "allocating option_state.");
		goto exit;
	}

	if (!set_status_code(STATUS_NoBinding, "Decline for unknown address.",
			     host_opt_state)) {
		goto exit;
	}

	/*
	 * Insure we have enough space
	 */
	if (reply_len < (*reply_ofs + 16)) {
		log_error("ia_na_nomatch_decline: "
			  "out of space for reply packet.");
		goto exit;
	}

	/*
	 * Put our status code into the reply packet.
	 */
	memset(&oro, 0, sizeof(oro));	/* empty ORO */
	len = store_options6(reply_data+(*reply_ofs)+16,
			     reply_len-(*reply_ofs)-16,
			     host_opt_state, packet,
			     required_opts_STATUS_CODE, &oro);

	/*
	 * Store the non-encapsulated option data for this 
	 * IA_NA into our reply packet. Defined in RFC 3315, 
	 * section 22.4.  
	 */
	/* option number */
	putUShort(reply_data+(*reply_ofs), D6O_IA_NA);
	/* option length */
	putUShort(reply_data+(*reply_ofs)+2, len + 12);
	/* IA_NA, copied from the client */
	memcpy(reply_data+(*reply_ofs)+4, ia_na_id, 4);
	/* t1 and t2, odd that we need them, but here it is */
	putULong(reply_data+(*reply_ofs)+8, 0);
	putULong(reply_data+(*reply_ofs)+12, 0);

	/*
	 * Get ready for next IA_NA.
	 */
	*reply_ofs += (len + 16);

exit:
	option_state_dereference(&host_opt_state, MDL);
}

static void
iterate_over_ia_na(struct data_string *reply_ret, 
		   struct packet *packet,
		   const struct data_string *client_id,
		   const struct data_string *server_id,
		   char *packet_type,
		   void (*ia_na_match)(),
		   void (*ia_na_nomatch)()) {
	struct option_state *opt_state;
	struct host_decl *packet_host;
	struct option_cache *ia;
	struct option_cache *oc;
	/* cli_enc_... variables come from the IA_NA/IA_TA options */
	struct data_string cli_enc_opt_data;
	struct option_state *cli_enc_opt_state;
	struct host_decl *host;
	struct option_state *host_opt_state;
	char tmp_addr[INET6_ADDRSTRLEN];
	int len;
	struct data_string iaaddr;
	struct data_string fixed_addr;
	int iaaddr_is_found;
	char reply_data[65536];
	struct dhcpv6_packet *reply = (struct dhcpv6_packet *)reply_data;
	int reply_ofs = (int)((char *)reply->options - (char *)reply);
	struct data_string d;
	char status_msg[32];
	struct iaaddr *lease;
	struct ia_na *existing_ia_na;
	int i;
	struct data_string key;
	u_int32_t iaid;

	/*
	 * Initialize to empty values, in case we have to exit early.
	 */
	opt_state = NULL;
	memset(&cli_enc_opt_data, 0, sizeof(cli_enc_opt_data));
	cli_enc_opt_state = NULL;
	memset(&iaaddr, 0, sizeof(iaaddr));
	memset(&fixed_addr, 0, sizeof(fixed_addr));
	host_opt_state = NULL;
	lease = NULL;

	/* 
	 * Find the host record that matches from the packet, if any.
	 */
	packet_host = NULL;
	if (!find_hosts_by_uid(&packet_host, 
			       client_id->data, client_id->len, MDL)) {
		packet_host = NULL;
		/* 
		 * Note: In general, we don't expect a client to provide
		 *       enough information to match by option for these
		 *       types of messages, but if we don't have a UID
		 *       match we can check anyway.
		 */
		if (!find_hosts_by_option(&packet_host, 
					  packet, packet->options, MDL)) {
			packet_host = NULL;
		}
	}

	/* 
	 * Set our reply information.
	 */
	reply->msg_type = DHCPV6_REPLY;
	memcpy(reply->transaction_id, packet->dhcpv6_transaction_id, 
	       sizeof(reply->transaction_id));

	/*
	 * Build our option state for reply.
	 */
	opt_state = NULL;
	if (!option_state_allocate(&opt_state, MDL)) {
		log_error("iterate_over_ia_na: no memory for option_state.");
		goto exit;
	}
	execute_statements_in_scope(NULL, packet, NULL, NULL, 
				    packet->options, opt_state, 
				    &global_scope, root_group, NULL);

	/* 
	 * RFC 3315, section 18.2.7 tells us which options to include.
	 */
	oc = lookup_option(&dhcpv6_universe, opt_state, D6O_SERVERID);
	if (oc == NULL) {
		if (!save_option_buffer(&dhcpv6_universe, opt_state, 
					NULL, (char *)duid.data, duid.len, 
					D6O_SERVERID, 0)) {
			log_error("iterate_over_ia_na: "
				  "error saving server identifier.");
			goto exit;
		}
	}

	if (!save_option_buffer(&dhcpv6_universe, opt_state, 
				client_id->buffer, 
				(unsigned char *)client_id->data,
				client_id->len, 
				D6O_CLIENTID, 0)) {
		log_error("iterate_over_ia_na: "
			  "error saving client identifier.");
		goto exit;
	}

	snprintf(status_msg, sizeof(status_msg), "%s received.", packet_type);
	if (!set_status_code(STATUS_Success, status_msg, opt_state)) {
		goto exit;
	}

	/* 
	 * Add our options that are not associated with any IA_NA or IA_TA. 
	 */
	memset(&d, 0, sizeof(d));	/* empty ORO */
	reply_ofs += store_options6(reply_data+reply_ofs,
				    sizeof(reply_data)-reply_ofs, 
				    opt_state, packet,
				    required_opts, &d);

	/*
	 * Loop through the IA_NA reported by the client, and deal with
	 * addresses reported as already in use.
	 */
	for (ia = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_NA);
	     ia != NULL; 
	     /* XXX: we should use the following line */
             /* ia = next_option(&dhcpv6_universe, packet->options, ia) */
	     ia = NULL) {
	     	iaaddr_is_found = 0;

		if (!get_encapsulated_IA_state(&cli_enc_opt_state,
					       &cli_enc_opt_data,
					       packet, ia)) {
			goto exit;
		}

		iaid = getULong(cli_enc_opt_data.data+4);

		/* 
		 * XXX: It is possible that we can get mulitple addresses
		 *      sent by the client. We don't send multiple 
		 *      addresses, so this indicates a client error. 
		 *      We should check for multiple IAADDR options, log
		 *      if found, and set as an error.
		 */
		oc = lookup_option(&dhcpv6_universe, cli_enc_opt_state, 
				   D6O_IAADDR);
		if (oc == NULL) {
			/* no address given for this IA, ignore */
			option_state_dereference(&cli_enc_opt_state, MDL);
			data_string_forget(&cli_enc_opt_data, MDL);
			continue;
		}

		memset(&iaaddr, 0, sizeof(iaaddr));
		if (!evaluate_option_cache(&iaaddr, packet, NULL, NULL, 
					   packet->options, NULL,
					   &global_scope, oc, MDL)) {
			log_error("iterate_over_ia_na: "
				  "error evaluating IAADDR.");
			goto exit;
		}

		/* 
		 * Now we need to figure out which host record matches
		 * this IA_NA and IAADDR.
		 *
		 * XXX: We don't currently track IA_NA separately, but
		 *      we will need to do this!
		 */
		host = NULL;
		if (!find_hosts_by_option(&host, packet, 
					  cli_enc_opt_state, MDL)) { 
			if (packet_host != NULL) {
				host = packet_host;
			} else {
				host = NULL;
			}
		}
		while (host != NULL) {
			if (host->fixed_addr != NULL) {
				if (!evaluate_option_cache(&fixed_addr, NULL, 
							   NULL, NULL, NULL, 
							   NULL, &global_scope,
							   host->fixed_addr, 
							   MDL)) {
					log_error("iterate_over_ia_na: error "
						  "evaluating host address.");
					goto exit;
				}
				if ((iaaddr.len >= 16) &&
				    !memcmp(fixed_addr.data, iaaddr.data, 16)) {
					data_string_forget(&fixed_addr, MDL);
					break;
				}
				data_string_forget(&fixed_addr, MDL);
			}
			host = host->n_ipaddr;
		}

		if ((host == NULL) && (iaaddr.len == 16)) {
			/*
			 * Find existing IA_NA.
			 */
			if (ia_na_make_key(&key, iaid, client_id->data,
					   client_id->len, 
					   MDL) != ISC_R_SUCCESS) {
				log_fatal("iterate_over_ia_na: no memory for "
					  "key.");
			}

			existing_ia_na = NULL;
			if (ia_na_hash_lookup(&existing_ia_na, ia_active, 
					      (char *)key.data, key.len, MDL)) {
				/* 
				 * Make sure this address is in the IA_NA.
				 */
				for (i=0; i<existing_ia_na->num_iaaddr; i++) {
					struct iaaddr *tmp;
					struct in6_addr *in6_addr;

					tmp = existing_ia_na->iaaddr[i];
					in6_addr = &tmp->addr;
					if (memcmp(in6_addr, 
						   iaaddr.data, 16) == 0) {
						iaaddr_reference(&lease,
								 tmp, MDL);
						break;
				        }
				}
			}

			data_string_forget(&key, MDL);
		}

		if ((host != NULL) || (lease != NULL)) {
			ia_na_match(client_id, &iaaddr, lease);
		} else {
			ia_na_nomatch(client_id, &iaaddr, 
				      (u_int32_t *)cli_enc_opt_data.data, 
				      packet, reply_data, &reply_ofs, 
				      sizeof(reply_data));
		}

		if (lease != NULL) {
			iaaddr_dereference(&lease, MDL);
		}

		data_string_forget(&iaaddr, MDL);
		option_state_dereference(&cli_enc_opt_state, MDL);
		data_string_forget(&cli_enc_opt_data, MDL);
	}

	/* 
	 * Return our reply to the caller.
	 */
	reply_ret->len = reply_ofs;
	reply_ret->buffer = NULL;
	if (!buffer_allocate(&reply_ret->buffer, reply_ofs, MDL)) {
		log_fatal("No memory to store reply.");
	}
	reply_ret->data = reply_ret->buffer->data;
	memcpy((char *)reply_ret->data, reply, reply_ofs);

exit:
	if (lease != NULL) {
		iaaddr_dereference(&lease, MDL);
	}
	if (host_opt_state != NULL) {
		option_state_dereference(&host_opt_state, MDL);
	}
	if (fixed_addr.buffer != NULL) {
		data_string_forget(&fixed_addr, MDL);
	}
	if (iaaddr.buffer != NULL) {
		data_string_forget(&iaaddr, MDL);
	}
	if (cli_enc_opt_state != NULL) {
		option_state_dereference(&cli_enc_opt_state, MDL);
	}
	if (cli_enc_opt_data.buffer != NULL) {
		data_string_forget(&cli_enc_opt_data, MDL);
	}
	if (opt_state != NULL) {
		option_state_dereference(&opt_state, MDL);
	}
}

/*
 * Decline means a client has detected that something else is using an
 * address we gave it.
 *
 * Since we're only dealing with fixed leases for now, there's not
 * much we can do, other that log the occurrance.
 * 
 * When we start issuing addresses from pools, then we will have to
 * record our declined addresses and issue another. In general with
 * IPv6 there is no worry about DoS by clients exhausting space, but
 * we still need to be aware of this possibility.
 */

/* TODO: discard unicast messages, unless we set unicast option */
/* TODO: IA_TA */
static void
dhcpv6_decline(struct data_string *reply, struct packet *packet) {
	struct data_string client_id;
	struct data_string server_id;

	/* 
	 * Validate our input.
	 */
	if (!valid_client_resp(packet, &client_id, &server_id)) {
		return;
	}

	/*
	 * And operate on each IA_NA in this packet.
	 */
	iterate_over_ia_na(reply, packet, &client_id, &server_id, "Decline", 
			   ia_na_match_decline, ia_na_nomatch_decline);
}

static void
ia_na_match_release(const struct data_string *client_id,
		    const struct data_string *iaaddr,
		    struct iaaddr *lease) {
	char tmp_addr[INET6_ADDRSTRLEN];

	log_info("Client %s releases address %s",
		 print_hex_1(client_id->len, client_id->data, 60),
		 inet_ntop(AF_INET6, iaaddr->data, tmp_addr, sizeof(tmp_addr)));
	if (lease != NULL) {
		release_lease6(lease->ipv6_pool, lease);
		write_ia_na(lease->ia_na);
	}
}

static void
ia_na_nomatch_release(const struct data_string *client_id,
		      const struct data_string *iaaddr,
		      u_int32_t *ia_na_id,
		      struct packet *packet,
		      char *reply_data,
		      int *reply_ofs,
		      int reply_len) {
	char tmp_addr[INET6_ADDRSTRLEN];
	struct option_state *host_opt_state;
	struct data_string oro;
	int len;

	log_info("Client %s releases address %s, which is not leased to it.",
		 print_hex_1(client_id->len, client_id->data, 60),
		 inet_ntop(AF_INET6, iaaddr->data, tmp_addr, sizeof(tmp_addr)));

	/*
	 * Create state for this IA_NA.
	 */
	host_opt_state = NULL;
	if (!option_state_allocate(&host_opt_state, MDL)) {
		log_error("ia_na_match_release: out of memory "
			  "allocating option_state.");
		goto exit;
	}

	if (!set_status_code(STATUS_NoBinding, 
			     "Release for non-leased address.",
			     host_opt_state)) {
		goto exit;
	}

	/*
	 * Insure we have enough space
	 */
	if (reply_len < (*reply_ofs + 16)) {
		log_error("ia_na_match_release: "
			  "out of space for reply packet.");
		goto exit;
	}

	/*
	 * Put our status code into the reply packet.
	 */
	memset(&oro, 0, sizeof(oro));	/* empty ORO */
	len = store_options6(reply_data+(*reply_ofs)+16,
			     reply_len-(*reply_ofs)-16,
			     host_opt_state, packet,
			     required_opts_STATUS_CODE, &oro);

	/*
	 * Store the non-encapsulated option data for this 
	 * IA_NA into our reply packet. Defined in RFC 3315, 
	 * section 22.4.  
	 */
	/* option number */
	putUShort(reply_data+(*reply_ofs), D6O_IA_NA);
	/* option length */
	putUShort(reply_data+(*reply_ofs)+2, len + 12);
	/* IA_NA, copied from the client */
	memcpy(reply_data+(*reply_ofs)+4, ia_na_id, 4);
	/* t1 and t2, odd that we need them, but here it is */
	putULong(reply_data+(*reply_ofs)+8, 0);
	putULong(reply_data+(*reply_ofs)+12, 0);

	/*
	 * Get ready for next IA_NA.
	 */
	*reply_ofs += (len + 16);

exit:
	option_state_dereference(&host_opt_state, MDL);
}

/*
 * Release means a client is done with the addresses.
 */

/* TODO: discard unicast messages, unless we set unicast option */
static void
dhcpv6_release(struct data_string *reply, struct packet *packet) {
	struct data_string client_id;
	struct data_string server_id;

	/* 
	 * Validate our input.
	 */
	if (!valid_client_resp(packet, &client_id, &server_id)) {
		return;
	}

	/*
	 * And operate on each IA_NA in this packet.
	 */
	iterate_over_ia_na(reply, packet, &client_id, &server_id, "Release", 
			   ia_na_match_release, ia_na_nomatch_release);

	data_string_forget(&server_id, MDL);
	data_string_forget(&client_id, MDL);
}

/* TODO: discard unicast messages, unless we set unicast option */
static void
dhcpv6_information_request(struct data_string *reply, struct packet *packet) {
	struct data_string server_id;

	if (!valid_client_info_req(packet, &server_id)) {
		return;
	}

	data_string_forget(&server_id, MDL);
}

/* 
 * The Relay-forw message is sent by relays. It typically contains a
 * single option, which encapsulates an entire packet.
 *
 * We need to build an encapsulated reply.
 */

/* XXX: this is very, very similar to do_packet6(), and should probably
	be combined in a clever way */
static void
dhcpv6_relay_forw(struct data_string *reply_ret, struct packet *packet) {
	struct dhcpv6_relay_packet reply;
	struct option_cache *oc;
	struct data_string enc_opt_data;
	struct packet *enc_packet;
	unsigned char msg_type;
        const struct dhcpv6_packet *msg;
        const struct dhcpv6_relay_packet *relay;
	struct data_string enc_reply;
	char link_addr[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
	char peer_addr[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
	struct data_string interface_id;

	/* 
	 * Intialize variables for early exit.
	 */
	memset(&enc_opt_data, 0, sizeof(enc_opt_data));
	enc_packet = NULL;
	memset(&enc_reply, 0, sizeof(enc_reply));
	memset(&interface_id, 0, sizeof(interface_id));

	/*
	 * Get our encapsulated relay message.
	 */
	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_RELAY_MSG);
	if (oc == NULL) {
		inet_ntop(AF_INET6, &packet->dhcpv6_link_address.sin6_addr,
			  link_addr, sizeof(link_addr));
		inet_ntop(AF_INET6, &packet->dhcpv6_peer_address.sin6_addr,
			  peer_addr, sizeof(peer_addr));
		log_info("Relay-forward from %s with link address=%s and "
			 "peer address=%s missing Relay Message option.",
			  piaddr(packet->client_addr), link_addr, peer_addr);
		goto exit;
	}

	memset(&enc_opt_data, 0, sizeof(enc_opt_data));
	if (!evaluate_option_cache(&enc_opt_data, NULL, NULL, NULL, 
				   NULL, NULL, &global_scope, oc, MDL)) {
		log_error("dhcpv6_forw_relay: error evaluating "
			  "relayed message.");
		goto exit;
	}

	if (!packet6_len_okay(enc_opt_data.data, enc_opt_data.len)) {
		log_error("dhcpv6_forw_relay: encapsulated packet too short.");
		goto exit;
	}

	/*
	 * Build a packet structure from this encapsulated packet.
	 */
	enc_packet = NULL;
	if (!packet_allocate(&enc_packet, MDL)) {
		log_error("dhcpv6_forw_relay: "
			  "no memory for encapsulated packet.");
		goto exit;
	}

	if (!option_state_allocate(&enc_packet->options, MDL)) {
		log_error("dhcpv6_forw_relay: "
			  "no memory for encapsulated packet's options.");
		goto exit;
	}

	enc_packet->client_port = packet->client_port;
	enc_packet->client_addr = packet->client_addr;

	msg_type = enc_opt_data.data[0];
        if ((msg_type == DHCPV6_RELAY_FORW) ||
            (msg_type == DHCPV6_RELAY_REPL)) {
                relay = (struct dhcpv6_relay_packet *)enc_opt_data.data;
                enc_packet->dhcpv6_msg_type = relay->msg_type;

                /* relay-specific data */
                enc_packet->dhcpv6_hop_count = relay->hop_count;
		memset(&enc_packet->dhcpv6_link_address, 0,
                       sizeof(enc_packet->dhcpv6_link_address));
                enc_packet->dhcpv6_link_address.sin6_family = AF_INET6;
		memcpy(&enc_packet->dhcpv6_link_address.sin6_addr,
		       relay->link_address, sizeof(relay->link_address));
                memset(&enc_packet->dhcpv6_peer_address, 0,
                       sizeof(enc_packet->dhcpv6_peer_address));
                enc_packet->dhcpv6_peer_address.sin6_family = AF_INET6;
		memcpy(&enc_packet->dhcpv6_peer_address.sin6_addr,
		       relay->peer_address, sizeof(relay->peer_address));

                if (!parse_option_buffer(enc_packet->options,
                                         relay->options, 
					 enc_opt_data.len-sizeof(*relay),
                                         &dhcpv6_universe)) {
                        /* no logging here, as parse_option_buffer() logs all
                           cases where it fails */
                        goto exit;
                }
        } else {
                msg = (struct dhcpv6_packet *)enc_opt_data.data;
                enc_packet->dhcpv6_msg_type = msg->msg_type;

                /* message-specific data */
                memcpy(enc_packet->dhcpv6_transaction_id,
                       msg->transaction_id,
                       sizeof(enc_packet->dhcpv6_transaction_id));

                if (!parse_option_buffer(enc_packet->options,
                                         msg->options, 
					 enc_opt_data.len-sizeof(*msg),
                                         &dhcpv6_universe)) {
                        /* no logging here, as parse_option_buffer() logs all
                           cases where it fails */
                        goto exit;
                }
        }

	/*
	 * This is recursive. It is possible to exceed maximum packet size.
	 * XXX: This will cause the packet send to fail.
	 */
	build_dhcpv6_reply(&enc_reply, enc_packet);

	/*
	 * If we got no encapsulated data, then it is discarded, and
	 * our reply-forw is also discarded.
	 */
	if (enc_reply.data == NULL) {
		goto exit;
	}

	/*
	 * Append the interface-id if present
	 */
	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_INTERFACE_ID);
	if (oc != NULL) {
		memset(&interface_id, 0, sizeof(interface_id));
		if (!evaluate_option_cache(&interface_id, NULL, NULL, NULL, 
					   NULL, NULL, &global_scope, 
					   oc, MDL)) {
			log_error("dhcpv6_forw_relay: error evaluating "
				  "Interface ID.");
			goto exit;
		}
	}

	/*
	 * Packet header stuff all comes from the forward message.
	 */
	reply.msg_type = DHCPV6_RELAY_REPL;
	reply.hop_count = packet->dhcpv6_hop_count;
	memcpy(reply.link_address, &packet->dhcpv6_link_address.sin6_addr,
	       sizeof(reply.link_address));
	memcpy(reply.peer_address, &packet->dhcpv6_peer_address.sin6_addr,
	       sizeof(reply.peer_address));

	/* 
	 * Copy our encapsulated stuff for caller.
	 */
	reply_ret->len = sizeof(reply) + 4 + enc_reply.len;
	if (interface_id.data != NULL) {
		reply_ret->len += 4 + interface_id.len;
	}
	/* 
	 * XXX: We should not allow this to happen, perhaps by letting
	 *      build_dhcp_reply() know our space remaining.
	 */
	if (reply_ret->len >= 65536) {
		log_error("dhcpv6_forw_relay: RELAY-REPL too big (%d bytes)",
			  reply_ret->len);
		goto exit;
	}
	reply_ret->buffer = NULL;
	if (!buffer_allocate(&reply_ret->buffer, reply_ret->len, MDL)) {
		log_fatal("No memory to store reply.");
	}
	reply_ret->data = reply_ret->buffer->data;
	memcpy((char *)reply_ret->data, &reply, sizeof(reply));
	putShort((char *)reply_ret->data+sizeof(reply), D6O_RELAY_MSG);
	putShort((char *)reply_ret->data+sizeof(reply)+2, enc_reply.len);
	memcpy((char *)reply_ret->data+sizeof(reply)+4, 
	       enc_reply.data, enc_reply.len);
	if (interface_id.data != NULL) {
		putShort((char *)reply_ret->data+sizeof(reply)+4+enc_reply.len,
			 D6O_INTERFACE_ID);
		putShort((char *)reply_ret->data+sizeof(reply)+6+enc_reply.len,
			 interface_id.len);
		memcpy((char *)reply_ret->data+sizeof(reply)+8+enc_reply.len,
		       interface_id.data, interface_id.len);
	}

exit:
	if (interface_id.data != NULL) {
		data_string_forget(&interface_id, MDL);
	}
	if (enc_reply.data != NULL) {
		data_string_forget(&enc_reply, MDL);
	}
	if (enc_opt_data.data != NULL) {
		data_string_forget(&enc_opt_data, MDL);
	}
	if (enc_packet != NULL) {
		packet_dereference(&enc_packet, MDL);
	}
}

static void
dhcpv6_discard(struct packet *packet) {
	/* INSIST(packet->msg_type > 0); */
	/* INSIST(packet->msg_type < dhcpv6_type_name_max); */

	log_debug("Discarding %s from %s; message type not handled by server", 
		  dhcpv6_type_names[packet->dhcpv6_msg_type],
		  piaddr(packet->client_addr));
}

static void 
build_dhcpv6_reply(struct data_string *reply, struct packet *packet) {
	memset(reply, 0, sizeof(*reply));
	switch (packet->dhcpv6_msg_type) {
		case DHCPV6_SOLICIT:
			dhcpv6_solicit(reply, packet);
			break;
		case DHCPV6_ADVERTISE:
			dhcpv6_discard(packet);
			break;
		case DHCPV6_REQUEST:
			dhcpv6_request(reply, packet);
			break;
		case DHCPV6_CONFIRM:
			dhcpv6_confirm(reply, packet);
			break;
		case DHCPV6_RENEW:
			dhcpv6_renew(reply, packet);
			break;
		case DHCPV6_REBIND:
			dhcpv6_rebind(reply, packet);
			break;
		case DHCPV6_REPLY:
			dhcpv6_discard(packet);
			break;
		case DHCPV6_RELEASE:
			dhcpv6_release(reply, packet);
			break;
		case DHCPV6_DECLINE:
			dhcpv6_decline(reply, packet);
			break;
		case DHCPV6_RECONFIGURE:
			dhcpv6_discard(packet);
			break;
		case DHCPV6_INFORMATION_REQUEST:
			dhcpv6_information_request(reply, packet);
			break;
		case DHCPV6_RELAY_FORW:
			dhcpv6_relay_forw(reply, packet);
			break;
		case DHCPV6_RELAY_REPL:
			dhcpv6_discard(packet);
			break;
		default:
			/* XXX: would be nice if we had "notice" level, 
				as syslog, for this */
			log_info("Discarding unknown DHCPv6 message type %d "
				 "from %s", packet->dhcpv6_msg_type, 
				 piaddr(packet->client_addr));
	}
}

static void
log_packet_in(const struct packet *packet) {
	struct data_string s;
	u_int32_t tid;
	char tmp_addr[INET6_ADDRSTRLEN];
	const void *addr;
	struct option_cache *oc;
	struct data_string tmp_ds;

	memset(&s, 0, sizeof(s));

	if (packet->dhcpv6_msg_type < dhcpv6_type_name_max) {
		data_string_sprintfa(&s, "%s message from %s port %d",
				     dhcpv6_type_names[packet->dhcpv6_msg_type],
				     piaddr(packet->client_addr),
				     ntohs(packet->client_port));
	} else {
		data_string_sprintfa(&s, 
				     "Unknown message type %d from %s port %d",
				     packet->dhcpv6_msg_type,
				     piaddr(packet->client_addr),
				     ntohs(packet->client_port));
	}
	if ((packet->dhcpv6_msg_type == DHCPV6_RELAY_FORW) || 
	    (packet->dhcpv6_msg_type == DHCPV6_RELAY_REPL)) {
	    	addr = &packet->dhcpv6_link_address.sin6_addr;
	    	data_string_sprintfa(&s, ", link address %s", 
				     inet_ntop(AF_INET6, addr, 
					       tmp_addr, sizeof(tmp_addr)));
	    	addr = &packet->dhcpv6_peer_address.sin6_addr;
	    	data_string_sprintfa(&s, ", peer address %s", 
				     inet_ntop(AF_INET6, addr, 
					       tmp_addr, sizeof(tmp_addr)));
	} else {
		tid = 0;
		memcpy(((char *)&tid)+1, packet->dhcpv6_transaction_id, 3);
		data_string_sprintfa(&s, ", transaction ID 0x%06X", tid);

/*
		oc = lookup_option(&dhcpv6_universe, packet->options, 
				   D6O_CLIENTID);
		if (oc != NULL) {
			memset(&tmp_ds, 0, sizeof(tmp_ds_));
			if (!evaluate_option_cache(&tmp_ds, packet, NULL, NULL, 
						   packet->options, NULL,
						   &global_scope, oc, MDL)) {
				log_error("Error evaluating Client Identifier");
			} else {
				data_strint_sprintf(&s, ", client ID %s",

				data_string_forget(&tmp_ds, MDL);
			}
		}
*/

	}
	log_info("%s", s.data);

	data_string_forget(&s, MDL);
}

void 
dhcpv6(struct packet *packet) {
	struct data_string reply;
	struct sockaddr_in6 to_addr;
	int send_ret;

	/* 
	 * Log a message that we received this packet.
	 */
	log_packet_in(packet); 

	/*
	 * Build our reply packet.
	 */
	build_dhcpv6_reply(&reply, packet);

	if (reply.data != NULL) {
		/* 
		 * Send our reply, if we have one.
		 */
		memset(&to_addr, 0, sizeof(to_addr));
		to_addr.sin6_family = AF_INET6;
		if ((packet->dhcpv6_msg_type == DHCPV6_RELAY_FORW) || 
		    (packet->dhcpv6_msg_type == DHCPV6_RELAY_REPL)) {
			to_addr.sin6_port = local_port;
		} else {
			to_addr.sin6_port = remote_port;
		}
/* For testing, we reply to the sending port, so we don't need a root client */
		to_addr.sin6_port = packet->client_port;
		memcpy(&to_addr.sin6_addr, packet->client_addr.iabuf, 
		       sizeof(to_addr.sin6_addr));

		log_info("Sending %s to %s port %d", 
			 dhcpv6_type_names[reply.data[0]],
			 piaddr(packet->client_addr),
			 ntohs(to_addr.sin6_port));

		send_ret = send_packet6(packet->interface, 
					reply.data, reply.len, &to_addr);
		if (send_ret != reply.len) {
			log_error("dhcpv6: send_packet6() sent %d of %d bytes",
				  send_ret, reply.len);
		}
		data_string_forget(&reply, MDL);
	}
}

