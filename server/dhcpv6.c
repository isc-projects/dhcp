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

#ifdef DHCPv6

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
 * TODO: support multiple shared_networks on each interface (this 
 *       will allow the server to issue multiple IPv6 addresses to 
 *       a single interface)
 */

/*
 * DHCPv6 Reply workflow assist.  A Reply packet is built by various
 * different functions; this gives us one location where we keep state
 * regarding a reply.
 */
struct reply_state {
	/* root level persistent state */
	struct shared_network *shared;
	struct host_decl *host;
	struct option_state *opt_state;
	struct packet *packet;
	struct data_string client_id;

	/* IA level persistent state */
	unsigned ia_count;
	unsigned client_addresses;
	isc_boolean_t ia_addrs_included;
	isc_boolean_t static_lease;
	struct ia_na *ia_na;
	struct ia_na *old_ia;
	struct option_state *reply_ia;
	struct data_string fixed;

	/* IAADDR level persistent state */
	struct iaaddr *lease;

	/*
	 * "t1", "t2", preferred, and valid lifetimes records for calculating
	 * t1 and t2 (min/max).
	 */
	u_int32_t renew, rebind, prefer, valid;

	/* Client-requested valid and preferred lifetimes. */
	u_int32_t client_valid, client_prefer;

	/* Chosen values to transmit for valid and preferred lifetimes. */
	u_int32_t send_valid, send_prefer;

	/* Index into the data field that has been consumed. */
	unsigned cursor;

	union reply_buffer {
		unsigned char data[65536];
		struct dhcpv6_packet reply;
	} buf;
};

/* 
 * Prototypes local to this file.
 */
static int get_encapsulated_IA_state(struct option_state **enc_opt_state,
				     struct data_string *enc_opt_data,
				     struct packet *packet,
				     struct option_cache *oc,
				     int offset);
static void build_dhcpv6_reply(struct data_string *, struct packet *);
static isc_result_t shared_network_from_packet6(struct shared_network **shared,
						struct packet *packet);
static void seek_shared_host(struct host_decl **hp,
			     struct shared_network *shared);
static isc_boolean_t fixed_matches_shared(struct host_decl *host,
					  struct shared_network *shared);
static isc_result_t reply_process_ia(struct reply_state *reply,
				     struct option_cache *ia);
static isc_result_t reply_process_addr(struct reply_state *reply,
				       struct option_cache *addr);
static isc_boolean_t address_is_owned(struct reply_state *reply,
				      struct iaddr *addr);
static isc_result_t reply_process_try_addr(struct reply_state *reply,
					   struct iaddr *addr);
static isc_result_t find_client_address(struct reply_state *reply);
static isc_result_t reply_process_is_addressed(struct reply_state *reply,
					       struct binding_scope **scope,
					       struct group *group);
static isc_result_t reply_process_send_addr(struct reply_state *reply,
					    struct iaddr *addr);
static struct iaaddr *lease_compare(struct iaaddr *alpha, struct iaaddr *beta);

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
 *
 * This must remain the same for the lifetime of this server, because
 * clients return the server DUID that we sent them in Request packets.
 *
 * We pick the server DUID like this:
 *
 * 1. Check dhcpd.conf - any value the administrator has configured 
 *    overrides any possible values.
 * 2. Check the leases.txt - we want to use the previous value if 
 *    possible.
 * 3. Check if dhcpd.conf specifies a type of server DUID to use,
 *    and generate that type.
 * 4. Generate a type 1 (time + hardware address) DUID.
 */
static struct data_string server_duid;

/*
 * Check if the server_duid has been set.
 */
isc_boolean_t 
server_duid_isset(void) {
	return (server_duid.data != NULL);
}

/*
 * Return the server_duid.
 */
void
copy_server_duid(struct data_string *ds, const char *file, int line) {
	data_string_copy(ds, &server_duid, file, line);
}

/*
 * Set the server DUID to a specified value. This is used when
 * the server DUID is stored in persistent memory (basically the
 * leases.txt file).
 */
void
set_server_duid(struct data_string *new_duid) {
	/* INSIST(new_duid != NULL); */
	/* INSIST(new_duid->data != NULL); */

	if (server_duid_isset()) {
		data_string_forget(&server_duid, MDL);
	}
	data_string_copy(&server_duid, new_duid, MDL);
}


/*
 * Set the server DUID based on the D6O_SERVERID option. This handles
 * the case where the administrator explicitly put it in the dhcpd.conf 
 * file.
 */
isc_result_t
set_server_duid_from_option(void) {
	struct option_state *opt_state;
	struct option_cache *oc;
	struct data_string option_duid;
	isc_result_t ret_val;

	opt_state = NULL;
	if (!option_state_allocate(&opt_state, MDL)) {
		log_fatal("No memory for server DUID.");
	}

	execute_statements_in_scope(NULL, NULL, NULL, NULL, NULL,
				    opt_state, &global_scope, root_group, NULL);

	oc = lookup_option(&dhcpv6_universe, opt_state, D6O_SERVERID);
	if (oc == NULL) {
		ret_val = ISC_R_NOTFOUND;
	} else {
		memset(&option_duid, 0, sizeof(option_duid));
		if (!evaluate_option_cache(&option_duid, NULL, NULL, NULL, 
					   opt_state, NULL, &global_scope, 
					   oc, MDL)) {
			ret_val = ISC_R_UNEXPECTED;
		} else {
			set_server_duid(&option_duid);
			data_string_forget(&option_duid, MDL);
			ret_val = ISC_R_SUCCESS;
		}
	}

	option_state_dereference(&opt_state, MDL);

	return ret_val;
}

/*
 * DUID layout, as defined in RFC 3315, section 9.
 * 
 * We support type 1 (hardware address plus time) and type 3 (hardware
 * address).
 *
 * We can support type 2 for specific vendors in the future, if they 
 * publish the specification. And of course there may be additional
 * types later.
 */
static int server_duid_type = DUID_LLT;

/* 
 * Set the DUID type.
 */
void
set_server_duid_type(int type) {
	server_duid_type = type;
}

/*
 * Generate a new server DUID. This is done if there was no DUID in 
 * the leases.txt or in the dhcpd.conf file.
 */
isc_result_t
generate_new_server_duid(void) {
	struct interface_info *p;
	u_int32_t time_val;
	struct data_string generated_duid;

	/*
	 * Verify we have a type that we support.
	 */
	if ((server_duid_type != DUID_LL) && (server_duid_type != DUID_LLT)) {
		log_error("Invalid DUID type %d specified, "
			  "only LL and LLT types supported", server_duid_type);
		return ISC_R_INVALIDARG;
	}

	/*
	 * Find an interface with a hardware address.
	 * Any will do. :)
	 */
	for (p = interfaces; p != NULL; p = p->next) {
		if (p->hw_address.hlen > 0) {
			break;
		}
	}
	if (p == NULL) {
		return ISC_R_UNEXPECTED;
	}

	/*
	 * Build our DUID.
	 */
	memset(&generated_duid, 0, sizeof(generated_duid));
	if (server_duid_type == DUID_LLT) {
		time_val = duid_time(time(NULL));
		generated_duid.len = 8 + p->hw_address.hlen - 1;
		if (!buffer_allocate(&generated_duid.buffer, 
				     generated_duid.len, MDL)) {
			log_fatal("No memory for server DUID.");
		}
		generated_duid.data = generated_duid.buffer->data;
		putUShort(generated_duid.buffer->data, DUID_LLT);
		putUShort(generated_duid.buffer->data + 2, 
			  p->hw_address.hbuf[0]);
		putULong(generated_duid.buffer->data + 4, time_val);
		memcpy(generated_duid.buffer->data + 8, 
		       p->hw_address.hbuf+1, p->hw_address.hlen-1);
	} else if (server_duid_type == DUID_LL) {
		generated_duid.len = 4 + p->hw_address.hlen - 1;
		if (!buffer_allocate(&generated_duid.buffer, 
				     generated_duid.len, MDL)) {
			log_fatal("No memory for server DUID.");
		}
		generated_duid.data = generated_duid.buffer->data;
		putUShort(generated_duid.buffer->data, DUID_LL);
		putUShort(generated_duid.buffer->data + 2, 
			  p->hw_address.hbuf[0]);
		memcpy(generated_duid.buffer->data +4, 
		       p->hw_address.hbuf+1, p->hw_address.hlen-1);
	} else {
		log_fatal("Unsupported server DUID type %d.", server_duid_type);
	} 

	set_server_duid(&generated_duid);
	data_string_forget(&generated_duid, MDL);

	return ISC_R_SUCCESS;
}

/*
 * Get the client identifier from the packet.
 */
isc_result_t
get_client_id(struct packet *packet, struct data_string *client_id) {
	struct option_cache *oc;

	/*
	 * Verify our client_id structure is empty.
	 */
	if ((client_id->data != NULL) || (client_id->len != 0)) {
		return ISC_R_INVALIDARG;
	}

	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_CLIENTID);
	if (oc == NULL) {
		return ISC_R_NOTFOUND;
	}

	if (!evaluate_option_cache(client_id, packet, NULL, NULL, 
				   packet->options, NULL,
				   &global_scope, oc, MDL)) {
		return ISC_R_FAILURE;
	}

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

	switch (get_client_id(packet, client_id)) {
		case ISC_R_SUCCESS:
			break;
		case ISC_R_NOTFOUND:
			log_debug("Discarding %s from %s; "
				  "client identifier missing", 
				  dhcpv6_type_names[packet->dhcpv6_msg_type],
				  piaddr(packet->client_addr));
			goto exit;
		default:
			log_error("Error processing %s from %s; "
				  "unable to evaluate Client Identifier",
				  dhcpv6_type_names[packet->dhcpv6_msg_type],
				  piaddr(packet->client_addr));
			goto exit;
	}

	/*
	 * Required by RFC 3315, section 15.
	 */
	if (packet->unicast) {
		log_debug("Discarding %s from %s; packet sent unicast "
			  "(CLIENTID %s)", 
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr),
			  print_hex_1(client_id->len, client_id->data, 60));
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
		  struct data_string *server_id)
{
	int ret_val;
	struct option_cache *oc;

	/* INSIST((duid.data != NULL) && (duid.len > 0)); */

	ret_val = 0;
	memset(client_id, 0, sizeof(*client_id));
	memset(server_id, 0, sizeof(*server_id));

	switch (get_client_id(packet, client_id)) {
		case ISC_R_SUCCESS:
			break;
		case ISC_R_NOTFOUND:
			log_debug("Discarding %s from %s; "
				  "client identifier missing", 
				  dhcpv6_type_names[packet->dhcpv6_msg_type],
				  piaddr(packet->client_addr));
			goto exit;
		default:
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
	if ((server_duid.len != server_id->len) || 
	    (memcmp(server_duid.data, server_id->data, server_duid.len) != 0)) {
		log_debug("Discarding %s from %s; " 
			  "not our server identifier "
			  "(CLIENTID %s, SERVERID %s, server DUID %s)", 
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr),
			  print_hex_1(client_id->len, client_id->data, 60),
			  print_hex_2(server_id->len, server_id->data, 60),
			  print_hex_3(server_duid.len, server_duid.data, 60));
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
	struct data_string client_id;
	char client_id_str[80];	/* print_hex_1() uses maximum 60 characters,
				   plus a few more for extra information */

	ret_val = 0;
	memset(server_id, 0, sizeof(*server_id));

	/*
	 * Make a string that we can print out to give more 
	 * information about the client if we need to.
	 *
	 * By RFC 3315, Section 18.1.5 clients SHOULD have a 
	 * client-id on an Information-request packet, but it 
	 * is not strictly necessary.
	 */
	if (get_client_id(packet, &client_id) == ISC_R_SUCCESS) {
		snprintf(client_id_str, sizeof(client_id_str), " (CLIENTID %s)",
			 print_hex_1(client_id.len, client_id.data, 60));
		data_string_forget(&client_id, MDL);
	} else {
		client_id_str[0] = '\0';
	}

	/*
	 * Required by RFC 3315, section 15.
	 */
	if (packet->unicast) {
		log_debug("Discarding %s from %s; packet sent unicast%s",
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr), client_id_str);
		goto exit;
	}

	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_NA);
	if (oc != NULL) {
		log_debug("Discarding %s from %s; "
			  "IA_NA option present%s", 
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr), client_id_str);
		goto exit;
	}
	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_TA);
	if (oc != NULL) {
		log_debug("Discarding %s from %s; "
			  "IA_TA option present%s", 
			  dhcpv6_type_names[packet->dhcpv6_msg_type],
			  piaddr(packet->client_addr), client_id_str);
		goto exit;
	}

	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_SERVERID);
	if (oc != NULL) {
		if (!evaluate_option_cache(server_id, packet, NULL, NULL, 
					   packet->options, NULL,
					   &global_scope, oc, MDL)) {
			log_error("Error processing %s from %s; "
				  "unable to evaluate Server Identifier%s",
				  dhcpv6_type_names[packet->dhcpv6_msg_type],
				  piaddr(packet->client_addr), client_id_str);
			goto exit;
		}
		if ((server_duid.len != server_id->len) || 
		    (memcmp(server_duid.data, server_id->data, 
		    	    server_duid.len) != 0)) {
			log_debug("Discarding %s from %s; " 
				  "not our server identifier "
				  "(SERVERID %s, server DUID %s)%s", 
				  dhcpv6_type_names[packet->dhcpv6_msg_type],
				  piaddr(packet->client_addr),
				  print_hex_1(server_id->len, 
				  	      server_id->data, 60),
				  print_hex_2(server_duid.len, 
				  	      server_duid.data, 60),
				  client_id_str);
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
	D6O_PREFERENCE,
	0
};
static const int required_opts_solicit[] = {
	D6O_CLIENTID,
	D6O_SERVERID,
	D6O_IA_NA,
	D6O_IA_TA,
	D6O_RAPID_COMMIT,
	D6O_STATUS_CODE,
	D6O_VENDOR_OPTS,
	D6O_RECONF_ACCEPT,
	D6O_PREFERENCE,
	0
};
static const int required_opts_IA_NA[] = {
	D6O_IAADDR,
	D6O_STATUS_CODE,
	D6O_VENDOR_OPTS,
	0
};
static const int required_opts_STATUS_CODE[] = {
	D6O_STATUS_CODE,
	0
};

/*
 * Extracts from packet contents an IA_* option, storing the IA structure
 * in its entirety in enc_opt_data, and storing any decoded DHCPv6 options
 * in enc_opt_state for later lookup and evaluation.  The 'offset' indicates
 * where in the IA_* the DHCPv6 options commence.
 */
static int
get_encapsulated_IA_state(struct option_state **enc_opt_state, 
			  struct data_string *enc_opt_data,
			  struct packet *packet,
			  struct option_cache *oc,
			  int offset)
{
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
	if (enc_opt_data->len < offset) {
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
				 enc_opt_data->data + offset, 
				 enc_opt_data->len - offset,
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
		struct option_state *opt_state)
{
	struct data_string d;
	int ret_val;

	memset(&d, 0, sizeof(d));
	d.len = sizeof(status_code) + strlen(status_message);
	if (!buffer_allocate(&d.buffer, d.len, MDL)) {
		log_fatal("set_status_code: no memory for status code.");
	}
	d.data = d.buffer->data;
	putUShort(d.buffer->data, status_code);
	memcpy(d.buffer->data + sizeof(status_code), 
	       status_message, d.len - sizeof(status_code));
	if (!save_option_buffer(&dhcpv6_universe, opt_state, 
				d.buffer, (unsigned char *)d.data, d.len, 
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
	    struct dhcpv6_packet *reply)
{
	struct option_cache *oc;
	const unsigned char *server_id_data;
	int server_id_len;

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
	 * A small bit of special handling for Solicit messages.
	 *
	 * We could move the logic into a flag, but for now just check
	 * explicitly.
	 */
	if (packet->dhcpv6_msg_type == DHCPV6_SOLICIT) {
		reply->msg_type = DHCPV6_ADVERTISE;

		/*
		 * If:
		 * - this message type supports rapid commit (Solicit), and
		 * - the server is configured to supply a rapid commit, and
		 * - the client requests a rapid commit,
		 * Then we add a rapid commit option, and send Reply (instead
		 * of an Advertise).
		 */
		oc = lookup_option(&dhcpv6_universe,
				   *opt_state, D6O_RAPID_COMMIT);
		if (oc != NULL) {
			oc = lookup_option(&dhcpv6_universe,
					   packet->options, D6O_RAPID_COMMIT);
			if (oc != NULL) {
				if (!save_option_buffer(&dhcpv6_universe,
							*opt_state, NULL,
							(unsigned char *)"", 0,
							D6O_RAPID_COMMIT, 0)) {
					log_error("start_reply: error saving "
						  "RAPID_COMMIT option.");
					return 0;
				}

				reply->msg_type = DHCPV6_REPLY;
			}
		}
	} else
		reply->msg_type = DHCPV6_REPLY;

	/* 
	 * Use the client's transaction identifier for the reply.
	 */
	memcpy(reply->transaction_id, packet->dhcpv6_transaction_id, 
	       sizeof(reply->transaction_id));

	/* 
	 * RFC 3315, section 18.2 says we need server identifier and
	 * client identifier.
	 *
	 * If the server ID is defined via the configuration file, then
	 * it will already be present in the option state at this point, 
	 * so we don't need to set it.
	 *
	 * If we have a server ID passed in from the caller, 
	 * use that, otherwise use the global DUID.
	 */
	oc = lookup_option(&dhcpv6_universe, *opt_state, D6O_SERVERID);
	if (oc == NULL) {
		if (server_id == NULL) {
			server_id_data = server_duid.data;
			server_id_len = server_duid.len;
		} else {
			server_id_data = server_id->data;
			server_id_len = server_id->len;
		}
		if (!save_option_buffer(&dhcpv6_universe, *opt_state, 
					NULL, (unsigned char *)server_id_data,
					server_id_len, D6O_SERVERID, 0)) {
				log_error("start_reply: "
					  "error saving server identifier.");
				return 0;
		}
	}

	if (client_id->buffer != NULL) {
		if (!save_option_buffer(&dhcpv6_universe, *opt_state, 
					client_id->buffer, 
					(unsigned char *)client_id->data, 
					client_id->len, 
					D6O_CLIENTID, 0)) {
			log_error("start_reply: error saving "
				  "client identifier.");
			return 0;
		}
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
					NULL, (unsigned char *)"", 0, 
					D6O_RECONF_ACCEPT, 0)) {
			log_error("start_reply: "
				  "error saving RECONF_ACCEPT option.");
			option_state_dereference(opt_state, MDL);
			return 0;
		}
	}

	return 1;
}

/*
 * Try to get the IPv6 address the client asked for from the
 * pool.
 *
 * addr is the result (should be a pointer to NULL on entry)
 * pool is the pool to search in
 * requested_addr is the address the client wants
 */
static isc_result_t
try_client_v6_address(struct iaaddr **addr,
		      struct ipv6_pool *pool,
		      const struct data_string *requested_addr)
{
	struct in6_addr tmp_addr;
	isc_result_t result;

	if (requested_addr->len < sizeof(tmp_addr)) {
		return ISC_R_INVALIDARG;
	}
	memcpy(&tmp_addr, requested_addr->data, sizeof(tmp_addr));
	if (IN6_IS_ADDR_UNSPECIFIED(&tmp_addr)) {
		return ISC_R_FAILURE;
	}

	if (!ipv6_addr_in_pool(&tmp_addr, pool)) {
		return ISC_R_FAILURE;
	}

	if (lease6_exists(pool, &tmp_addr)) {
		return ISC_R_ADDRINUSE;
	}

	result = iaaddr_allocate(addr, MDL);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	(*addr)->addr = tmp_addr;

	result = add_lease6(pool, *addr, 0);
	if (result != ISC_R_SUCCESS) {
		iaaddr_dereference(addr, MDL);
	}
	return result;
}

/*
 * Get an IPv6 address for the client.
 *
 * addr is the result (should be a pointer to NULL on entry)
 * packet is the information about the packet from the client
 * requested_iaaddr is a hint from the client
 * client_id is the DUID for the client
 */
static isc_result_t 
pick_v6_address(struct iaaddr **addr, struct shared_network *shared_network,
		const struct data_string *client_id)
{
	struct ipv6_pool *p;
	int i;
	int start_pool;
	unsigned int attempts;
	char tmp_buf[INET6_ADDRSTRLEN];

	/*
	 * No pools, we're done.
	 */
	if (shared_network->ipv6_pools == NULL) {
		log_debug("Unable to pick client address: "
			  "no IPv6 pools on this shared network");
		return ISC_R_NORESOURCES;
	}

	/*
	 * Otherwise try to get a lease from the first subnet possible.
	 *
	 * We start looking at the last pool we allocated from, unless
	 * it had a collision trying to allocate an address. This will
	 * tend to move us into less-filled pools.
	 */
	start_pool = shared_network->last_ipv6_pool;
	i = start_pool;
	do {

		p = shared_network->ipv6_pools[i];
		if (activate_lease6(p, addr, &attempts, 
				    client_id, 0) == ISC_R_SUCCESS) {
			/*
			 * Record the pool used (or next one if there 
			 * was a collision).
			 */
			if (attempts > 1) {
				i++;
				if (shared_network->ipv6_pools[i] == NULL) {
					i = 0;
				}
			}
			shared_network->last_ipv6_pool = i;

			log_debug("Picking pool address %s",
				  inet_ntop(AF_INET6, &((*addr)->addr),
				  	    tmp_buf, sizeof(tmp_buf)));
			return ISC_R_SUCCESS;
		}

		i++;
		if (shared_network->ipv6_pools[i] == NULL) {
			i = 0;
		}
	} while (i != start_pool);

	/*
	 * If we failed to pick an IPv6 address from any of the subnets.
	 * Presumably that means we have no addresses for the client.
	 */
	log_debug("Unable to pick client address: no addresses available");
	return ISC_R_NORESOURCES;
}

/*
 * lease_to_client() is called from several messages to construct a
 * reply that contains all that we know about the client's correct lease
 * (or projected lease).
 *
 * Solicit - "Soft" binding, ignore unknown addresses or bindings, just
 *	     send what we "may" give them on a request.
 *
 * Request - "Hard" binding, but ignore supplied addresses (just provide what
 *	     the client should really use).
 *
 * Renew   - "Hard" binding, but client-supplied addresses are 'real'.  Error
 * Rebind    out any "wrong" addresses the client sends.  This means we send
 *	     an empty IA_NA with a status code of NoBinding or NotOnLink or
 *	     possibly send the address with zeroed lifetimes.
 *
 * Information-Request - No binding.
 *
 * The basic structure is to traverse the client-supplied data first, and
 * validate and echo back any contents that can be.  If the client-supplied
 * data does not error out (on renew/rebind as above), but we did not send
 * any addresses, attempt to allocate one.
 */
/* TODO: look at client hints for lease times */
static void
lease_to_client(struct data_string *reply_ret,
		struct packet *packet, 
		const struct data_string *client_id,
		const struct data_string *server_id)
{
	static struct reply_state reply;
	struct option_cache *oc;
	struct data_string packet_oro;
	isc_boolean_t no_addrs_avail;

	/* Locate the client.  */
	if (shared_network_from_packet6(&reply.shared,
					packet) != ISC_R_SUCCESS)
		goto exit;

	/* 
	 * Initialize the reply.
	 */
	packet_reference(&reply.packet, packet, MDL);
	data_string_copy(&reply.client_id, client_id, MDL);

	if (!start_reply(packet, client_id, server_id, &reply.opt_state,
			 &reply.buf.reply))
		goto exit;

	/* Set the write cursor to just past the reply header. */
	reply.cursor = REPLY_OPTIONS_INDEX;

	/*
	 * Get the ORO from the packet, if any.
	 */
	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_ORO);
	memset(&packet_oro, 0, sizeof(packet_oro));
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
	 * Find a host record that matches from the packet, if any, and is
	 * valid for the shared network the client is on.
	 */
	if (find_hosts_by_option(&reply.host, packet, packet->options, MDL)) {
		seek_shared_host(&reply.host, reply.shared);
	}

	if ((reply.host == NULL) &&
	    find_hosts_by_uid(&reply.host, client_id->data, client_id->len,
			      MDL)) {
		seek_shared_host(&reply.host, reply.shared);
	}

	/* Process the client supplied IA_NA's onto the reply buffer. */
	reply.ia_count = 0;
	oc = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_NA);
	no_addrs_avail = ISC_FALSE;
	for (; oc != NULL ; oc = oc->next) {
		isc_result_t status;

		/* Start counting addresses offered. */
		reply.client_addresses = 0;
		reply.ia_addrs_included = ISC_FALSE;

		status = reply_process_ia(&reply, oc);

		/*
		 * We continue to try other IA's whether we can address
		 * this one or not.  Any other result is an immediate fail.
		 */
		if ((status != ISC_R_SUCCESS) &&
		    (status != ISC_R_NORESOURCES))
			goto exit;

		/*
		 * If any address can be given to any IA, then do not set the
		 * NoAddrsAvail status code.
		 */
		if (reply.client_addresses == 0)
			no_addrs_avail = ISC_TRUE;
	}

	/*
	 * Make no reply if we gave no resources and is not
	 * for Information-Request.
	 */
	if ((reply.ia_count == 0) &&
	    (packet->dhcpv6_msg_type != DHCPV6_INFORMATION_REQUEST))
	        goto exit;

	/*
	 * RFC3315 section 17.2.2 (Solicit):
	 *
	 * If the server will not assign any addresses to any IAs in a
	 * subsequent Request from the client, the server MUST send an
	 * Advertise message to the client that includes only a Status
	 * Code option with code NoAddrsAvail and a status message for
	 * the user, a Server Identifier option with the server's DUID,
	 * and a Client Identifier option with the client's DUID.
	 *
	 * Section 18.2.1 (Request):
	 *
	 * If the server cannot assign any addresses to an IA in the
	 * message from the client, the server MUST include the IA in
	 * the Reply message with no addresses in the IA and a Status
	 * Code option in the IA containing status code NoAddrsAvail.
	 *
	 * Section 18.2.3 (Renew):
	 *
	 * The server may choose to change the list of addresses and
	 * the lifetimes of addresses in IAs that are returned to the
	 * client.
	 *
	 * Section 18.2.4 (Rebind):
	 *
	 * Absolutely nothing.
	 *
	 * INTERPRETATION;
	 *
	 * Solicit and Request are fairly explicit; we send NoAddrsAvail.
	 * We handle SOLICIT here and REQUEST in the reply_process_ia()
	 * function (because SOLICIT only counts if we never get around to
	 * it).
	 *
	 * Renew and Rebind are totally undefined.  If we send a reply with
	 * empty IA's, however, the client will stop renewing or rebinding,
	 * and this is a problem if they could have gotten addressed from
	 * another server.  So we ignore client packets...they will eventually
	 * time out in the worst case.
	 */
	if (no_addrs_avail &&
	    (reply.packet->dhcpv6_msg_type == DHCPV6_SOLICIT))
	{
		/* Set the NoAddrsAvail status code. */
		if (!set_status_code(STATUS_NoAddrsAvail,
				     "No addresses available for this "
				     "interface.", reply.opt_state)) {
			log_error("lease_to_client: Unable to set "
				  "NoAddrsAvail status code.");
			goto exit;
		}

		/* Rewind the cursor to the start. */
		reply.cursor = REPLY_OPTIONS_INDEX;

		/*
		 * Produce a reply that includes;
		 *
		 * Status code.
		 * Server DUID.
		 * Client DUID.
		 */
		reply.cursor += store_options6((char *)reply.buf.data +
							reply.cursor,
					       sizeof(reply.buf) -
					       		reply.cursor,
					       reply.opt_state, reply.packet,
					       required_opts,
					       NULL);
	} else if (no_addrs_avail &&
		   (reply.packet->dhcpv6_msg_type != DHCPV6_REQUEST))
	{
		goto exit;
	} else {
		/*
		 * Having stored the client's IA_NA's, store any options that
		 * will fit in the remaining space.
		 */
		reply.cursor += store_options6((char *)reply.buf.data +
							reply.cursor,
					       sizeof(reply.buf) -
							reply.cursor,
					       reply.opt_state, reply.packet,
					       required_opts_solicit,
					       &packet_oro);
	}

	/* Return our reply to the caller. */
	reply_ret->len = reply.cursor;
	reply_ret->buffer = NULL;
	if (!buffer_allocate(&reply_ret->buffer, reply.cursor, MDL)) {
		log_fatal("No memory to store Reply.");
	}
	memcpy(reply_ret->buffer->data, reply.buf.data, reply.cursor);
	reply_ret->data = reply_ret->buffer->data;

      exit:
	/* Cleanup. */
	if (reply.shared != NULL)
		shared_network_dereference(&reply.shared, MDL);
	if (reply.host != NULL)
		host_dereference(&reply.host, MDL);
	if (reply.opt_state != NULL)
		option_state_dereference(&reply.opt_state, MDL);
	if (reply.packet != NULL)
		packet_dereference(&reply.packet, MDL);
	if (reply.client_id.data != NULL)
		data_string_forget(&reply.client_id, MDL);
	reply.renew = reply.rebind = reply.prefer = reply.valid = 0;
	reply.cursor = 0;
}

/* Process a client-supplied IA_NA.  This may append options to the tail of
 * the reply packet being built in the reply_state structure.
 */
static isc_result_t
reply_process_ia(struct reply_state *reply, struct option_cache *ia) {
	isc_result_t status = ISC_R_SUCCESS;
	u_int32_t iaid;
	unsigned ia_cursor;
	struct option_state *packet_ia;
	struct option_cache *oc;
	struct data_string ia_data, data;
	isc_boolean_t lease_in_database;

	/* Initialize values that will get cleaned up on return. */
	packet_ia = NULL;
	memset(&ia_data, 0, sizeof(ia_data));
	memset(&data, 0, sizeof(data));
	lease_in_database = ISC_FALSE;
	/* 
	 * Note that find_client_address() may set reply->lease. 
	 */

	/* Make sure there is at least room for the header. */
	if ((reply->cursor + IA_NA_OFFSET + 4) > sizeof(reply->buf)) {
		log_error("reply_process_ia: Reply too long for IA.");
		return ISC_R_NOSPACE;
	}


	/* Fetch the IA_NA contents. */
	if (!get_encapsulated_IA_state(&packet_ia, &ia_data, reply->packet,
				       ia, IA_NA_OFFSET)) {
		log_error("reply_process_ia: error evaluating ia_na");
		status = ISC_R_FAILURE;
		goto cleanup;
	}

	/* Extract IA_NA header contents. */
	iaid = getULong(ia_data.data);
	reply->renew = getULong(ia_data.data + 4);
	reply->rebind = getULong(ia_data.data + 8);

	/* Create an IA_NA structure. */
	if (ia_na_allocate(&reply->ia_na, iaid, (char *)reply->client_id.data, 
			   reply->client_id.len, MDL) != ISC_R_SUCCESS) {
		log_error("lease_to_client: no memory for ia_na.");
		status = ISC_R_NOMEMORY;
		goto cleanup;
	}

	/* Cache pre-existing IA, if any. */
	ia_na_hash_lookup(&reply->old_ia, ia_active,
			  (unsigned char *)reply->ia_na->iaid_duid.data,
			  reply->ia_na->iaid_duid.len, MDL);

	/*
	 * Create an option cache to carry the IA_NA option contents, and
	 * execute any user-supplied values into it.
	 */
	if (!option_state_allocate(&reply->reply_ia, MDL)) {
		status = ISC_R_NOMEMORY;
		goto cleanup;
	}

	/* Check & cache the fixed host record. */
	if ((reply->host != NULL) && (reply->host->fixed_addr != NULL)) {
		if (!evaluate_option_cache(&reply->fixed, NULL, NULL, NULL,
					   NULL, NULL, &global_scope,
					   reply->host->fixed_addr, MDL)) {
			log_error("reply_process_ia: unable to evaluate "
				  "fixed address.");
			status = ISC_R_FAILURE;
			goto cleanup;
		}

		if (reply->fixed.len < 16) {
			log_error("reply_process_ia: invalid fixed address.");
			status = ISC_R_INVALIDARG;
			goto cleanup;
		}

		reply->static_lease = ISC_TRUE;
	} else
		reply->static_lease = ISC_FALSE;

	/*
	 * Save the cursor position at the start of the IA, so we can
	 * set length and adjust t1/t2 values later.  We write a temporary
	 * header out now just in case we decide to adjust the packet
	 * within sub-process functions.
	 */
	ia_cursor = reply->cursor;

	/* Initialize the IA_NA header.  First the code. */
	putUShort(reply->buf.data + reply->cursor, (unsigned)D6O_IA_NA);
	reply->cursor += 2;

	/* Then option length. */
	putUShort(reply->buf.data + reply->cursor, 0x0Cu);
	reply->cursor += 2;

	/* Then IA_NA header contents; IAID. */
	putULong(reply->buf.data + reply->cursor, iaid);
	reply->cursor += 4;

	/* We store the client's t1 for now, and may over-ride it later. */
	putULong(reply->buf.data + reply->cursor, reply->renew);
	reply->cursor += 4;

	/* We store the client's t2 for now, and may over-ride it later. */
	putULong(reply->buf.data + reply->cursor, reply->rebind);
	reply->cursor += 4;

	/* 
	 * For each address in this IA_NA, decide what to do about
	 * it.
	 */
	oc = lookup_option(&dhcpv6_universe, packet_ia, D6O_IAADDR);
	reply->valid = reply->prefer = 0xffffffff;
	reply->client_valid = reply->client_prefer = 0;
	for (; oc != NULL ; oc = oc->next) {
		status = reply_process_addr(reply, oc);

		/*
		 * Canceled means we did not allocate addresses to the
		 * client, but we're "done" with this IA - we set a status
		 * code.  So transmit this reply, e.g., move on to the next
		 * IA.
		 */
		if (status == ISC_R_CANCELED)
			break;

		if ((status != ISC_R_SUCCESS) && (status != ISC_R_ADDRINUSE))
			goto cleanup;
	}

	reply->ia_count++;

	/*
	 * If we fell through the above and never gave the client
	 * an address, give it one now.
	 */
	if ((status != ISC_R_CANCELED) && (reply->client_addresses == 0)) {
		status = find_client_address(reply);

		if (status == ISC_R_NORESOURCES) {
			switch (reply->packet->dhcpv6_msg_type) {
			      case DHCPV6_SOLICIT:
				/*
				 * Solicit is handled by the caller, because
				 * it has to be the sum of all the IA's.
				 */
				goto cleanup;

			      case DHCPV6_REQUEST:
				/* Section 18.2.1 (Request):
				 *
				 * If the server cannot assign any addresses to
				 * an IA in the message from the client, the
				 * server MUST include the IA in the Reply
				 * message with no addresses in the IA and a
				 * Status Code option in the IA containing
				 * status code NoAddrsAvail.
				 */
				option_state_dereference(&reply->reply_ia, MDL);
				if (!option_state_allocate(&reply->reply_ia,
							   MDL))
				{
					log_error("reply_process_ia: No "
						  "memory for option state "
						  "wipe.");
					status = ISC_R_NOMEMORY;
					goto cleanup;
				}

				if (!set_status_code(STATUS_NoAddrsAvail,
						     "No addresses available "
						     "for this interface.",
						      reply->reply_ia)) {
					log_error("reply_process_ia: Unable "
						  "to set NoAddrsAvail status "
						  "code.");
					status = ISC_R_FAILURE;
					goto cleanup;
				}

				status = ISC_R_SUCCESS;
				break;

			      default:
				/*
				 * RFC 3315 does not tell us to emit a status
				 * code in this condition, or anything else.
				 *
				 * If we included non-allocated addresses
				 * (zeroed lifetimes) in an IA, then the client
				 * will deconfigure them.
				 *
				 * So we want to include the IA even if we
				 * can't give it a new address if it includes
				 * zeroed lifetime addresses.
				 *
				 * We don't want to include the IA if we
				 * provide zero addresses including zeroed
				 * lifetimes...if we did, the client would
				 * reset its renew/rebind behaviour.  If we do
				 * not, the client may get a success off
				 * another server.
				 */
				if (reply->ia_addrs_included)
					status = ISC_R_SUCCESS;
				else
					goto cleanup;
				break;
			}
		}

		if (status != ISC_R_SUCCESS)
			goto cleanup;
	}

	reply->cursor += store_options6((char *)reply->buf.data + reply->cursor,
					sizeof(reply->buf) - reply->cursor,
					reply->reply_ia, reply->packet,
					required_opts_IA_NA, NULL);

	/* Reset the length of this IA to match what was just written. */
	putUShort(reply->buf.data + ia_cursor + 2,
		  reply->cursor - (ia_cursor + 4));

	/*
	 * T1/T2 time selection is kind of weird.  We actually use DHCP
	 * (v4) scoped options as handy existing places where these might
	 * be configured by an administrator.  A value of zero tells the
	 * client it may choose its own renewal time.
	 */
	reply->renew = 0;
	oc = lookup_option(&dhcp_universe, reply->opt_state,
			   DHO_DHCP_RENEWAL_TIME);
	if (oc != NULL) {
		if (!evaluate_option_cache(&data, reply->packet, NULL, NULL,
					   reply->packet->options,
					   reply->opt_state, &global_scope,
					   oc, MDL) ||
		    (data.len != 4)) {
			log_error("Invalid renewal time.");
		} else {
			reply->renew = getULong(data.data);
		}

		if (data.data != NULL)
			data_string_forget(&data, MDL);
	}
	putULong(reply->buf.data + ia_cursor + 8, reply->renew);

	/* Now T2. */
	reply->rebind = 0;
	oc = lookup_option(&dhcp_universe, reply->opt_state,
			   DHO_DHCP_REBINDING_TIME);
	if (oc != NULL) {
		if (!evaluate_option_cache(&data, reply->packet, NULL, NULL,
					   reply->packet->options,
					   reply->opt_state, &global_scope,
					   oc, MDL) ||
		    (data.len != 4)) {
			log_error("Invalid rebinding time.");
		} else {
			reply->rebind = getULong(data.data);
		}

		if (data.data != NULL)
			data_string_forget(&data, MDL);
	}
	putULong(reply->buf.data + ia_cursor + 12, reply->rebind);

	/*
	 * If this is not a 'soft' binding, consume the new changes into
	 * the database (if any have been attached to the ia_na).
	 *
	 * Loop through the assigned dynamic addresses, referencing the
	 * leases onto this IA_NA rather than any old ones, and updating
	 * pool timers for each (if any).
	 */
	if ((status != ISC_R_CANCELED) && !reply->static_lease &&
	    (reply->buf.reply.msg_type == DHCPV6_REPLY) &&
	    (reply->ia_na->num_iaaddr != 0)) {
		struct iaaddr *tmp;
		struct data_string *ia_id;
		int i;

		for (i = 0 ; i < reply->ia_na->num_iaaddr ; i++) {
			tmp = reply->ia_na->iaaddr[i];

			if (tmp->ia_na != NULL)
				ia_na_dereference(&tmp->ia_na, MDL);
			ia_na_reference(&tmp->ia_na, reply->ia_na, MDL);

			schedule_lease_timeout(tmp->ipv6_pool);

			/*
			 * If this constitutes a 'hard' binding, perform ddns
			 * updates.
			 */
			oc = lookup_option(&server_universe, reply->opt_state,
					   SV_DDNS_UPDATES);
			if ((oc == NULL) ||
			    evaluate_boolean_option_cache(NULL, reply->packet,
							  NULL, NULL,
							reply->packet->options,
							  reply->opt_state,
							  &tmp->scope,
							  oc, MDL)) {
				ddns_updates(reply->packet, NULL, NULL,
					     tmp, NULL, reply->opt_state);
			}
		}

		/* Remove any old ia_na from the hash. */
		if (reply->old_ia != NULL) {
			ia_id = &reply->old_ia->iaid_duid;
			ia_na_hash_delete(ia_active,
					  (unsigned char *)ia_id->data,
					  ia_id->len, MDL);
			ia_na_dereference(&reply->old_ia, MDL);
		}

		/* Put new ia_na into the hash. */
		ia_id = &reply->ia_na->iaid_duid;
		ia_na_hash_add(ia_active, (unsigned char *)ia_id->data,
			       ia_id->len, reply->ia_na, MDL);

		write_ia_na(reply->ia_na);

		/* 
		 * Note that we wrote the lease into the database,
		 * so that we know not to release it when we're done
		 * with this function.
		 */
		lease_in_database = ISC_TRUE;

	/*
	 * If this is a soft binding, we will check to see if we are 
	 * suggesting the existing database entry to the client.
	 */
	} else if ((status != ISC_R_CANCELED) && !reply->static_lease &&
	    (reply->old_ia != NULL)) {
	    	if (ia_na_equal(reply->old_ia, reply->ia_na)) {
			lease_in_database = ISC_TRUE;
		}
	}

      cleanup:
	if (packet_ia != NULL)
		option_state_dereference(&packet_ia, MDL);
	if (reply->reply_ia != NULL)
		option_state_dereference(&reply->reply_ia, MDL);
	if (ia_data.data != NULL)
		data_string_forget(&ia_data, MDL);
	if (data.data != NULL)
		data_string_forget(&data, MDL);
	if (reply->ia_na != NULL)
		ia_na_dereference(&reply->ia_na, MDL);
	if (reply->old_ia != NULL)
		ia_na_dereference(&reply->old_ia, MDL);
	if (reply->lease != NULL) {
		if (!lease_in_database) {
			release_lease6(reply->lease->ipv6_pool, reply->lease);
		}
		iaaddr_dereference(&reply->lease, MDL);
	}
	if (reply->fixed.data != NULL)
		data_string_forget(&reply->fixed, MDL);

	/*
	 * ISC_R_CANCELED is a status code used by the addr processing to
	 * indicate we're replying with a status code.  This is still a
	 * success at higher layers.
	 */
	return((status == ISC_R_CANCELED) ? ISC_R_SUCCESS : status);
}

/*
 * Process an IAADDR within a given IA_NA, storing any IAADDR reply contents
 * into the reply's current ia-scoped option cache.  Returns ISC_R_CANCELED
 * in the event we are replying with a status code and do not wish to process
 * more IAADDRs within this IA.
 */
static isc_result_t
reply_process_addr(struct reply_state *reply, struct option_cache *addr) {
	u_int32_t pref_life, valid_life;
	struct binding_scope **scope;
	struct group *group;
	struct subnet *subnet;
	struct iaddr tmp_addr;
	struct option_cache *oc;
	struct data_string iaaddr, data;
	isc_result_t status = ISC_R_SUCCESS;

	/* Initializes values that will be cleaned up. */
	memset(&iaaddr, 0, sizeof(iaaddr));
	memset(&data, 0, sizeof(data));
	/* Note that reply->lease may be set by address_is_owned() */

	/*
	 * There is no point trying to process an incoming address if there
	 * is no room for an outgoing address.
	 */
	if ((reply->cursor + 28) > sizeof(reply->buf)) {
		log_error("reply_process_addr: Out of room for address.");
		return ISC_R_NOSPACE;
	}

	/* Extract this IAADDR option. */
	if (!evaluate_option_cache(&iaaddr, reply->packet, NULL, NULL, 
				   reply->packet->options, NULL, &global_scope,
				   addr, MDL) ||
	    (iaaddr.len < IAADDR_OFFSET)) {
		log_error("reply_process_addr: error evaluating IAADDR.");
		status = ISC_R_FAILURE;
		goto cleanup;
	}

	/* The first 16 bytes are the IPv6 address. */
	pref_life = getULong(iaaddr.data + 16);
	valid_life = getULong(iaaddr.data + 20);

	if ((reply->client_valid == 0) ||
	    (reply->client_valid > valid_life))
		reply->client_valid = valid_life;

	if ((reply->client_prefer == 0) ||
	    (reply->client_prefer > pref_life))
		reply->client_prefer = pref_life;

	/* 
	 * Clients may choose to send :: as an address, with the idea to give
	 * hints about preferred-lifetime or valid-lifetime.
	 */
	tmp_addr.len = 16;
	memset(tmp_addr.iabuf, 0, 16);
	if (!memcmp(iaaddr.data, tmp_addr.iabuf, 16)) {
		/* Status remains success; we just ignore this one. */
		goto cleanup;
	}

	/* tmp_addr len remains 16 */
	memcpy(tmp_addr.iabuf, iaaddr.data, 16);

	/*
	 * Verify that this address is on the client's network.
	 */
	for (subnet = reply->shared->subnets ; subnet != NULL ;
	     subnet = subnet->next_sibling) {
		if (addr_eq(subnet_number(tmp_addr, subnet->netmask),
			    subnet->net))
			break;
	}

	/* Address not found on shared network. */
	if (subnet == NULL) {
		/* Ignore this address on 'soft' bindings. */
		if (reply->packet->dhcpv6_msg_type == DHCPV6_SOLICIT)
			/* status remains success */
			goto cleanup;

		/*
		 * RFC3315 section 18.2.1:
		 *
		 * If the server finds that the prefix on one or more IP
		 * addresses in any IA in the message from the client is not
		 * appropriate for the link to which the client is connected,
		 * the server MUST return the IA to the client with a Status
		 * Code option with the value NotOnLink.
		 */
		if (reply->packet->dhcpv6_msg_type == DHCPV6_REQUEST) {
			/* Rewind the IA_NA to empty. */
			option_state_dereference(&reply->reply_ia, MDL);
			if (!option_state_allocate(&reply->reply_ia, MDL)) {
				log_error("reply_process_addr: No memory for "
					  "option state wipe.");
				status = ISC_R_NOMEMORY;
				goto cleanup;
			}

			/* Append a NotOnLink status code. */
			if (!set_status_code(STATUS_NotOnLink,
					     "Address not for use on this "
					     "link.", reply->reply_ia)) {
				log_error("reply_process_addr: Failure "
					  "setting status code.");
				status = ISC_R_FAILURE;
				goto cleanup;
			}

			/* Fin (no more IAADDRs). */
			status = ISC_R_CANCELED;
			goto cleanup;
		}

		/*
		 * RFC3315 sections 18.2.3 and 18.2.4 have identical language:
		 *
		 * If the server finds that any of the addresses are not
		 * appropriate for the link to which the client is attached,
		 * the server returns the address to the client with lifetimes
		 * of 0.
		 */
		if ((reply->packet->dhcpv6_msg_type != DHCPV6_RENEW) &&
		    (reply->packet->dhcpv6_msg_type != DHCPV6_REBIND)) {
			log_error("It is impossible to lease a client that is "
				  "not sending a solict, request, renew, or "
				  "rebind.");
			status = ISC_R_FAILURE;
			goto cleanup;
		}

		reply->send_prefer = reply->send_valid = 0;
		goto send_addr;
	}

	/* Verify the address belongs to the client. */
	if (!address_is_owned(reply, &tmp_addr)) {
		/*
		 * For solicit and request, any addresses included are
		 * 'requested' addresses.  For rebind, we actually have
		 * no direction on what to do from 3315 section 18.2.4!
		 * So I think the best bet is to try and give it out, and if
		 * we can't, zero lifetimes.
		 */
		if ((reply->packet->dhcpv6_msg_type == DHCPV6_SOLICIT) ||
		    (reply->packet->dhcpv6_msg_type == DHCPV6_REQUEST) ||
		    (reply->packet->dhcpv6_msg_type == DHCPV6_REBIND)) {
			status = reply_process_try_addr(reply, &tmp_addr);

			/* Either error out or skip this address. */
			if ((status != ISC_R_SUCCESS) && 
			    (status != ISC_R_ADDRINUSE)) 
				goto cleanup;

			if (reply->lease == NULL) {
				if (reply->packet->dhcpv6_msg_type ==
							DHCPV6_REBIND) {
					reply->send_prefer = 0;
					reply->send_valid = 0;
					goto send_addr;
				}

				/* status remains success - ignore */
				goto cleanup;
			}
		/*
		 * RFC3315 section 18.2.3:
		 *
		 * If the server cannot find a client entry for the IA the
		 * server returns the IA containing no addresses with a Status
		 * Code option set to NoBinding in the Reply message.
		 */
		} else if (reply->packet->dhcpv6_msg_type == DHCPV6_RENEW) {
			/* Rewind the IA_NA to empty. */
			option_state_dereference(&reply->reply_ia, MDL);
			if (!option_state_allocate(&reply->reply_ia, MDL)) {
				log_error("reply_process_addr: No memory for "
					  "option state wipe.");
				status = ISC_R_NOMEMORY;
				goto cleanup;
			}

			/* Append a NoBinding status code.  */
			if (!set_status_code(STATUS_NoBinding,
					     "Address not bound to this "
					     "interface.", reply->reply_ia)) {
				log_error("reply_process_addr: Unable to "
					  "attach status code.");
				status = ISC_R_FAILURE;
				goto cleanup;
			}

			/* Fin (no more IAADDRs). */
			status = ISC_R_CANCELED;
			goto cleanup;
		} else {
			log_error("It is impossible to lease a client that is "
				  "not sending a solicit, request, renew, or "
				  "rebind message.");
			status = ISC_R_FAILURE;
			goto cleanup;
		}
	}

	if (reply->static_lease) {
		if (reply->host == NULL)
			log_fatal("Impossible condition at %s:%d.", MDL);

		scope = &global_scope;
		group = reply->host->group;
	} else {
		if (reply->lease == NULL)
			log_fatal("Impossible condition at %s:%d.", MDL);

		scope = &reply->lease->scope;
		group = reply->shared->group;
	}

	/*
	 * If client_addresses is nonzero, then the reply_process_is_addressed
	 * function has executed configuration state into the reply option
	 * cache.  We will use that valid cache to derive configuration for
	 * whether or not to engage in additional addresses, and similar.
	 */
	if (reply->client_addresses != 0) {
		unsigned limit = 1;

		/*
		 * Does this client have "enough" addresses already?  Default
		 * to one.  Everybody gets one, and one should be enough for
		 * anybody.
		 */
		oc = lookup_option(&server_universe, reply->opt_state,
				   SV_LIMIT_ADDRS_PER_IA);
		if (oc != NULL) {
			if (!evaluate_option_cache(&data, reply->packet,
						   NULL, NULL,
						   reply->packet->options,
						   reply->opt_state,
						   scope, oc, MDL) ||
			    (data.len != 4)) {
				log_error("reply_process_ia: unable to "
					  "evaluate addrs-per-ia value.");
				status = ISC_R_FAILURE;
				goto cleanup;
			}

			limit = getULong(data.data);
			data_string_forget(&data, MDL);
		}

		/*
		 * If we wish to limit the client to a certain number of
		 * addresses, then omit the address from the reply.
		 */
		if (reply->client_addresses >= limit)
			goto cleanup;
	}

	status = reply_process_is_addressed(reply, scope, group);
	if (status != ISC_R_SUCCESS)
		goto cleanup;

      send_addr:
	status = reply_process_send_addr(reply, &tmp_addr);

      cleanup:
	if (iaaddr.data != NULL)
		data_string_forget(&iaaddr, MDL);
	if (data.data != NULL)
		data_string_forget(&data, MDL);
	if (reply->lease != NULL)
		iaaddr_dereference(&reply->lease, MDL);

	return status;
}

/*
 * Verify the address belongs to the client.  If we've got a host
 * record with a fixed address, it has to be the assigned address
 * (fault out all else).  Otherwise it's a dynamic address, so lookup
 * that address and make sure it belongs to this DUID:IAID pair.
 */
static isc_boolean_t
address_is_owned(struct reply_state *reply, struct iaddr *addr) {
	int i;

	/*
	 * This faults out addresses that don't match fixed addresses.
	 */
	if (reply->static_lease) {
		if (reply->fixed.data == NULL)
			log_fatal("Impossible condition at %s:%d.", MDL);

		if (memcmp(addr->iabuf, reply->fixed.data, 16) == 0)
			return ISC_TRUE;

		return ISC_FALSE;
	}

	if ((reply->old_ia == NULL) || (reply->old_ia->num_iaaddr == 0))
		return ISC_FALSE;

	for (i = 0 ; i < reply->old_ia->num_iaaddr ; i++) {
		struct iaaddr *tmp;

		tmp = reply->old_ia->iaaddr[i];

		if (memcmp(addr->iabuf, &tmp->addr, 16) == 0) {
			iaaddr_reference(&reply->lease, tmp, MDL);
			return ISC_TRUE;
		}
	}

	return ISC_FALSE;
}

/*
 * This function only returns failure on 'hard' failures.  If it succeeds,
 * it will leave a lease structure behind.
 */
static isc_result_t
reply_process_try_addr(struct reply_state *reply, struct iaddr *addr) {
	isc_result_t status = ISC_R_FAILURE;
	struct ipv6_pool *pool;
	int i;
	struct data_string data_addr;

	if ((reply == NULL) || (reply->shared == NULL) ||
	    (reply->shared->ipv6_pools == NULL) || (addr == NULL) ||
	    (reply->lease != NULL))
		return ISC_R_INVALIDARG;

	memset(&data_addr, 0, sizeof(data_addr));
	data_addr.len = addr->len;
	data_addr.data = addr->iabuf;

	for (i = 0 ; (pool = reply->shared->ipv6_pools[i]) != NULL ; i++) {
		status = try_client_v6_address(&reply->lease, pool,
					       &data_addr);
		if (status == ISC_R_SUCCESS)
			break;
	}

	/* Note that this is just pedantry.  There is no allocation to free. */
	data_string_forget(&data_addr, MDL);
	/* Return just the most recent status... */
	return status;
}

/* Look around for an address to give the client.  First, look through the
 * old IA for addresses we can extend.  Second, try to allocate a new address.
 * Finally, actually add that address into the current reply IA.
 */
static isc_result_t
find_client_address(struct reply_state *reply) {
	struct iaddr send_addr;
	isc_result_t status = ISC_R_NORESOURCES;
	struct iaaddr *lease, *best_lease = NULL;
	struct binding_scope **scope;
	struct group *group;
	int i;

	if (reply->host != NULL)
		group = reply->host->group;
	else
		group = reply->shared->group;

	if (reply->static_lease) {
		if (reply->host == NULL)
			return ISC_R_INVALIDARG;

		send_addr.len = 16;
		memcpy(send_addr.iabuf, reply->fixed.data, 16);

		status = ISC_R_SUCCESS;
		scope = &global_scope;
		goto send_addr;
	}

	if (reply->old_ia != NULL)  {
		for (i = 0 ; i < reply->old_ia->num_iaaddr ; i++) {
			lease = reply->old_ia->iaaddr[i];

			best_lease = lease_compare(lease, best_lease);
		}
	}

	/* Try to pick a new address if we didn't find one, or if we found an
	 * abandoned lease.
	 */
	if ((best_lease == NULL) || (best_lease->state == FTS_ABANDONED)) {
		status = pick_v6_address(&reply->lease, reply->shared,
					 &reply->client_id);
	} else if (best_lease != NULL) {
		iaaddr_reference(&reply->lease, best_lease, MDL);
		status = ISC_R_SUCCESS;
	}

	/* Pick the abandoned lease as a last resort. */
	if ((status == ISC_R_NORESOURCES) && (best_lease != NULL)) {
		/* I don't see how this is supposed to be done right now. */
		log_error("Reclaiming abandoned addresses is not yet "
			  "supported.  Treating this as an out of space "
			  "condition.");
		/* lease_reference(&reply->lease, best_lease, MDL); */
	}

	/* Give up now if we didn't find a lease. */
	if (status != ISC_R_SUCCESS)
		return status;

	if (reply->lease == NULL)
		log_fatal("Impossible condition at %s:%d.", MDL);

	scope = &reply->lease->scope;
	group = reply->shared->group;

	send_addr.len = 16;
	memcpy(send_addr.iabuf, &reply->lease->addr, 16);

      send_addr:
	status = reply_process_is_addressed(reply, scope, group);
	if (status != ISC_R_SUCCESS)
		return status;

	status = reply_process_send_addr(reply, &send_addr);
	return status;
}

/* Once an address is found for a client, perform several common functions;
 * Calculate and store valid and preferred lease times, draw client options
 * into the option state.
 */
static isc_result_t
reply_process_is_addressed(struct reply_state *reply,
			   struct binding_scope **scope, struct group *group)
{
	isc_result_t status = ISC_R_SUCCESS;
	struct data_string data;
	struct option_cache *oc;

	/* Initialize values we will cleanup. */
	memset(&data, 0, sizeof(data));

	/* Execute relevant options into root scope. */
	execute_statements_in_scope(NULL, reply->packet, NULL, NULL,
				    reply->packet->options, reply->opt_state,
				    scope, group, root_group);

	/* Determine valid lifetime. */
	if (reply->client_valid == 0)
		reply->send_valid = DEFAULT_DEFAULT_LEASE_TIME;
	else
		reply->send_valid = reply->client_valid;

	oc = lookup_option(&server_universe, reply->opt_state,
			   SV_DEFAULT_LEASE_TIME);
	if (oc != NULL) {
		if (!evaluate_option_cache(&data, reply->packet, NULL, NULL,
					   reply->packet->options,
					   reply->opt_state,
					   scope, oc, MDL) ||
		    (data.len != 4)) {
			log_error("reply_process_ia: unable to "
				  "evaluate default lease time");
			status = ISC_R_FAILURE;
			goto cleanup;
		}

		reply->send_valid = getULong(data.data);
		data_string_forget(&data, MDL);
	}

	if (reply->client_prefer == 0)
		reply->send_prefer = reply->send_valid;
	else
		reply->send_prefer = reply->client_prefer;

	if (reply->send_prefer >= reply->send_valid)
		reply->send_prefer = (reply->send_valid / 2) +
				     (reply->send_valid / 8);

	oc = lookup_option(&server_universe, reply->opt_state,
			   SV_PREFER_LIFETIME);
	if (oc != NULL) {
		if (!evaluate_option_cache(&data, reply->packet, NULL, NULL,
					   reply->packet->options,
					   reply->opt_state,
					   scope, oc, MDL) ||
		    (data.len != 4)) {
			log_error("reply_process_ia: unable to "
				  "evaluate preferred lease time");
			status = ISC_R_FAILURE;
			goto cleanup;
		}

		reply->send_prefer = getULong(data.data);
		data_string_forget(&data, MDL);
	}

	/* Note lowest values for later calculation of renew/rebind times. */
	if (reply->prefer > reply->send_prefer)
		reply->prefer = reply->send_prefer;

	if (reply->valid > reply->send_valid)
		reply->valid = reply->send_valid;

#if 0
	/*
	 * XXX: Old 4.0.0 alpha code would change the host {} record
	 * XXX: uid upon lease assignment.  This was intended to cover the
	 * XXX: case where a client first identifies itself using vendor
	 * XXX: options in a solicit, or request, but later neglects to include
	 * XXX: these options in a Renew or Rebind.  It is not clear that this
	 * XXX: is required, and has some startling ramifications (such as
	 * XXX: how to recover this dynamic host {} state across restarts).
	 */
	if (reply->host != NULL)
		change_host_uid(host, reply->client_id->data,
				reply->client_id->len);
#endif /* 0 */

	/* Perform dynamic lease related update work. */
	if (reply->lease != NULL) {
		/* Advance (or rewind) the valid lifetime. */
		reply->lease->valid_lifetime_end_time = cur_time +
							reply->send_valid;
		renew_lease6(reply->lease->ipv6_pool, reply->lease);

		status = ia_na_add_iaaddr(reply->ia_na, reply->lease, MDL);
		if (status != ISC_R_SUCCESS) {
			log_fatal("reply_process_addr: Unable to attach lease "
				  "to new IA: %s", isc_result_totext(status));
		}

		/*
		 * If this is a new lease, make sure it is attached somewhere.
		 */
		if (reply->lease->ia_na == NULL) {
			ia_na_reference(&reply->lease->ia_na, reply->ia_na,
					MDL);
		}
	}

	/* Bring a copy of the relevant options into the IA scope. */
	execute_statements_in_scope(NULL, reply->packet, NULL, NULL,
				    reply->packet->options, reply->reply_ia,
				    scope, group, root_group);

      cleanup:
	if (data.data != NULL)
		data_string_forget(&data, MDL);

	if (status == ISC_R_SUCCESS)
		reply->client_addresses++;

	return status;
}

/* Simply send an IAADDR within the IA_NA scope as described. */
static isc_result_t
reply_process_send_addr(struct reply_state *reply, struct iaddr *addr) {
	isc_result_t status = ISC_R_SUCCESS;
	struct data_string data;

	memset(&data, 0, sizeof(data));

	/* Now append the lease. */
	data.len = IAADDR_OFFSET;
	if (!buffer_allocate(&data.buffer, data.len, MDL)) {
		log_error("reply_process_ia: out of memory allocating "
			  "new IAADDR buffer.");
		status = ISC_R_NOMEMORY;
		goto cleanup;
	}
	data.data = data.buffer->data;

	memcpy(data.buffer->data, addr->iabuf, 16);
	putULong(data.buffer->data + 16, reply->send_prefer);
	putULong(data.buffer->data + 20, reply->send_valid);

	if (!append_option_buffer(&dhcpv6_universe, reply->reply_ia,
				  data.buffer, data.buffer->data,
				  data.len, D6O_IAADDR, 0)) {
		log_error("reply_process_ia: unable to save IAADDR "
			  "option");
		status = ISC_R_FAILURE;
		goto cleanup;
	}

	reply->ia_addrs_included = ISC_TRUE;

      cleanup:
	if (data.data != NULL)
		data_string_forget(&data, MDL);

	return status;
}

/* Choose the better of two leases. */
static struct iaaddr *
lease_compare(struct iaaddr *alpha, struct iaaddr *beta) {
	if (alpha == NULL)
		return beta;
	if (beta == NULL)
		return alpha;

	switch(alpha->state) {
	      case FTS_ACTIVE:
		switch(beta->state) {
		      case FTS_ACTIVE:
			/* Choose the lease with the longest lifetime (most
			 * likely the most recently allocated).
			 */
			if (alpha->valid_lifetime_end_time < 
			    beta->valid_lifetime_end_time)
				return beta;
			else
				return alpha;

		      case FTS_EXPIRED:
		      case FTS_ABANDONED:
			return alpha;

		      default:
			log_fatal("Impossible condition at %s:%d.", MDL);
		}
		break;

	      case FTS_EXPIRED:
		switch (beta->state) {
		      case FTS_ACTIVE:
			return beta;

		      case FTS_EXPIRED:
			/* Choose the most recently expired lease. */
			if (alpha->valid_lifetime_end_time <
			    beta->valid_lifetime_end_time)
				return beta;
			else
				return alpha;

		      case FTS_ABANDONED:
			return alpha;

		      default:
			log_fatal("Impossible condition at %s:%d.", MDL);
		}
		break;

	      case FTS_ABANDONED:
		switch (beta->state) {
		      case FTS_ACTIVE:
		      case FTS_EXPIRED:
			return alpha;

		      case FTS_ABANDONED:
			/* Choose the lease that was abandoned longest ago. */
			if (alpha->valid_lifetime_end_time <
			    beta->valid_lifetime_end_time)
				return alpha;

		      default:
			log_fatal("Impossible condition at %s:%d.", MDL);
		}
		break;

	      default:
		log_fatal("Impossible condition at %s:%d.", MDL);
	}

	log_fatal("Triple impossible condition at %s:%d.", MDL);
	return NULL;
}

/*
 * Solicit is how a client starts requesting addresses.
 *
 * If the client asks for rapid commit, and we support it, we will 
 * allocate the addresses and reply.
 *
 * Otherwise we will send an advertise message.
 */

static void
dhcpv6_solicit(struct data_string *reply_ret, struct packet *packet) {
	struct data_string client_id;

	/* 
	 * Validate our input.
	 */
	if (!valid_client_msg(packet, &client_id)) {
		return;
	}

	lease_to_client(reply_ret, packet, &client_id, NULL);

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
	lease_to_client(reply_ret, packet, &client_id, &server_id);

	/*
	 * Cleanup.
	 */
	data_string_forget(&client_id, MDL);
	data_string_forget(&server_id, MDL);
}

/* Find a DHCPv6 packet's shared network from hints in the packet.
 */
static isc_result_t
shared_network_from_packet6(struct shared_network **shared,
			    struct packet *packet)
{
	const struct packet *chk_packet;
	const struct in6_addr *link_addr, *first_link_addr;
	struct iaddr tmp_addr;
	struct subnet *subnet;
	isc_result_t status;

	if ((shared == NULL) || (*shared != NULL) || (packet == NULL))
		return ISC_R_INVALIDARG;

	/*
	 * First, find the link address where the packet from the client
	 * first appeared (if this packet was relayed).
	 */
	first_link_addr = NULL;
	chk_packet = packet->dhcpv6_container_packet;
	while (chk_packet != NULL) {
		link_addr = &chk_packet->dhcpv6_link_address;
		if (!IN6_IS_ADDR_UNSPECIFIED(link_addr) &&
		    !IN6_IS_ADDR_LINKLOCAL(link_addr)) {
			first_link_addr = link_addr;
		}
		chk_packet = chk_packet->dhcpv6_container_packet;
	}

	/*
	 * If there is a relayed link address, find the subnet associated
	 * with that, and use that to get the appropriate
	 * shared_network.
	 */
	if (first_link_addr != NULL) {
		tmp_addr.len = sizeof(*first_link_addr);
		memcpy(tmp_addr.iabuf,
		       first_link_addr, sizeof(*first_link_addr));
		subnet = NULL;
		if (!find_subnet(&subnet, tmp_addr, MDL)) {
			log_debug("No subnet found for link-address %s.",
				  piaddr(tmp_addr));
			return ISC_R_NOTFOUND;
		}
		status = shared_network_reference(shared,
						  subnet->shared_network, MDL);
		subnet_dereference(&subnet, MDL);

	/*
	 * If there is no link address, we will use the interface
	 * that this packet came in on to pick the shared_network.
	 */
	} else {
		status = shared_network_reference(shared,
					 packet->interface->shared_network,
					 MDL);
	}

	return status;
}

/*
 * When a client thinks it might be on a new link, it sends a 
 * Confirm message.
 *
 * From RFC3315 section 18.2.2:
 *
 *   When the server receives a Confirm message, the server determines
 *   whether the addresses in the Confirm message are appropriate for the
 *   link to which the client is attached.  If all of the addresses in the
 *   Confirm message pass this test, the server returns a status of
 *   Success.  If any of the addresses do not pass this test, the server
 *   returns a status of NotOnLink.  If the server is unable to perform
 *   this test (for example, the server does not have information about
 *   prefixes on the link to which the client is connected), or there were
 *   no addresses in any of the IAs sent by the client, the server MUST
 *   NOT send a reply to the client.
 */

/* TODO: discard unicast messages, unless we set unicast option */
static void
dhcpv6_confirm(struct data_string *reply_ret, struct packet *packet) {
	struct shared_network *shared;
	struct subnet *subnet;
	struct option_cache *ia, *ta, *oc;
	struct data_string cli_enc_opt_data, iaaddr, client_id, packet_oro;
	struct option_state *cli_enc_opt_state, *opt_state;
	struct iaddr cli_addr;
	int pass;
	isc_boolean_t inappropriate, has_addrs;
	char reply_data[65536];
	struct dhcpv6_packet *reply = (struct dhcpv6_packet *)reply_data;
	int reply_ofs = (int)((char *)reply->options - (char *)reply);

	/* 
	 * Basic client message validation.
	 */
	memset(&client_id, 0, sizeof(client_id));
	if (!valid_client_msg(packet, &client_id)) {
		return;
	}

	/* Do not process Confirms that do not have IA's we do not recognize.
	 */
	ia = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_NA);
	ta = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_TA);
	if ((ia == NULL) && (ta == NULL))
		return;

	/* 
	 * Bit of variable initialization.
	 */
	opt_state = cli_enc_opt_state = NULL;
	memset(&cli_enc_opt_data, 0, sizeof(cli_enc_opt_data));
	memset(&iaaddr, 0, sizeof(iaaddr));
	memset(&packet_oro, 0, sizeof(packet_oro));

	/* Determine what shared network the client is connected to.  We
	 * must not respond if we don't have any information about the
	 * network the client is on.
	 */
	shared = NULL;
	if ((shared_network_from_packet6(&shared, packet) != ISC_R_SUCCESS) ||
	    (shared == NULL))
		goto exit;

	/* If there are no recorded subnets, then we have no
	 * information about this subnet - ignore Confirms.
	 */
	subnet = shared->subnets;
	if (subnet == NULL)
		goto exit;

	/* Are the addresses in all the IA's appropriate for that link? */
	has_addrs = inappropriate = ISC_FALSE;
	pass = D6O_IA_NA;
	while(!inappropriate) {
		/* If we've reached the end of the IA_NA pass, move to the
		 * IA_TA pass.
		 */
		if ((pass == D6O_IA_NA) && (ia == NULL)) {
			pass = D6O_IA_TA;
			ia = ta;
		}

		/* If we've reached the end of all passes, we're done. */
		if (ia == NULL)
			break;

		if (((pass == D6O_IA_NA) &&
		     !get_encapsulated_IA_state(&cli_enc_opt_state,
						&cli_enc_opt_data,
						packet, ia, IA_NA_OFFSET)) ||
		    ((pass == D6O_IA_TA) &&
		     !get_encapsulated_IA_state(&cli_enc_opt_state,
						&cli_enc_opt_data,
						packet, ia, IA_TA_OFFSET))) {
			goto exit;
		}

		oc = lookup_option(&dhcpv6_universe, cli_enc_opt_state,
				   D6O_IAADDR);

		for ( ; oc != NULL ; oc = oc->next) {
			if (!evaluate_option_cache(&iaaddr, packet, NULL, NULL,
						   packet->options, NULL,
						   &global_scope, oc, MDL) ||
			    (iaaddr.len < IAADDR_OFFSET)) {
				log_error("dhcpv6_confirm: "
					  "error evaluating IAADDR.");
				goto exit;
			}

			/* Copy out the IPv6 address for processing. */
			cli_addr.len = 16;
			memcpy(cli_addr.iabuf, iaaddr.data, 16);

			data_string_forget(&iaaddr, MDL);

			/* Record that we've processed at least one address. */
			has_addrs = ISC_TRUE;

			/* Find out if any subnets cover this address. */
			for (subnet = shared->subnets ; subnet != NULL ;
			     subnet = subnet->next_sibling) {
				if (addr_eq(subnet_number(cli_addr,
							  subnet->netmask),
					    subnet->net))
					break;
			}

			/* If we reach the end of the subnet list, and no
			 * subnet matches the client address, then it must
			 * be inappropriate to the link (so far as our
			 * configuration says).  Once we've found one
			 * inappropriate address, there is no reason to
			 * continue searching.
			 */
			if (subnet == NULL) {
				inappropriate = ISC_TRUE;
				break;
			}
		}

		option_state_dereference(&cli_enc_opt_state, MDL);
		data_string_forget(&cli_enc_opt_data, MDL);

		/* Advance to the next IA_*. */
		ia = ia->next;
	}

	/* If the client supplied no addresses, do not reply. */
	if (!has_addrs)
		goto exit;

	/* 
	 * Set up reply.
	 */
	if (!start_reply(packet, &client_id, NULL, &opt_state, reply)) {
		goto exit;
	}

	/* 
	 * Set our status.
	 */
	if (inappropriate) {
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
	memcpy(reply_ret->buffer->data, reply, reply_ofs);

exit:
	/* Cleanup any stale data strings. */
	if (cli_enc_opt_data.buffer != NULL)
		data_string_forget(&cli_enc_opt_data, MDL);
	if (iaaddr.buffer != NULL)
		data_string_forget(&iaaddr, MDL);
	if (client_id.buffer != NULL)
		data_string_forget(&client_id, MDL);
	if (packet_oro.buffer != NULL)
		data_string_forget(&packet_oro, MDL);

	/* Release any stale option states. */
	if (cli_enc_opt_state != NULL)
		option_state_dereference(&cli_enc_opt_state, MDL);
	if (opt_state != NULL)
		option_state_dereference(&opt_state, MDL);
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
	lease_to_client(reply, packet, &client_id, &server_id);

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

	lease_to_client(reply, packet, &client_id, NULL);

	data_string_forget(&client_id, MDL);
}

static void
ia_na_match_decline(const struct data_string *client_id,
		    const struct data_string *iaaddr,
		    struct iaaddr *lease)
{
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
		      int reply_len)
{
	char tmp_addr[INET6_ADDRSTRLEN];
	struct option_state *host_opt_state;
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
	len = store_options6(reply_data+(*reply_ofs)+16,
			     reply_len-(*reply_ofs)-16,
			     host_opt_state, packet,
			     required_opts_STATUS_CODE, NULL);

	/*
	 * Store the non-encapsulated option data for this 
	 * IA_NA into our reply packet. Defined in RFC 3315, 
	 * section 22.4.  
	 */
	/* option number */
	putUShort((unsigned char *)reply_data+(*reply_ofs), D6O_IA_NA);
	/* option length */
	putUShort((unsigned char *)reply_data+(*reply_ofs)+2, len + 12);
	/* IA_NA, copied from the client */
	memcpy(reply_data+(*reply_ofs)+4, ia_na_id, 4);
	/* t1 and t2, odd that we need them, but here it is */
	putULong((unsigned char *)reply_data+(*reply_ofs)+8, 0);
	putULong((unsigned char *)reply_data+(*reply_ofs)+12, 0);

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
		   const char *packet_type,
		   void (*ia_na_match)(),
		   void (*ia_na_nomatch)())
{
	struct option_state *opt_state;
	struct host_decl *packet_host;
	struct option_cache *ia;
	struct option_cache *oc;
	/* cli_enc_... variables come from the IA_NA/IA_TA options */
	struct data_string cli_enc_opt_data;
	struct option_state *cli_enc_opt_state;
	struct host_decl *host;
	struct option_state *host_opt_state;
	struct data_string iaaddr;
	struct data_string fixed_addr;
	int iaaddr_is_found;
	char reply_data[65536];
	struct dhcpv6_packet *reply = (struct dhcpv6_packet *)reply_data;
	int reply_ofs = (int)((char *)reply->options - (char *)reply);
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
		if (!save_option_buffer(&dhcpv6_universe, opt_state, NULL, 
					(unsigned char *)server_duid.data, 
					server_duid.len, D6O_SERVERID, 0)) {
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
	reply_ofs += store_options6(reply_data+reply_ofs,
				    sizeof(reply_data)-reply_ofs, 
				    opt_state, packet,
				    required_opts, NULL);

	/*
	 * Loop through the IA_NA reported by the client, and deal with
	 * addresses reported as already in use.
	 */
	for (ia = lookup_option(&dhcpv6_universe, packet->options, D6O_IA_NA);
	     ia != NULL; ia = ia->next) {
	     	iaaddr_is_found = 0;

		if (!get_encapsulated_IA_state(&cli_enc_opt_state,
					       &cli_enc_opt_data,
					       packet, ia, IA_NA_OFFSET)) {
			goto exit;
		}

		iaid = getULong(cli_enc_opt_data.data);

		/* 
		 * XXX: It is possible that we can get multiple addresses
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

		if ((host == NULL) && (iaaddr.len >= IAADDR_OFFSET)) {
			/*
			 * Find existing IA_NA.
			 */
			if (ia_na_make_key(&key, iaid, 
					   (char *)client_id->data,
					   client_id->len, 
					   MDL) != ISC_R_SUCCESS) {
				log_fatal("iterate_over_ia_na: no memory for "
					  "key.");
			}

			existing_ia_na = NULL;
			if (ia_na_hash_lookup(&existing_ia_na, ia_active, 
					      (unsigned char *)key.data, 
					      key.len, MDL)) {
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
	memcpy(reply_ret->buffer->data, reply, reply_ofs);

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
 * much we can do, other that log the occurrence.
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
		    struct iaaddr *lease)
{
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
		      int reply_len)
{
	char tmp_addr[INET6_ADDRSTRLEN];
	struct option_state *host_opt_state;
	int len;

	log_info("Client %s releases address %s, which is not leased to it.",
		 print_hex_1(client_id->len, client_id->data, 60),
		 inet_ntop(AF_INET6, iaaddr->data, tmp_addr, sizeof(tmp_addr)));

	/*
	 * Create state for this IA_NA.
	 */
	host_opt_state = NULL;
	if (!option_state_allocate(&host_opt_state, MDL)) {
		log_error("ia_na_nomatch_release: out of memory "
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
		log_error("ia_na_nomatch_release: "
			  "out of space for reply packet.");
		goto exit;
	}

	/*
	 * Put our status code into the reply packet.
	 */
	len = store_options6(reply_data+(*reply_ofs)+16,
			     reply_len-(*reply_ofs)-16,
			     host_opt_state, packet,
			     required_opts_STATUS_CODE, NULL);

	/*
	 * Store the non-encapsulated option data for this 
	 * IA_NA into our reply packet. Defined in RFC 3315, 
	 * section 22.4.  
	 */
	/* option number */
	putUShort((unsigned char *)reply_data+(*reply_ofs), D6O_IA_NA);
	/* option length */
	putUShort((unsigned char *)reply_data+(*reply_ofs)+2, len + 12);
	/* IA_NA, copied from the client */
	memcpy(reply_data+(*reply_ofs)+4, ia_na_id, 4);
	/* t1 and t2, odd that we need them, but here it is */
	putULong((unsigned char *)reply_data+(*reply_ofs)+8, 0);
	putULong((unsigned char *)reply_data+(*reply_ofs)+12, 0);

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

/*
 * Information-Request is used by clients who have obtained an address
 * from other means, but want configuration information from the server.
 */

/* TODO: discard unicast messages, unless we set unicast option */
static void
dhcpv6_information_request(struct data_string *reply, struct packet *packet) {
	struct data_string client_id;
	struct data_string server_id;

	/*
	 * Validate our input.
	 */
	if (!valid_client_info_req(packet, &server_id)) {
		return;
	}

	/*
	 * Get our client ID, if there is one.
	 */
	memset(&client_id, 0, sizeof(client_id));
	if (get_client_id(packet, &client_id) != ISC_R_SUCCESS) {
		data_string_forget(&client_id, MDL);
	}

	/*
	 * Use the lease_to_client() function. This will work fine, 
	 * because the valid_client_info_req() insures that we 
	 * don't have any IA_NA or IA_TA that would cause us to
	 * allocate addresses to the client.
	 */
	lease_to_client(reply, packet, &client_id,
			server_id.data != NULL ? &server_id : NULL);

	/*
	 * Cleanup.
	 */
	if (client_id.data != NULL) {
		data_string_forget(&client_id, MDL);
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
	 * Initialize variables for early exit.
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
		inet_ntop(AF_INET6, &packet->dhcpv6_link_address,
			  link_addr, sizeof(link_addr));
		inet_ntop(AF_INET6, &packet->dhcpv6_peer_address,
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

	if (!packet6_len_okay((char *)enc_opt_data.data, enc_opt_data.len)) {
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
	enc_packet->dhcpv6_container_packet = packet;

	msg_type = enc_opt_data.data[0];
	if ((msg_type == DHCPV6_RELAY_FORW) ||
	    (msg_type == DHCPV6_RELAY_REPL)) {
		relay = (struct dhcpv6_relay_packet *)enc_opt_data.data;
		enc_packet->dhcpv6_msg_type = relay->msg_type;

		/* relay-specific data */
		enc_packet->dhcpv6_hop_count = relay->hop_count;
		memcpy(&enc_packet->dhcpv6_link_address,
		       relay->link_address, sizeof(relay->link_address));
		memcpy(&enc_packet->dhcpv6_peer_address,
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
	memcpy(reply.link_address, &packet->dhcpv6_link_address,
	       sizeof(reply.link_address));
	memcpy(reply.peer_address, &packet->dhcpv6_peer_address,
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
	memcpy(reply_ret->buffer->data, &reply, sizeof(reply));
	putShort(reply_ret->buffer->data+sizeof(reply), D6O_RELAY_MSG);
	putShort(reply_ret->buffer->data+sizeof(reply)+2, enc_reply.len);
	memcpy(reply_ret->buffer->data+sizeof(reply)+4, 
	       enc_reply.data, enc_reply.len);
	if (interface_id.data != NULL) {
		putShort(reply_ret->buffer->data+sizeof(reply)+4+enc_reply.len,
			 D6O_INTERFACE_ID);
		putShort(reply_ret->buffer->data+sizeof(reply)+6+enc_reply.len,
			 interface_id.len);
		memcpy(reply_ret->buffer->data+sizeof(reply)+8+enc_reply.len,
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
	    	addr = &packet->dhcpv6_link_address;
	    	data_string_sprintfa(&s, ", link address %s", 
				     inet_ntop(AF_INET6, addr, 
					       tmp_addr, sizeof(tmp_addr)));
	    	addr = &packet->dhcpv6_peer_address;
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

static void
seek_shared_host(struct host_decl **hp, struct shared_network *shared) {
	struct host_decl *nofixed = NULL;
	struct host_decl *seek, *hold = NULL;

	/*
	 * Seek forward through fixed addresses for the right broadcast
	 * domain.
	 */
	host_reference(&hold, *hp, MDL);
	host_dereference(hp, MDL);
	seek = hold;
	while (seek != NULL) {
		if (seek->fixed_addr == NULL)
			nofixed = seek;
		else if (fixed_matches_shared(seek, shared))
			break;

		seek = seek->n_ipaddr;
	}

	if ((seek == NULL) && (nofixed != NULL))
		seek = nofixed;

	if (seek != NULL)
		host_reference(hp, seek, MDL);
}

static isc_boolean_t
fixed_matches_shared(struct host_decl *host, struct shared_network *shared) {
	struct subnet *subnet;
	struct data_string addr;
	isc_boolean_t matched;
	struct iaddr fixed;

	if (host->fixed_addr == NULL)
		return ISC_FALSE;

	memset(&addr, 0, sizeof(addr));
	if (!evaluate_option_cache(&addr, NULL, NULL, NULL, NULL, NULL,
				   &global_scope, host->fixed_addr, MDL))
		return ISC_FALSE;

	if (addr.len < 16) {
		data_string_forget(&addr, MDL);
		return ISC_FALSE;
	}

	fixed.len = 16;
	memcpy(fixed.iabuf, addr.data, 16);

	matched = ISC_FALSE;
	for (subnet = shared->subnets ; subnet != NULL ;
	     subnet = subnet->next_sibling) {
		if (addr_eq(subnet_number(fixed, subnet->netmask),
			    subnet->net)) {
			matched = ISC_TRUE;
			break;
		}
	}

	data_string_forget(&addr, MDL);
	return matched;
}

#endif /* DHCPv6 */

