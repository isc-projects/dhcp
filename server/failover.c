/* failover.c

   Failover protocol support code... */

/*
 * Copyright (c) 1999-1999 Internet Software Consortium.
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
"$Id: failover.c,v 1.4 1999/11/20 18:36:31 mellon Exp $ Copyright (c) 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include <omapip/omapip_p.h>

#if defined (FAILOVER_PROTOCOL)
static struct hash_table *failover_hash;
static dhcp_failover_state_t *failover_states;
static isc_result_t do_a_failover_option (omapi_object_t *,
					  dhcp_failover_link_t *);

void enter_failover_peer (peer)
	struct failover_peer *peer;
{
	add_hash (failover_hash, peer -> name, 0, (unsigned char *)peer);
}

struct failover_peer *find_failover_peer (name)
	char *name;
{
	struct failover_peer *peer;

	peer = ((struct failover_peer *)
		hash_lookup (failover_hash, peer -> name, 0));
	return peer;
}

/* The failover protocol has three objects associated with it.  For
   each failover partner declaration in the dhcpd.conf file, primary
   or secondary, there is a failover_state object.  For any primary or
   secondary state object that has a connection to its peer, there is
   also a failover_link object, which has its own input state seperate
   from the failover protocol state for managing the actual bytes
   coming in off the wire.  Finally, there will be one listener object
   for every distinct port number associated with a secondary
   failover_state object.  Normally all secondary failover_state
   objects are expected to listen on the same port number, so there
   need be only one listener object, but if different port numbers are
   specified for each failover object, there could be as many as one
   listener object for each secondary failover_state object. */

/* This, then, is the implemention of the failover link object. */

isc_result_t dhcp_failover_link_initiate (omapi_object_t *h)
{
	isc_result_t status;
	dhcp_failover_link_t *obj;
	char *peer_name;
	unsigned long port;
	omapi_value_t *value = (omapi_value_t *)0;

	status = omapi_get_value_str (h, (omapi_object_t *)0,
				      "remote-port", &value);
	if (status != ISC_R_SUCCESS)
		return status;
	if (!value -> value) {
		omapi_value_dereference (&value,
					 "dhcp_failover_link_initiate");
		return ISC_R_INVALIDARG;
	}
	
	status = omapi_get_int_value (&port, value -> value);
	omapi_value_dereference (&value, "dhcp_failover_link_initiate");
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_get_value_str (h, (omapi_object_t *)0,
				      "remote-peer", &value);
	if (status != ISC_R_SUCCESS)
		return status;
	if (!value -> value ||
	    (value -> value -> type != omapi_datatype_string &&
	     value -> value -> type != omapi_datatype_data)) {
		omapi_value_dereference (&value,
					 "dhcp_failover_link_initiate");
		return ISC_R_INVALIDARG;
	}

	/* Save the name. */
	peer_name = malloc (value -> value -> u.buffer.len + 1);
	if (!peer_name) {
		omapi_value_dereference (&value,
					 "dhcp_failover_link_initiate");
		return ISC_R_NOMEMORY;
	}

	memcpy (peer_name, value -> value -> u.buffer.value,
		value -> value -> u.buffer.len);
	peer_name [value -> value -> u.buffer.len] = 0;
	omapi_value_dereference (&value, "dhcp_failover_link_initiate");

	obj = (dhcp_failover_link_t *)malloc (sizeof *obj);
	if (!obj)
		return ISC_R_NOMEMORY;
	memset (obj, 0, sizeof *obj);
	obj -> refcnt = 1;
	obj -> type = dhcp_type_failover_link;
	obj -> peer_name = peer_name;
	obj -> peer_port = port;

	status = omapi_connect ((omapi_object_t *)obj, peer_name, port);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "dhcp_failover_link_initiate");
		return status;
	}
	status = omapi_object_reference (&h -> outer, (omapi_object_t *)obj,
					 "dhcp_failover_link_initiate");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "dhcp_failover_link_initiate");
		return status;
	}
	status = omapi_object_reference (&obj -> inner, h,
					 "dhcp_failover_link_initiate");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "dhcp_failover_link_initiate");
		return status;
	}

	/* Send the introductory message. */
	status = dhcp_failover_send_connect ((omapi_object_t *)obj);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "dhcp_failover_link_initiate");
		return status;
	}

	omapi_object_dereference ((omapi_object_t **)&obj,
				  "omapi_protocol_accept");
	return ISC_R_SUCCESS;
}

isc_result_t dhcp_failover_link_signal (omapi_object_t *h,
					const char *name, va_list ap)
{
	isc_result_t status;
	dhcp_failover_link_t *link;
	omapi_object_t *c;
	u_int16_t nlen;
	u_int32_t vlen;

	if (h -> type != dhcp_type_failover_link) {
		/* XXX shouldn't happen.   Put an assert here? */
		return ISC_R_UNEXPECTED;
	}
	link = (dhcp_failover_link_t *)h;

	/* Not a signal we recognize? */
	if (strcmp (name, "ready")) {
		if (h -> inner && h -> inner -> type -> signal_handler)
			return (*(h -> inner -> type -> signal_handler)) (h,
									  name,
									  ap);
		return ISC_R_NOTFOUND;
	}

	if (!h -> outer || h -> outer -> type != omapi_type_connection)
		return ISC_R_INVALIDARG;
	c = h -> outer;

	/* We get here because we requested that we be woken up after
           some number of bytes were read, and that number of bytes
           has in fact been read. */
	switch (link -> state) {
	      case dhcp_flink_start:
		link -> state = dhcp_flink_message_length_wait;
		if ((omapi_connection_require (c, 2)) != ISC_R_SUCCESS)
			break;
	      case dhcp_flink_message_length_wait:
		link -> state = dhcp_flink_message_wait;
		link -> imsg = dmalloc (sizeof (failover_message_t),
					"dhcp_failover_link_signal");
		if (!link -> imsg) {
		      dhcp_flink_fail:
			if (link -> imsg) {
				dfree (link -> imsg,
				       "dhcp_failover_link_signal");
				link -> imsg = (failover_message_t *)0;
			}
			link -> state = dhcp_flink_disconnected;
			omapi_disconnect (c, 1);
			/* XXX just blow away the protocol state now?
			   XXX or will disconnect blow it away? */
			return ISC_R_UNEXPECTED;
		}
		memset (link -> imsg, 0, sizeof (link -> imsg));
		/* Get the length: */
		omapi_connection_get_uint16 (c, &link -> imsg_len);
		link -> imsg_count = 0;	/* Bytes read. */
		
		/* Maximum of 2048 bytes in any failover message. */
		if (link -> imsg_len > DHCP_FAILOVER_MAX_MESSAGE_SIZE)
			goto dhcp_flink_fail;

		if ((omapi_connection_require (c, link -> imsg_len)) !=
		    ISC_R_SUCCESS)
			break;
	      case dhcp_flink_message_wait:
		/* Read in the message.  At this point we have the
		   entire message in the input buffer.  For each
		   incoming value ID, set a bit in the bitmask
		   indicating that we've gotten it.  Maybe flag an
		   error message if the bit is already set.  Once
		   we're done reading, we can check the bitmask to
		   make sure that the required fields for each message
		   have been included. */

		link -> imsg_count += 2;	/* Count the length as read. */

		/* Get message type. */
		omapi_connection_copyout (&link -> imsg -> type, c, 1);
		link -> imsg_count++;

		/* Get message payload offset. */
		omapi_connection_copyout (&link -> imsg_payoff, c, 1);
		link -> imsg_count++;

		/* Get message time. */
		omapi_connection_get_uint32 (c, &link -> imsg -> time);
		link -> imsg_count += 4;

		/* Get transaction ID. */
		omapi_connection_get_uint32 (c, &link -> imsg -> xid);
		link -> imsg_count += 4;

		/* Skip over any portions of the message header that we
		   don't understand. */
		if (link -> imsg_payoff - link -> imsg_count) {
			omapi_connection_copyout ((unsigned char *)0, c,
						  (link -> imsg_payoff -
						   link -> imsg_count));
			link -> imsg_count = link -> imsg_payoff;
		}
				
		/* Get transaction ID. */
		omapi_connection_get_uint32 (c, &link -> imsg -> xid);
		link -> imsg_count += 4;

		/* Now start sucking options off the wire. */
		while (link -> imsg_count < link -> imsg_len) {
			if (do_a_failover_option (c, link) != ISC_R_SUCCESS)
				goto dhcp_flink_fail;
		}

		/* Once we have the entire message, and we've validated
		   it as best we can here, pass it to the parent. */
		omapi_signal_in (h -> outer, "message", link);
		break;

	      default:
		/* XXX should never get here.   Assertion? */
		break;
	}
	return ISC_R_SUCCESS;
}

static isc_result_t do_a_failover_option (c, link)
	omapi_object_t *c;
	dhcp_failover_link_t *link;
{
	u_int16_t option_code;
	u_int16_t option_len;
	unsigned char *op;
	unsigned op_size;
	unsigned op_count;
	int i;
	
	if (link -> imsg_count + 2 > link -> imsg_len) {
		log_error ("FAILOVER: message overflow at option code.");
		return ISC_R_PROTOCOLERROR;
	}

	/* Get option code. */
	omapi_connection_get_uint16 (c, &option_code);
	link -> imsg_count += 2;
	
	/* Get option length. */
	omapi_connection_get_uint16 (c, &option_len);
	link -> imsg_count += 2;

	if (link -> imsg_count + option_len > link -> imsg_len) {
		log_error ("FAILOVER: message overflow at %s",
			   " length.");
		return ISC_R_PROTOCOLERROR;
	}

	/* If it's an unknown code, skip over it. */
	if (option_code > FTO_MAX) {
#if defined (FAILOVER_PROTOCOL_DEBUG) && defined (FAILOVER_DEBUG_VERBOSE)
		log_debug ("  option code %d len %d (not recognized)",
			   option_code, option_len);
#endif
		omapi_connection_copyout ((unsigned char *)0, c, option_len);
		link -> imsg_count += option_len;
		return ISC_R_SUCCESS;
	}

	/* If it's the digest, do it now. */
	if (ft_options [option_code].type == FT_DIGEST) {
		link -> imsg_count += option_len;
		if (link -> imsg_count != link -> imsg_len) {
			log_error ("FAILOVER: digest not at end of message");
			return ISC_R_PROTOCOLERROR;
		}
#if defined (FAILOVER_PROTOCOL_DEBUG) && defined (FAILOVER_DEBUG_VERBOSE)
		log_debug ("  option %s len %d",
			   ft_options [option_code].name, option_len);
#endif
		/* For now, just dump it. */
		omapi_connection_copyout ((unsigned char *)0, c, option_len);
		return ISC_R_SUCCESS;
	}
	
	/* Only accept an option once. */
	if (link -> imsg -> options_present & ft_options [option_code].bit) {
		log_error ("FAILOVER: duplicate option %s",
			   ft_options [option_code].name);
		return ISC_R_PROTOCOLERROR;
	}

	/* Make sure the option is appropriate for this type of message.
	   Really, any option is generally allowed for any message, and the
	   cases where this is not true are too complicated to represent in
	   this way - what this code is doing is to just avoid saving the
	   value of an option we don't have any way to use, which allows
	   us to make the failover_message structure smaller. */
	if (ft_options [option_code].bit &&
	    !(fto_allowed [option_code] & ft_options [option_code].bit)) {
		omapi_connection_copyout ((unsigned char *)0, c, option_len);
		link -> imsg_count += option_len;
		return ISC_R_SUCCESS;
	}		

	/* Figure out how many elements, how big they are, and where
	   to store them. */
	if (ft_options [option_code].num_present) {
		/* If this option takes a fixed number of elements,
		   we expect the space for them to be preallocated,
		   and we can just read the data in. */

		op = ((unsigned char *)&link -> imsg) +
			ft_options [option_code].offset;
		op_size = ft_sizes [ft_options [option_code].type];
		op_count = ft_options [option_code].num_present;

		if (option_len != op_size * op_count) {
			log_error ("FAILOVER: option size (%d:%d), option %s",
				   option_len,
				   (ft_sizes [ft_options [option_code].type] *
				    ft_options [option_code].num_present),
				   ft_options [option_code].name);
			return ISC_R_PROTOCOLERROR;
		}
	} else {
		failover_option_t *fo;

		/* FT_DDNS* are special - one or two bytes of status
		   followed by the client FQDN. */
		if (ft_options [option_code].type == FT_DDNS1 ||
		    ft_options [option_code].type == FT_DDNS1) {
			ddns_fqdn_t *ddns =
				((ddns_fqdn_t *)
				 (((char *)&link -> imsg) +
				  ft_options [option_code].offset));

			op_count = (ft_options [option_code].type == FT_DDNS1
				    ? 1 : 2);

			omapi_connection_copyout (&ddns -> codes [0],
						  c, op_count);
			if (op_count == 1)
				ddns -> codes [1] = 0;
			op_size = 1;
			op_count = option_len - op_count;

			ddns -> length = op_count;
			ddns -> data = malloc (op_count);
			if (!ddns -> data) {
				log_error ("FAILOVER: no memory getting%s(%d)",
					   " DNS data ", op_count);

				/* Actually, NO_MEMORY, but if we lose here
				   we have to drop the connection. */
				return ISC_R_PROTOCOLERROR;
			}
			omapi_connection_copyout (ddns -> data, c, op_count);
			goto out;
		}

		/* A zero for num_present means that any number of
		   elements can appear, so we have to figure out how
		   many we got from the length of the option, and then
		   fill out a failover_option structure describing the
		   data. */
		op_size = ft_sizes [ft_options [option_code].type];

		/* Make sure that option data length is a multiple of the
		   size of the data type being sent. */
		if (op_size > 1 && option_len % op_size) {
			log_error ("FAILOVER: option_len %d not %s%d",
				   option_len, "multiple of ", op_size);
			return ISC_R_PROTOCOLERROR;
		}

		op_count = option_len / op_size;
		
		fo = ((failover_option_t *)
		      (((char *)&link -> imsg) +
		       ft_options [option_code].offset));

		fo -> count = op_count;
		fo -> data = malloc (option_len);
		if (!fo -> data) {
			log_error ("FAILOVER: no memory getting %s (%d)",
				   "option data", op_count);

			return ISC_R_PROTOCOLERROR;
		}			
		op = fo -> data;
	}

	/* For single-byte message values and multi-byte values that
           don't need swapping, just read them in all at once. */
	if (op_size == 1 || ft_options [option_code].type == FT_IPADDR) {
		omapi_connection_copyout ((unsigned char *)op, c, option_len);
		goto out;
	}

	/* For values that require swapping, read them in one at a time
	   using routines that swap bytes. */
	for (i = 0; i < op_count; i++) {
		switch (ft_options [option_code].type) {
		      case FT_UINT32:
			omapi_connection_get_uint32 (c, (u_int32_t *)op);
			op += 4;
			break;
			
		      case FT_UINT16:
			omapi_connection_get_uint16 (c, (u_int16_t *)op);
			op += 2;
			break;
			
		      default:
			/* Everything else should have been handled
			   already. */
			log_error ("FAILOVER: option %s: bad type %d",
				   ft_options [option_code].name,
				   ft_options [option_code].type);
			return ISC_R_PROTOCOLERROR;
		}
	}
      out:
	/* Remember that we got this option. */
	link -> imsg -> options_present |= ft_options [option_code].bit;
	return ISC_R_SUCCESS;
}

isc_result_t dhcp_failover_link_set_value (omapi_object_t *h,
					   omapi_object_t *id,
					   omapi_data_string_t *name,
					   omapi_typed_data_t *value)
{
	if (h -> type != omapi_type_protocol)
		return ISC_R_INVALIDARG;

	/* Never valid to set these. */
	if (!omapi_ds_strcmp (name, "link-port") ||
	    !omapi_ds_strcmp (name, "link-name") ||
	    !omapi_ds_strcmp (name, "link-state"))
		return ISC_R_NOPERM;

	if (h -> inner && h -> inner -> type -> set_value)
		return (*(h -> inner -> type -> set_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_failover_link_get_value (omapi_object_t *h,
					   omapi_object_t *id,
					   omapi_data_string_t *name,
					   omapi_value_t **value)
{
	dhcp_failover_link_t *link;

	if (h -> type != omapi_type_protocol)
		return ISC_R_INVALIDARG;
	link = (dhcp_failover_link_t *)h;
	
	if (!omapi_ds_strcmp (name, "link-port")) {
		return omapi_make_int_value (value, name,
					     (int)link -> peer_port,
					     "dhcp_failover_link_get_value");
	} else if (!omapi_ds_strcmp (name, "link-name")) {
		return omapi_make_string_value
			(value, name, link -> peer_name,
			 "dhcp_failover_link_get_value");
	} else if (!omapi_ds_strcmp (name, "link-state")) {
		if (link -> state < 0 ||
		    link -> state >= dhcp_flink_state_max)
			return omapi_make_string_value
				(value, name, "invalid link state",
				 "dhcp_failover_link_get_value");
		return omapi_make_string_value
			(value, name,
			 dhcp_failover_link_state_names [link -> state],
			 "dhcp_failover_link_get_value");
	}

	if (h -> inner && h -> inner -> type -> get_value)
		return (*(h -> inner -> type -> get_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_failover_link_destroy (omapi_object_t *h, const char *name)
{
	dhcp_failover_link_t *link;
	if (h -> type != dhcp_type_failover_link)
		return ISC_R_INVALIDARG;
	link = (dhcp_failover_link_t *)h;
	if (link -> imsg) {
		dfree (link -> imsg, "dhcp_failover_link_destroy");
		link -> imsg = (failover_message_t *)0;
	}
	return ISC_R_SUCCESS;
}

/* Write all the published values associated with the object through the
   specified connection. */

isc_result_t dhcp_failover_link_stuff_values (omapi_object_t *c,
					      omapi_object_t *id,
					      omapi_object_t *l)
{
	dhcp_failover_link_t *link;
	isc_result_t status;

	if (l -> type != dhcp_type_failover_link)
		return ISC_R_INVALIDARG;
	link = (dhcp_failover_link_t *)l;
	
	status = omapi_connection_put_name (c, "link-port");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, sizeof (int));
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, link -> peer_port);
	if (status != ISC_R_SUCCESS)
		return status;
	
	status = omapi_connection_put_name (c, "link-name");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_string (c, link -> peer_name);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "link-state");
	if (status != ISC_R_SUCCESS)
		return status;
	if (link -> state < 0 ||
	    link -> state >= dhcp_flink_state_max)
		status = omapi_connection_put_string (c, "invalid link state");
	else
		status = (omapi_connection_put_string
			  (c, dhcp_failover_link_state_names [link -> state]));
	if (status != ISC_R_SUCCESS)
		return status;

	if (link -> inner && link -> inner -> type -> stuff_values)
		return (*(link -> inner -> type -> stuff_values)) (c, id,
								link -> inner);
	return ISC_R_SUCCESS;
}

/* Set up a listener for the omapi protocol.    The handle stored points to
   a listener object, not a protocol object. */

isc_result_t dhcp_failover_listen (omapi_object_t *h)
{
	isc_result_t status;
	dhcp_failover_listener_t *obj;
	unsigned long port;
	omapi_value_t *value = (omapi_value_t *)0;

	status = omapi_get_value_str (h, (omapi_object_t *)0,
				      "local-port", &value);
	if (status != ISC_R_SUCCESS)
		return status;
	if (!value -> value) {
		omapi_value_dereference (&value, "dhcp_failover_listen");
		return ISC_R_INVALIDARG;
	}
	
	status = omapi_get_int_value (&port, value -> value);
	omapi_value_dereference (&value, "dhcp_failover_listen");
	if (status != ISC_R_SUCCESS)
		return status;

	obj = (dhcp_failover_listener_t *)malloc (sizeof *obj);
	if (!obj)
		return ISC_R_NOMEMORY;
	memset (obj, 0, sizeof *obj);
	obj -> refcnt = 1;
	obj -> type = dhcp_type_failover_listener;
	obj -> local_port = port;
	
	status = omapi_listen ((omapi_object_t *)obj, port, 1);
	omapi_object_dereference ((omapi_object_t **)&obj,
				  "dhcp_failover_listen");
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_object_reference (&h -> outer, (omapi_object_t *)obj,
					 "dhcp_failover_listen");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "dhcp_failover_listen");
		return status;
	}
	status = omapi_object_reference (&obj -> inner, h,
					 "dhcp_failover_listen");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "dhcp_failover_listen");
		return status;
	}

	return status;
}

/* Signal handler for protocol listener - if we get a connect signal,
   create a new protocol connection, otherwise pass the signal down. */

isc_result_t dhcp_failover_listener_signal (omapi_object_t *o,
					    const char *name, va_list ap)
{
	isc_result_t status;
	omapi_connection_object_t *c;
	dhcp_failover_link_t *obj;
	dhcp_failover_listener_t *p;
	dhcp_failover_state_t *state;
	char *peer_name;

	if (!o || o -> type != dhcp_type_failover_listener)
		return ISC_R_INVALIDARG;
	p = (dhcp_failover_listener_t *)o;

	/* Not a signal we recognize? */
	if (strcmp (name, "connect")) {
		if (p -> inner && p -> inner -> type -> signal_handler)
			return (*(p -> inner -> type -> signal_handler))
				(p -> inner, name, ap);
		return ISC_R_NOTFOUND;
	}

	c = va_arg (ap, omapi_connection_object_t *);
	if (!c || c -> type != omapi_type_connection)
		return ISC_R_INVALIDARG;

	/* See if we can find a secondary failover_state object that
	   matches this connection. */
	for (state = failover_states; state; state = state -> next) {
		struct hostent *he;
		int hix;
		struct in_addr ia;

		if (inet_aton (state -> remote_peer, &ia)) {
			if (ia.s_addr == c -> remote_addr.sin_addr.s_addr)
				break;
		} else {
			he = gethostbyname (state -> remote_peer);
			if (!he)
				continue;
			for (hix = 0; he -> h_addr_list [hix]; hix++) {
				if (!memcmp (he -> h_addr_list [hix],
					     &c -> remote_addr.sin_addr,
					     sizeof c -> remote_addr.sin_addr))
					break;
			}
			if (he -> h_addr_list [hix])
				break;
		}
	}		

	/* If we can't find a failover protocol state for this remote
	   host, drop the connection */
	if (!state) {
		/* XXX Send a refusal message first?
		   XXX Look in protocol spec for guidance. */
		/* XXX An error message from a connect signal should
		   XXX drop the connection - make sure this is what
		   XXX actually happens! */
		return ISC_R_INVALIDARG;
	}

	obj = (dhcp_failover_link_t *)malloc (sizeof *obj);
	if (!obj)
		return ISC_R_NOMEMORY;
	memset (obj, 0, sizeof *obj);
	obj -> refcnt = 1;
	obj -> type = dhcp_type_failover_link;
	peer_name = malloc (strlen (state -> remote_peer) + 1);
	if (!peer_name)
		return ISC_R_NOMEMORY;
	strcpy (peer_name, state -> remote_peer);
	obj -> peer_name = peer_name;
	obj -> peer_port = ntohs (c -> remote_addr.sin_port);

	status = omapi_object_reference (&obj -> outer, (omapi_object_t *)c,
					 "dhcp_failover_listener_signal");
	if (status != ISC_R_SUCCESS) {
	      lose:
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "dhcp_failover_listener_signal");
		omapi_disconnect ((omapi_object_t *)c, 1);
		return status;
	}

	status = omapi_object_reference (&c -> inner, (omapi_object_t *)obj,
					 "dhcp_failover_listener_signal");
	if (status != ISC_R_SUCCESS)
		goto lose;

	/* Notify the master state machine of the arrival of a new
           connection. */
	status = omapi_signal_in ((omapi_object_t *)state, "connect", obj);
	if (status != ISC_R_SUCCESS)
		goto lose;

	omapi_object_dereference ((omapi_object_t **)&obj,
				  "dhcp_failover_listener_signal");
	return status;
}

isc_result_t dhcp_failover_listener_set_value (omapi_object_t *h,
						omapi_object_t *id,
						omapi_data_string_t *name,
						omapi_typed_data_t *value)
{
	if (h -> type != dhcp_type_failover_listener)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> set_value)
		return (*(h -> inner -> type -> set_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_failover_listener_get_value (omapi_object_t *h,
						omapi_object_t *id,
						omapi_data_string_t *name,
						omapi_value_t **value)
{
	if (h -> type != dhcp_type_failover_listener)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> get_value)
		return (*(h -> inner -> type -> get_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_failover_listener_destroy (omapi_object_t *h,
					      const char *name)
{
	if (h -> type != dhcp_type_failover_listener)
		return ISC_R_INVALIDARG;
	return ISC_R_SUCCESS;
}

/* Write all the published values associated with the object through the
   specified connection. */

isc_result_t dhcp_failover_listener_stuff (omapi_object_t *c,
					   omapi_object_t *id,
					   omapi_object_t *p)
{
	int i;

	if (p -> type != dhcp_type_failover_listener)
		return ISC_R_INVALIDARG;

	if (p -> inner && p -> inner -> type -> stuff_values)
		return (*(p -> inner -> type -> stuff_values)) (c, id,
								p -> inner);
	return ISC_R_SUCCESS;
}

/* Set up master state machine for the failover protocol. */

isc_result_t dhcp_failover_register (omapi_object_t *h)
{
	isc_result_t status;
	dhcp_failover_state_t *obj;
	unsigned long port;
	omapi_value_t *value = (omapi_value_t *)0;

	status = omapi_get_value_str (h, (omapi_object_t *)0,
				      "local-port", &value);
	if (status != ISC_R_SUCCESS)
		return status;
	if (!value -> value) {
		omapi_value_dereference (&value, "dhcp_failover_register");
		return ISC_R_INVALIDARG;
	}
	
	status = omapi_get_int_value (&port, value -> value);
	omapi_value_dereference (&value, "dhcp_failover_listen");
	if (status != ISC_R_SUCCESS)
		return status;

	obj = (dhcp_failover_state_t *)malloc (sizeof *obj);
	if (!obj)
		return ISC_R_NOMEMORY;
	memset (obj, 0, sizeof *obj);
	obj -> refcnt = 1;
	obj -> type = dhcp_type_failover_state;
	obj -> listen_port = port;
	
	status = omapi_listen ((omapi_object_t *)obj, port, 1);
	omapi_object_dereference ((omapi_object_t **)&obj,
				  "dhcp_failover_listen");
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_object_reference (&h -> outer, (omapi_object_t *)obj,
					 "dhcp_failover_listen");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "dhcp_failover_listen");
		return status;
	}
	status = omapi_object_reference (&obj -> inner, h,
					 "dhcp_failover_listen");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "dhcp_failover_listen");
		return status;
	}

	return status;
}

/* Signal handler for protocol state machine. */

isc_result_t dhcp_failover_state_signal (omapi_object_t *o,
					 const char *name, va_list ap)
{
	isc_result_t status;
	omapi_connection_object_t *c;
	omapi_protocol_object_t *obj;
	dhcp_failover_state_t *state;
	char *peer_name;

	if (!o || o -> type != dhcp_type_failover_state)
		return ISC_R_INVALIDARG;
	state = (dhcp_failover_state_t *)o;

	/* Not a signal we recognize? */
	if (strcmp (name, "connect") &&
	    strcmp (name, "disconnect") &&
	    strcmp (name, "message")) {
		if (state -> inner && state -> inner -> type -> signal_handler)
			return (*(state -> inner -> type -> signal_handler))
				(state -> inner, name, ap);
		return ISC_R_NOTFOUND;
	}

	/* Handle all the events we care about... */
	return ISC_R_SUCCESS;
}

isc_result_t dhcp_failover_state_set_value (omapi_object_t *h,
						omapi_object_t *id,
						omapi_data_string_t *name,
						omapi_typed_data_t *value)
{
	if (h -> type != dhcp_type_failover_state)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> set_value)
		return (*(h -> inner -> type -> set_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_failover_state_get_value (omapi_object_t *h,
						omapi_object_t *id,
						omapi_data_string_t *name,
						omapi_value_t **value)
{
	if (h -> type != dhcp_type_failover_state)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> get_value)
		return (*(h -> inner -> type -> get_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_failover_state_destroy (omapi_object_t *h,
					      const char *name)
{
	if (h -> type != dhcp_type_failover_state)
		return ISC_R_INVALIDARG;
	return ISC_R_SUCCESS;
}

/* Write all the published values associated with the object through the
   specified connection. */

isc_result_t dhcp_failover_state_stuff (omapi_object_t *c,
					   omapi_object_t *id,
					   omapi_object_t *p)
{
	int i;

	if (p -> type != dhcp_type_failover_state)
		return ISC_R_INVALIDARG;

	if (p -> inner && p -> inner -> type -> stuff_values)
		return (*(p -> inner -> type -> stuff_values)) (c, id,
								p -> inner);
	return ISC_R_SUCCESS;
}


#endif /* defined (FAILOVER_PROTOCOL) */
