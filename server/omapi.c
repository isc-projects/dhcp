/* omapi.c

   OMAPI object interfaces for the DHCP server. */

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

/* Many, many thanks to Brian Murrell and BCtel for this code - BCtel
   provided the funding that resulted in this code and the entire
   OMAPI support library being written, and Brian helped brainstorm
   and refine the requirements.  To the extent that this code is
   useful, you have Brian and BCtel to thank.  Any limitations in the
   code are a result of mistakes on my part.  -- Ted Lemon */

#ifndef lint
static char copyright[] =
"$Id: omapi.c,v 1.1 1999/09/08 01:36:05 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

omapi_object_type_t *dhcp_type_lease;
omapi_object_type_t *dhcp_type_group;
omapi_object_type_t *dhcp_type_host;
omapi_object_type_t *dhcp_type_pool;
omapi_object_type_t *dhcp_type_shared_network;
omapi_object_type_t *dhcp_type_subnet;
omapi_object_type_t *dhcp_type_class;

void dhcp_db_objects_setup ()
{
	isc_result_t status;

	status = omapi_object_type_register (&dhcp_type_lease,
					     "lease",
					     dhcp_lease_set_value,
					     dhcp_lease_get_value,
					     dhcp_lease_destroy,
					     dhcp_lease_signal_handler,
					     dhcp_lease_stuff_values,
					     dhcp_lease_lookup, 
					     dhcp_lease_create);
	if (status != ISC_R_SUCCESS)
		log_fatal ("Can't register lease object type: %s",
			   isc_result_totext (status));

	status = omapi_object_type_register (&dhcp_type_host,
					     "host",
					     dhcp_host_set_value,
					     dhcp_host_get_value,
					     dhcp_host_destroy,
					     dhcp_host_signal_handler,
					     dhcp_host_stuff_values,
					     dhcp_host_lookup, 
					     dhcp_host_create);
	if (status != ISC_R_SUCCESS)
		log_fatal ("Can't register host object type: %s",
			   isc_result_totext (status));

	status = omapi_object_type_register (&dhcp_type_pool,
					     "pool",
					     dhcp_pool_set_value,
					     dhcp_pool_get_value,
					     dhcp_pool_destroy,
					     dhcp_pool_signal_handler,
					     dhcp_pool_stuff_values,
					     dhcp_pool_lookup, 
					     dhcp_pool_create);
	if (status != ISC_R_SUCCESS)
		log_fatal ("Can't register pool object type: %s",
			   isc_result_totext (status));
}

isc_result_t dhcp_lease_set_value  (omapi_object_t *h,
				    omapi_object_t *id,
				    omapi_data_string_t *name,
				    omapi_typed_data_t *value)
{
	struct lease *lease;
	isc_result_t status;
	int foo;

	if (h -> type != omapi_type_message)
		return ISC_R_INVALIDARG;
	lease = (struct lease *)h;

	/* We're skipping a lot of things it might be interesting to
	   set - for now, we just make it possible to whack the abandoned
	   flag. */
	if (!omapi_ds_strcmp (name, "abandoned")) {
		int bar;

		if (value -> type == omapi_datatype_int)
			bar = value -> u.integer;
		else if (value -> type == omapi_datatype_data &&
			 value -> u.buffer.len == sizeof (int)) {
			memcpy (&bar, value -> u.buffer.value, sizeof bar);
			/* No need to byte-swap here. */
		} else
			return ISC_R_INVALIDARG;

		foo = lease -> flags;
		if (bar)
			lease -> flags |= ABANDONED_LEASE;
		else
			lease -> flags &= ~ABANDONED_LEASE;
		if (foo != lease -> flags)
			return ISC_R_SUCCESS;
		return ISC_R_UNCHANGED;
	}

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> set_value) {
		status = ((*(h -> inner -> type -> set_value))
			  (h -> inner, id, name, value));
		if (status == ISC_R_SUCCESS || status == ISC_R_UNCHANGED)
			return status;
	}
			  
	return ISC_R_NOTFOUND;
}


isc_result_t dhcp_lease_get_value (omapi_object_t *h, omapi_object_t *id,
				   omapi_data_string_t *name,
				   omapi_value_t **value)
{
	struct lease *lease;
	isc_result_t status;

	if (h -> type != dhcp_type_lease)
		return ISC_R_INVALIDARG;
	lease = (struct lease *)h;

	if (!omapi_ds_strcmp (name, "abandoned"))
		return omapi_make_int_value (value, name,
					     (lease -> flags &
					      ABANDONED_LEASE) ? 1 : 0,
					     "dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "bootpp"))
		return omapi_make_int_value (value, name,
					     (lease -> flags &
					      BOOTP_LEASE) ? 1 : 0,
					     "dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "ip-address"))
		return omapi_make_const_value (value, name,
					       lease -> ip_addr.iabuf,
					       lease -> ip_addr.len,
					       "dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "dhcp-client-identifier"))
		return omapi_make_const_value (value, name,
					       lease -> uid,
					       lease -> uid_len,
					       "dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "hostname"))
		return omapi_make_string_value (value, name,
						lease -> hostname,
						"dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "client-hostname"))
		return omapi_make_string_value (value, name,
						lease -> client_hostname,
						"dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "ddns-fwd-name"))
		return omapi_make_string_value (value, name,
						lease -> ddns_fwd_name,
						"dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "ddns-rev-name"))
		return omapi_make_string_value (value, name,
						lease -> ddns_rev_name,
						"dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "host"))
		return omapi_make_handle_value (value, name,
						((omapi_object_t *)
						 lease -> host),
						"dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "subnet"))
		return omapi_make_handle_value (value, name,
						((omapi_object_t *)
						 lease -> subnet),
						"dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "pool"))
		return omapi_make_handle_value (value, name,
						((omapi_object_t *)
						 lease -> pool),
						"dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "billing-class"))
		return omapi_make_handle_value (value, name,
						((omapi_object_t *)
						 lease -> billing_class),
						"dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "hardware-address"))
		return omapi_make_const_value (value, name,
					       lease -> hardware_addr.haddr,
					       lease -> hardware_addr.hlen,
					       "dhcp_lease_get_value");
	else if (!omapi_ds_strcmp (name, "hardware-type"))
		return omapi_make_int_value (value, name,
					     lease -> hardware_addr.htype,
					     "dhcp_lease_get_value");

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> get_value) {
		status = ((*(h -> inner -> type -> get_value))
			  (h -> inner, id, name, value));
		if (status == ISC_R_SUCCESS)
			return status;
	}
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_lease_destroy (omapi_object_t *h, char *name)
{
	struct lease *lease;
	isc_result_t status;

	if (h -> type != dhcp_type_lease)
		return ISC_R_INVALIDARG;
	lease = (struct lease *)h;

	uid_hash_delete (lease);
	hw_hash_delete (lease);
	if (lease -> billing_class)
		omapi_object_dereference
			((omapi_object_t **)&lease -> billing_class, name);
	if (lease -> uid && lease -> uid != &lease -> uid_buf [0]) {
		free (lease -> uid);
		lease -> uid = &lease -> uid_buf [0];
		lease -> uid_len = 0;
	}
	if (lease -> hostname) {
		free (lease -> hostname);
		lease -> hostname = (char *)0;
	}
	if (lease -> client_hostname) {
		free (lease -> client_hostname);
		lease -> hostname = (char *)0;
	}
	if (lease -> ddns_fwd_name) {
		free (lease -> ddns_fwd_name);
		lease -> ddns_fwd_name = (char *)0;
	}
	if (lease -> ddns_rev_name) {
		free (lease -> ddns_rev_name);
		lease -> ddns_rev_name = (char *)0;
	}
	if (lease -> host)
		omapi_object_dereference ((omapi_object_t **)&lease -> host,
					  name);
	if (lease -> subnet)
		omapi_object_dereference ((omapi_object_t **)&lease -> subnet,
					  name);
	if (lease -> pool)
		omapi_object_dereference ((omapi_object_t **)&lease -> pool,
					  name);
	if (lease -> on_expiry)
		executable_statement_dereference (&lease -> on_expiry, name);
	if (lease -> on_commit)
		executable_statement_dereference (&lease -> on_commit, name);
	if (lease -> on_release)
		executable_statement_dereference (&lease -> on_release, name);
	if (lease -> state) {
		data_string_forget (&lease -> state -> parameter_request_list,
				    name);
		free_lease_state (lease -> state, name);
		lease -> state = (struct lease_state *)0;

		cancel_timeout (lease_ping_timeout, lease);
		--outstanding_pings; /* XXX */
	}
	return ISC_R_SUCCESS;
}

isc_result_t dhcp_lease_signal_handler (omapi_object_t *h,
					char *name, va_list ap)
{
	struct lease *lease;
	isc_result_t status;

	if (h -> type != dhcp_type_lease)
		return ISC_R_INVALIDARG;
	lease = (struct lease *)h;

	if (!strcmp (name, "updated")) {
		if (!write_lease (lease))
			return ISC_R_IOERROR;
	}

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> get_value) {
		status = ((*(h -> inner -> type -> signal_handler))
			  (h -> inner, name, ap));
		if (status == ISC_R_SUCCESS)
			return status;
	}
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_lease_stuff_values (omapi_object_t *c,
				      omapi_object_t *id,
				      omapi_object_t *h)
{
	struct lease *lease;
	isc_result_t status;

	if (h -> type != dhcp_type_lease)
		return ISC_R_INVALIDARG;
	lease = (struct lease *)h;

	/* Write out all the values. */

	status = omapi_connection_put_name (c, "abandoned");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, sizeof (int));
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, (lease -> flags &
						  ABANDONED_LEASE) ? 1 : 0);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "bootpp");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, sizeof (int));
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, (lease -> flags &
						  BOOTP_LEASE) ? 1 : 0);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "ip-address");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, lease -> ip_addr.len);
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_copyin (c, lease -> ip_addr.iabuf,
					  lease -> ip_addr.len);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "dhcp-client-identifier");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, lease -> uid_len);
	if (status != ISC_R_SUCCESS)
		return status;
	if (lease -> uid_len) {
		status = omapi_connection_copyin (c, lease -> uid,
						  lease -> uid_len);
		if (status != ISC_R_SUCCESS)
			return status;
	}

	status = omapi_connection_put_name (c, "hostname");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_string (c, lease -> hostname);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "client-hostname");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_string (c, lease -> client_hostname);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "ddns-fwd-name");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_string (c, lease -> ddns_fwd_name);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "ddns-rev-name");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_string (c, lease -> ddns_rev_name);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "host");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_handle (c,
					      (omapi_object_t *)lease -> host);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "subnet");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_handle
		(c, (omapi_object_t *)lease -> subnet);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "pool");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_handle (c,
					      (omapi_object_t *)lease -> pool);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "billing-class");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_handle
		(c, (omapi_object_t *)lease -> billing_class);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "hardware-address");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, lease -> hardware_addr.hlen);
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_copyin (c, lease -> hardware_addr.haddr,
					  lease -> hardware_addr.hlen);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "hardware-type");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, sizeof (int));
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, lease -> hardware_addr.htype);
	if (status != ISC_R_SUCCESS)
		return status;

	/* Write out the inner object, if any. */
	if (h -> inner && h -> inner -> type -> stuff_values) {
		status = ((*(h -> inner -> type -> stuff_values))
			  (c, id, h -> inner));
		if (status == ISC_R_SUCCESS)
			return status;
	}

	return ISC_R_SUCCESS;
}

isc_result_t dhcp_lease_lookup (omapi_object_t **lp,
				omapi_object_t *id, omapi_object_t *ref)
{
	omapi_value_t *tv = (omapi_value_t *)0;
	isc_result_t status;
	struct lease *lease;

	/* First see if we were sent a handle. */
	status = omapi_get_value_str (ref, id, "handle", &tv);
	if (status == ISC_R_SUCCESS) {
		status = omapi_handle_td_lookup (lp, tv -> value);

		omapi_value_dereference (&tv, "dhcp_lease_lookup");
		if (status != ISC_R_SUCCESS)
			return status;

		/* Don't return the object if the type is wrong. */
		if ((*lp) -> type != dhcp_type_lease) {
			omapi_object_dereference (lp, "dhcp_lease_lookup");
			return ISC_R_INVALIDARG;
		}
	}

	/* Now look for an IP address. */
	status = omapi_get_value_str (ref, id, "handle", &tv);
	if (status == ISC_R_SUCCESS) {
		/* If we already have a value, flag an error - only one
		   key can be used for lookups at a time. */
		if (*lp) {
			omapi_object_dereference (lp, "dhcp_lease_lookup");
			omapi_value_dereference (&tv, "dhcp_lease_lookup");
			return ISC_R_INVALIDARG;
		}

		lease = ((struct lease *)
			 hash_lookup (lease_ip_addr_hash,
				      tv -> value -> u.buffer.value,
				      tv -> value -> u.buffer.len));

		omapi_value_dereference (&tv, "dhcp_lease_lookup");

		if (!lease)
			return ISC_R_NOTFOUND;

		/* XXX fix so that hash lookup itself creates
		   XXX the reference. */
		omapi_object_reference (lp, (omapi_object_t *)lease,
					"dhcp_lease_lookup");
	}

	/* Now look for a client identifier. */
	status = omapi_get_value_str (ref, id, "dhcp-client-identifier", &tv);
	if (status == ISC_R_SUCCESS) {
		if (*lp) {
			omapi_object_dereference (lp, "dhcp_lease_lookup");
			omapi_value_dereference (&tv, "dhcp_lease_lookup");
			return ISC_R_INVALIDARG;
		}

		lease = ((struct lease *)
			 hash_lookup (lease_uid_hash,
				      tv -> value -> u.buffer.value,
				      tv -> value -> u.buffer.len));
		omapi_value_dereference (&tv, "dhcp_lease_lookup");
			
		if (!lease)
			return ISC_R_NOTFOUND;
		if (lease -> n_uid)
			return ISC_R_MULTIPLE;

		/* XXX fix so that hash lookup itself creates
		   XXX the reference. */
		omapi_object_reference (lp, (omapi_object_t *)lease,
					"dhcp_lease_lookup");
	}

	/* Now look for a hardware address. */
	status = omapi_get_value_str (ref, id, "hardware-address", &tv);
	if (status == ISC_R_SUCCESS) {
		if (*lp) {
			omapi_object_dereference (lp, "dhcp_lease_lookup");
			omapi_value_dereference (&tv, "dhcp_lease_lookup");
			return ISC_R_INVALIDARG;
		}

		lease = ((struct lease *)
			 hash_lookup (lease_uid_hash,
				      tv -> value -> u.buffer.value,
				      tv -> value -> u.buffer.len));
		omapi_value_dereference (&tv, "dhcp_lease_lookup");
			
		if (!lease)
			return ISC_R_NOTFOUND;
		if (lease -> n_hw)
			return ISC_R_MULTIPLE;

		/* XXX fix so that hash lookup itself creates
		   XXX the reference. */
		omapi_object_reference (lp, (omapi_object_t *)lease,
					"dhcp_lease_lookup");
	}

	/* If we get to here without finding a lease, no valid key was
	   specified. */
	if (!*lp)
		return ISC_R_INVALIDARG;
	return ISC_R_SUCCESS;
}

isc_result_t dhcp_lease_create (omapi_object_t **lp,
				omapi_object_t *id)
{
	return ISC_R_NOTIMPLEMENTED;
}

#if 0
isc_result_t dhcp_group_set_value  (omapi_object_t *, omapi_object_t *,
				    omapi_data_string_t *,
				    omapi_typed_data_t *);
isc_result_t dhcp_group_get_value (omapi_object_t *, omapi_object_t *,
				   omapi_data_string_t *,
				   omapi_value_t **); 
isc_result_t dhcp_group_destroy (omapi_object_t *, char *);
isc_result_t dhcp_group_signal_handler (omapi_object_t *, char *, va_list);
isc_result_t dhcp_group_stuff_values (omapi_object_t *,
				      omapi_object_t *,
				      omapi_object_t *);
isc_result_t dhcp_group_lookup (omapi_object_t **,
				omapi_object_t *, omapi_object_t *);
#endif

isc_result_t dhcp_host_set_value  (omapi_object_t *h,
				    omapi_object_t *id,
				    omapi_data_string_t *name,
				    omapi_typed_data_t *value)
{
	struct host_decl *host;
	isc_result_t status;
	int foo;

	if (h -> type != omapi_type_message)
		return ISC_R_INVALIDARG;
	host = (struct host_decl *)h;

	/* XXX For now, we can only set these values on new host objects. 
	   XXX Soon, we need to be able to update host objects. */
	if (!omapi_ds_strcmp (name, "name")) {
		if (host -> name)
			return ISC_R_EXISTS;
		if (value -> type == omapi_datatype_data ||
		    value -> type == omapi_datatype_string) {
			host -> name = malloc (value -> u.buffer.len + 1);
			if (!host -> name)
				return ISC_R_NOMEMORY;
			memcpy (host -> name,
				value -> u.buffer.value,
				value -> u.buffer.len);
			host -> name [value -> u.buffer.len] = 0;
		} else
			return ISC_R_INVALIDARG;
		return ISC_R_SUCCESS;
	}

	if (!omapi_ds_strcmp (name, "hardware-address")) {
		if (host -> interface.hlen)
			return ISC_R_EXISTS;
		if (value -> type == omapi_datatype_data ||
		    value -> type == omapi_datatype_string) {
			if (value -> u.buffer.len >
			    sizeof host -> interface.haddr)
				return ISC_R_INVALIDARG;
			memcpy (host -> interface.haddr,
				value -> u.buffer.value,
				value -> u.buffer.len);
			host -> interface.hlen = value -> u.buffer.len;
		} else
			return ISC_R_INVALIDARG;
		return ISC_R_SUCCESS;
	}

	if (!omapi_ds_strcmp (name, "hardware-type")) {
		int type;
		if (value -> type == omapi_datatype_data &&
		    value -> u.buffer.len == sizeof type) {
			if (value -> u.buffer.len >
			    sizeof host -> interface.haddr)
				return ISC_R_INVALIDARG;
			memcpy (&type,
				value -> u.buffer.value,
				value -> u.buffer.len);
		} else if (value -> type == omapi_datatype_int)
			type = value -> u.integer;
		else
			return ISC_R_INVALIDARG;
		host -> interface.htype = type;
		return ISC_R_SUCCESS;
	}

	if (!omapi_ds_strcmp (name, "dhcp-client-identifier")) {
		if (host -> client_identifier.data)
			return ISC_R_EXISTS;
		if (value -> type == omapi_datatype_data ||
		    value -> type == omapi_datatype_string) {
			host -> client_identifier.len = value -> u.buffer.len;
			if (!buffer_allocate
			    (&host -> client_identifier.buffer,
			     host -> client_identifier.len,
			     "dhcp_host_set_value"))
				return ISC_R_NOMEMORY;
			host -> client_identifier.data =
				&host -> client_identifier.buffer -> data [0];
			memcpy (host -> client_identifier.data,
				value -> u.buffer.value,
				host -> client_identifier.len);
		} else
			return ISC_R_INVALIDARG;
		return ISC_R_SUCCESS;
	}

	if (!omapi_ds_strcmp (name, "ip-address")) {
		if (host -> fixed_addr)
			return ISC_R_EXISTS;
		if (value -> type == omapi_datatype_data ||
		    value -> type == omapi_datatype_string) {
			struct data_string ds;
			memset (&ds, 0, sizeof ds);
			ds.len = value -> u.buffer.len;
			if (!buffer_allocate (&ds.buffer, ds.len,
					      "dhcp_host_set_value"))
				return ISC_R_NOMEMORY;
			ds.data = (&host -> client_identifier.buffer ->
				   data [0]);
			memcpy (ds.data, value -> u.buffer.value, ds.len);
			if (!option_cache (&host -> fixed_addr,
					   &ds, (struct expression *)0,
					   (struct option *)0)) {
				data_string_forget (&ds,
						    "dhcp_host_set_value");
				return ISC_R_NOMEMORY;
			}
			data_string_forget (&ds, "dhcp_host_set_value");
		} else
			return ISC_R_INVALIDARG;
		return ISC_R_SUCCESS;
	}

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> set_value) {
		status = ((*(h -> inner -> type -> set_value))
			  (h -> inner, id, name, value));
		if (status == ISC_R_SUCCESS || status == ISC_R_UNCHANGED)
			return status;
	}
			  
	return ISC_R_NOTFOUND;
}


isc_result_t dhcp_host_get_value (omapi_object_t *h, omapi_object_t *id,
				   omapi_data_string_t *name,
				   omapi_value_t **value)
{
	struct host_decl *host;
	isc_result_t status;
	struct data_string ip_addrs;

	if (h -> type != dhcp_type_host)
		return ISC_R_INVALIDARG;
	host = (struct host_decl *)h;

	if (!omapi_ds_strcmp (name, "ip-addresses")) {
		memset (&ip_addrs, 0, sizeof ip_addrs);
		if (host -> fixed_addr &&
		    evaluate_option_cache (&ip_addrs, (struct packet *)0,
					   (struct lease *)0,
					   (struct option_state *)0,
					   (struct option_state *)0,
					   host -> fixed_addr)) {
			status = (omapi_make_const_value
				  (value, name, ip_addrs.data, ip_addrs.len,
				   "dhcp_host_get_value"));
			data_string_forget (&ip_addrs, "dhcp_host_get_value");
			return status;
		}
		return ISC_R_NOTFOUND;
	}

	if (!omapi_ds_strcmp (name, "dhcp-client-identifier")) {
		if (!host -> client_identifier.len)
			return ISC_R_NOTFOUND;
		return omapi_make_const_value (value, name,
					       host -> client_identifier.data,
					       host -> client_identifier.len,
					       "dhcp_host_get_value");
	}

	if (!omapi_ds_strcmp (name, "name"))
		return omapi_make_string_value (value, name, host -> name,
						"dhcp_host_get_value");

	if (!omapi_ds_strcmp (name, "hardware-address")) {
		if (!host -> interface.hlen)
			return ISC_R_NOTFOUND;
		return omapi_make_const_value (value, name,
					       host -> interface.haddr,
					       host -> interface.hlen,
					       "dhcp_host_get_value");
	}

	if (!omapi_ds_strcmp (name, "hardware-type")) {
		if (!host -> interface.hlen)
			return ISC_R_NOTFOUND;
		return omapi_make_int_value (value, name,
					     host -> interface.htype,
					     "dhcp_host_get_value");
	}

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> get_value) {
		status = ((*(h -> inner -> type -> get_value))
			  (h -> inner, id, name, value));
		if (status == ISC_R_SUCCESS)
			return status;
	}
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_host_destroy (omapi_object_t *h, char *name)
{
	struct host_decl *host;
	isc_result_t status;

	if (h -> type != dhcp_type_host)
		return ISC_R_INVALIDARG;
	host = (struct host_decl *)h;

	/* Currently, this is completely hopeless - have to complete
           reference counting support for server OMAPI objects. */

	return ISC_R_SUCCESS;
}

isc_result_t dhcp_host_signal_handler (omapi_object_t *h,
					char *name, va_list ap)
{
	struct host_decl *host;
	isc_result_t status;

	if (h -> type != dhcp_type_host)
		return ISC_R_INVALIDARG;
	host = (struct host_decl *)h;

	if (!strcmp (name, "updated")) {
		if (!host -> name) {
			char hnbuf [64];
			sprintf (hnbuf, "nh%08lx%08x",
				 cur_time, (u_int32_t)host);
			host -> name = malloc (strlen (hnbuf) + 1);
			if (!host -> name)
				return ISC_R_NOMEMORY;
			strcpy (host -> name, hnbuf);
		}
		enter_host (host, 1);
		if (!write_host (host))
			return ISC_R_IOERROR;
	}

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> get_value) {
		status = ((*(h -> inner -> type -> signal_handler))
			  (h -> inner, name, ap));
		if (status == ISC_R_SUCCESS)
			return status;
	}
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_host_stuff_values (omapi_object_t *c,
				      omapi_object_t *id,
				      omapi_object_t *h)
{
	struct host_decl *host;
	isc_result_t status;
	struct data_string ip_addrs;

	if (h -> type != dhcp_type_host)
		return ISC_R_INVALIDARG;
	host = (struct host_decl *)h;

	/* Write out all the values. */

	memset (&ip_addrs, 0, sizeof ip_addrs);
	if (host -> fixed_addr &&
	    evaluate_option_cache (&ip_addrs, (struct packet *)0,
				   (struct lease *)0,
				   (struct option_state *)0,
				   (struct option_state *)0,
				   host -> fixed_addr)) {
		status = omapi_connection_put_name (c, "ip-address");
		if (status != ISC_R_SUCCESS)
			return status;
		status = omapi_connection_put_uint32 (c, ip_addrs.len);
		if (status != ISC_R_SUCCESS)
			return status;
		status = omapi_connection_copyin (c,
						  ip_addrs.data, ip_addrs.len);
		if (status != ISC_R_SUCCESS)
			return status;
	}

	if (host -> client_identifier.len) {
		status = omapi_connection_put_name (c,
						    "dhcp-client-identifier");
		if (status != ISC_R_SUCCESS)
			return status;
		status = (omapi_connection_put_uint32
			  (c, host -> client_identifier.len));
		if (status != ISC_R_SUCCESS)
			return status;
	}

	status = omapi_connection_put_name (c, "name");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_string (c, host -> name);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "hardware-address");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, host -> interface.hlen);
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_copyin (c, host -> interface.haddr,
					  host -> interface.hlen);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_connection_put_name (c, "hardware-type");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, sizeof (int));
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_connection_put_uint32 (c, host -> interface.htype);
	if (status != ISC_R_SUCCESS)
		return status;

	/* Write out the inner object, if any. */
	if (h -> inner && h -> inner -> type -> stuff_values) {
		status = ((*(h -> inner -> type -> stuff_values))
			  (c, id, h -> inner));
		if (status == ISC_R_SUCCESS)
			return status;
	}

	return ISC_R_SUCCESS;
}

isc_result_t dhcp_host_lookup (omapi_object_t **lp,
				omapi_object_t *id, omapi_object_t *ref)
{
	omapi_value_t *tv = (omapi_value_t *)0;
	isc_result_t status;
	struct host_decl *host;

	/* First see if we were sent a handle. */
	status = omapi_get_value_str (ref, id, "handle", &tv);
	if (status == ISC_R_SUCCESS) {
		status = omapi_handle_td_lookup (lp, tv -> value);

		omapi_value_dereference (&tv, "dhcp_host_lookup");
		if (status != ISC_R_SUCCESS)
			return status;

		/* Don't return the object if the type is wrong. */
		if ((*lp) -> type != dhcp_type_host) {
			omapi_object_dereference (lp, "dhcp_host_lookup");
			return ISC_R_INVALIDARG;
		}
	}

	/* Now look for a client identifier. */
	status = omapi_get_value_str (ref, id, "dhcp-client-identifier", &tv);
	if (status == ISC_R_SUCCESS) {
		if (*lp) {
			omapi_object_dereference (lp, "dhcp_host_lookup");
			omapi_value_dereference (&tv, "dhcp_host_lookup");
			return ISC_R_INVALIDARG;
		}

		host = ((struct host_decl *)
			 hash_lookup (host_uid_hash,
				      tv -> value -> u.buffer.value,
				      tv -> value -> u.buffer.len));
		omapi_value_dereference (&tv, "dhcp_host_lookup");
			
		if (!host)
			return ISC_R_NOTFOUND;

		/* XXX fix so that hash lookup itself creates
		   XXX the reference. */
		omapi_object_reference (lp, (omapi_object_t *)host,
					"dhcp_host_lookup");
	}

	/* Now look for a hardware address. */
	status = omapi_get_value_str (ref, id, "hardware-address", &tv);
	if (status == ISC_R_SUCCESS) {
		if (*lp) {
			omapi_object_dereference (lp, "dhcp_host_lookup");
			omapi_value_dereference (&tv, "dhcp_host_lookup");
			return ISC_R_INVALIDARG;
		}

		host = ((struct host_decl *)
			 hash_lookup (host_hw_addr_hash,
				      tv -> value -> u.buffer.value,
				      tv -> value -> u.buffer.len));
		omapi_value_dereference (&tv, "dhcp_host_lookup");
			
		if (!host)
			return ISC_R_NOTFOUND;

		/* XXX fix so that hash lookup itself creates
		   XXX the reference. */
		omapi_object_reference (lp, (omapi_object_t *)host,
					"dhcp_host_lookup");
	}

	/* If we get to here without finding a host, no valid key was
	   specified. */
	if (!*lp)
		return ISC_R_INVALIDARG;
	return ISC_R_SUCCESS;
}

isc_result_t dhcp_host_create (omapi_object_t **lp,
			       omapi_object_t *id)
{
	struct host_decl *hp;
	hp = (struct host_decl *)dmalloc (sizeof (struct host_decl),
					  "dhcp_host_create");
	if (!hp)
		return ISC_R_NOMEMORY;
	memset (hp, 0, sizeof *hp);
	hp -> refcnt = 0;
	return omapi_object_reference (lp, (omapi_object_t *)hp,
				       "dhcp_host_create");
}

isc_result_t dhcp_pool_set_value  (omapi_object_t *h,
				    omapi_object_t *id,
				    omapi_data_string_t *name,
				    omapi_typed_data_t *value)
{
	struct pool *pool;
	isc_result_t status;
	int foo;

	if (h -> type != omapi_type_message)
		return ISC_R_INVALIDARG;
	pool = (struct pool *)h;

	/* No values to set yet. */

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> set_value) {
		status = ((*(h -> inner -> type -> set_value))
			  (h -> inner, id, name, value));
		if (status == ISC_R_SUCCESS || status == ISC_R_UNCHANGED)
			return status;
	}
			  
	return ISC_R_NOTFOUND;
}


isc_result_t dhcp_pool_get_value (omapi_object_t *h, omapi_object_t *id,
				   omapi_data_string_t *name,
				   omapi_value_t **value)
{
	struct pool *pool;
	isc_result_t status;

	if (h -> type != dhcp_type_pool)
		return ISC_R_INVALIDARG;
	pool = (struct pool *)h;

	/* No values to get yet. */

	/* Try to find some inner object that can provide the value. */
	if (h -> inner && h -> inner -> type -> get_value) {
		status = ((*(h -> inner -> type -> get_value))
			  (h -> inner, id, name, value));
		if (status == ISC_R_SUCCESS)
			return status;
	}
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_pool_destroy (omapi_object_t *h, char *name)
{
	struct pool *pool;
	isc_result_t status;

	if (h -> type != dhcp_type_pool)
		return ISC_R_INVALIDARG;
	pool = (struct pool *)h;

	/* Can't destroy pools yet. */

	return ISC_R_SUCCESS;
}

isc_result_t dhcp_pool_signal_handler (omapi_object_t *h,
					char *name, va_list ap)
{
	struct pool *pool;
	isc_result_t status;

	if (h -> type != dhcp_type_pool)
		return ISC_R_INVALIDARG;
	pool = (struct pool *)h;

	/* Can't write pools yet. */

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> get_value) {
		status = ((*(h -> inner -> type -> signal_handler))
			  (h -> inner, name, ap));
		if (status == ISC_R_SUCCESS)
			return status;
	}
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_pool_stuff_values (omapi_object_t *c,
				      omapi_object_t *id,
				      omapi_object_t *h)
{
	struct pool *pool;
	isc_result_t status;

	if (h -> type != dhcp_type_pool)
		return ISC_R_INVALIDARG;
	pool = (struct pool *)h;

	/* Can't stuff pool values yet. */

	/* Write out the inner object, if any. */
	if (h -> inner && h -> inner -> type -> stuff_values) {
		status = ((*(h -> inner -> type -> stuff_values))
			  (c, id, h -> inner));
		if (status == ISC_R_SUCCESS)
			return status;
	}

	return ISC_R_SUCCESS;
}

isc_result_t dhcp_pool_lookup (omapi_object_t **lp,
				omapi_object_t *id, omapi_object_t *ref)
{
	omapi_value_t *tv = (omapi_value_t *)0;
	isc_result_t status;
	struct pool *pool;

	/* Can't look up pools yet. */

	/* If we get to here without finding a pool, no valid key was
	   specified. */
	if (!*lp)
		return ISC_R_INVALIDARG;
	return ISC_R_SUCCESS;
}

isc_result_t dhcp_pool_create (omapi_object_t **lp,
				omapi_object_t *id)
{
	return ISC_R_NOTIMPLEMENTED;
}

