/* remote.c

   The dhcpctl remote object. */

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

#include <omapip/omapip_p.h>
#include "dhcpctl.h"

/* dhcpctl_new_object

   synchronous - creates a local handle for a host entry.
   returns nonzero status code if the local host entry couldn't
   be created
   stores handle to host through h if successful, and returns zero.
   object_type is a pointer to a NUL-terminated string containing
   the ascii name of the type of object being accessed - e.g., "host" */

dhcpctl_status dhcpctl_new_object (dhcpctl_handle *h,
				   dhcpctl_handle connection,
				   const char *object_type)
{
	dhcpctl_remote_object_t *m;
	omapi_object_t *g;
	isc_result_t status;

	m = malloc (sizeof *m);
	if (!m)
		return ISC_R_NOMEMORY;
	memset (m, 0, sizeof *m);
	m -> type = dhcpctl_remote_type;
	m -> refcnt = 1;

	g = (omapi_object_t *)0;
	status = omapi_generic_new (&g, "dhcpctl_new_object");
	if (status != ISC_R_SUCCESS) {
		free (m);
		return status;
	}
	status = omapi_object_reference (&m -> inner, g, "dhcpctl_new_object");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&m,
					  "dhcpctl_new_object");
		omapi_object_dereference (&g, "dhcpctl_new_object");
		return status;
	}
	status = omapi_object_reference (&g -> outer,
					 (omapi_object_t *)m,
					 "dhcpctl_new_object");

	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&m,
					  "dhcpctl_new_object");
		omapi_object_dereference (&g, "dhcpctl_new_object");
		return status;
	}

	status = omapi_typed_data_new (&m -> rtype,
				       omapi_datatype_string,
				       object_type, "dhcpctl_new_object");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&m,
					  "dhcpctl_new_object");
		omapi_object_dereference (&g, "dhcpctl_new_object");
		return status;
	}

	status = omapi_object_reference (h, (omapi_object_t *)m,
					 "dhcpctl_new_object");
	omapi_object_dereference ((omapi_object_t **)&m, "dhcpctl_new_object");
	omapi_object_dereference (&g, "dhcpctl_new_object");
	if (status != ISC_R_SUCCESS)
		return status;

	return status;
}

/* asynchronous - just queues the request
   returns nonzero status code if open couldn't be queued
   returns zero if open was queued
   h is a handle to an object created by dhcpctl_new_object
   connection is a connection to a DHCP server
   flags include:
     DHCPCTL_CREATE - if the object doesn't exist, create it
     DHCPCTL_UPDATE - update the object on the server using the
     		      attached parameters 
     DHCPCTL_EXCL - error if the object exists and DHCPCTL_CREATE
     		      was also specified */

dhcpctl_status dhcpctl_open_object (dhcpctl_handle h,
				    dhcpctl_handle connection,
				    int flags)
{
	isc_result_t status;
	omapi_object_t *message = (omapi_object_t *)0;
	dhcpctl_remote_object_t *remote;

	if (h -> type != dhcpctl_remote_type)
		return ISC_R_INVALIDARG;
	remote = (dhcpctl_remote_object_t *)h;

	status = omapi_message_new (&message, "dhcpctl_open_object");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_set_int_value (message, (omapi_object_t *)0,
				      "op", OMAPI_OP_OPEN);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}
	status = omapi_set_object_value (message, (omapi_object_t *)0,
					 "object", h);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}
	if (flags & DHCPCTL_CREATE) {
		status = omapi_set_boolean_value (message, (omapi_object_t *)0,
						  "create", 1);
		if (status != ISC_R_SUCCESS) {
			omapi_object_dereference (&message,
						  "dhcpctl_open_object");
			return status;
		}
	}
	if (flags & DHCPCTL_UPDATE) {
		status = omapi_set_boolean_value (message, (omapi_object_t *)0,
						  "update", 1);
		if (status != ISC_R_SUCCESS) {
			omapi_object_dereference (&message,
						  "dhcpctl_open_object");
			return status;
		}
	}
	if (flags & DHCPCTL_EXCL) {
		status = omapi_set_boolean_value (message, (omapi_object_t *)0,
						  "exclusive", 1);
		if (status != ISC_R_SUCCESS) {
			omapi_object_dereference (&message,
						  "dhcpctl_open_object");
			return status;
		}
	}

	if (remote -> rtype) {
		status = omapi_set_value_str (message, (omapi_object_t *)0,
					      "type", remote -> rtype);
		if (status != ISC_R_SUCCESS) {
			omapi_object_dereference (&message,
						  "dhcpctl_open_object");
			return status;
		}
	}

	status = omapi_message_register (message);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}
	return omapi_protocol_send_message (connection -> outer,
					    (omapi_object_t *)0,
					    message, (omapi_object_t *)0);
}

/* Callback methods (not meant to be called directly) */

isc_result_t dhcpctl_remote_set_value (omapi_object_t *h,
				       omapi_object_t *id,
				       omapi_data_string_t *name,
				       omapi_typed_data_t *value)
{
	dhcpctl_remote_object_t *ro;
	unsigned long rh;
	isc_result_t status;

	if (h -> type != dhcpctl_remote_type)
		return ISC_R_INVALIDARG;
	ro = (dhcpctl_remote_object_t *)h;

	if (!omapi_ds_strcmp (name, "remote-handle")) {
		status = omapi_get_int_value (&rh, value);
		if (status == ISC_R_SUCCESS)
			ro -> remote_handle = rh;
		return status;
	}

	if (h -> inner && h -> inner -> type -> set_value)
		return (*(h -> inner -> type -> set_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t dhcpctl_remote_get_value (omapi_object_t *h,
				       omapi_object_t *id,
				       omapi_data_string_t *name,
				       omapi_value_t **value)
{
	if (h -> type != dhcpctl_remote_type)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> get_value)
		return (*(h -> inner -> type -> get_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t dhcpctl_remote_signal_handler (omapi_object_t *o,
					    const char *name, va_list ap)
{
	dhcpctl_remote_object_t *p;
	omapi_typed_data_t *tv;

	if (o -> type != dhcpctl_remote_type)
		return ISC_R_INVALIDARG;
	p = (dhcpctl_remote_object_t *)o;

	if (!strcmp (name, "updated")) {
		p -> waitstatus = ISC_R_SUCCESS;
		return omapi_signal_in (o -> inner, "ready");
	}
	if (!strcmp (name, "status")) {
		p -> waitstatus = va_arg (ap, isc_result_t);
		if (p -> message)
			omapi_typed_data_dereference
				(&p -> message,
				 "dhcpctl_remote_signal_handler");
		tv = va_arg (ap, omapi_typed_data_t *);
		if (tv)
			omapi_typed_data_reference
				(&p -> message, tv,
				 "dhcpctl_remote_signal_handler");
		return omapi_signal_in (o -> inner, "ready");
	}

	if (p -> inner && p -> inner -> type -> signal_handler)
		return (*(p -> inner -> type -> signal_handler))
			(p -> inner, name, ap);

	return ISC_R_SUCCESS;
}

isc_result_t dhcpctl_remote_destroy (omapi_object_t *h, const char *name)
{
	dhcpctl_remote_object_t *p;
	if (h -> type != dhcpctl_remote_type)
		return ISC_R_INVALIDARG;
	p = (dhcpctl_remote_object_t *)h;
	if (p -> handle)
		omapi_object_dereference ((omapi_object_t **)&p -> handle,
					  name);
	return ISC_R_SUCCESS;
}

/* Write all the published values associated with the object through the
   specified connection. */

isc_result_t dhcpctl_remote_stuff_values (omapi_object_t *c,
					  omapi_object_t *id,
					  omapi_object_t *p)
{
	int i;

	if (p -> type != dhcpctl_remote_type)
		return ISC_R_INVALIDARG;

	if (p -> inner && p -> inner -> type -> stuff_values)
		return (*(p -> inner -> type -> stuff_values)) (c, id,
								p -> inner);
	return ISC_R_SUCCESS;
}

