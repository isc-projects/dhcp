/* support.c

   Subroutines providing general support for objects. */

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

#include <omapip/omapip.h>

omapi_object_type_t *omapi_type_connection;
omapi_object_type_t *omapi_type_listener;
omapi_object_type_t *omapi_type_io_object;
omapi_object_type_t *omapi_type_datagram;
omapi_object_type_t *omapi_type_generic;
omapi_object_type_t *omapi_type_protocol;
omapi_object_type_t *omapi_type_protocol_listener;
omapi_object_type_t *omapi_type_waiter;
omapi_object_type_t *omapi_type_remote;
omapi_object_type_t *omapi_type_message;

omapi_object_type_t *omapi_object_types;
int omapi_object_type_count;
static int ot_max;

isc_result_t omapi_init (void)
{
	isc_result_t status;

	/* Register all the standard object types... */
	status = omapi_object_type_register (&omapi_type_connection,
					     "connection",
					     omapi_connection_set_value,
					     omapi_connection_get_value,
					     omapi_connection_destroy,
					     omapi_connection_signal_handler,
					     omapi_connection_stuff_values);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_object_type_register (&omapi_type_listener,
					     "listener",
					     omapi_listener_set_value,
					     omapi_listener_get_value,
					     omapi_listener_destroy,
					     omapi_listener_signal_handler,
					     omapi_listener_stuff_values);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_object_type_register (&omapi_type_io_object,
					     "io",
					     omapi_io_set_value,
					     omapi_io_get_value,
					     omapi_io_destroy,
					     omapi_io_signal_handler,
					     omapi_io_stuff_values);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_object_type_register (&omapi_type_generic,
					     "generic",
					     omapi_generic_set_value,
					     omapi_generic_get_value,
					     omapi_generic_destroy,
					     omapi_generic_signal_handler,
					     omapi_generic_stuff_values);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_object_type_register (&omapi_type_protocol,
					     "protocol",
					     omapi_protocol_set_value,
					     omapi_protocol_get_value,
					     omapi_protocol_destroy,
					     omapi_protocol_signal_handler,
					     omapi_protocol_stuff_values);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_object_type_register (&omapi_type_protocol_listener,
					     "protocol-listener",
					     omapi_protocol_listener_set_value,
					     omapi_protocol_listener_get_value,
					     omapi_protocol_listener_destroy,
					     omapi_protocol_listener_signal,
					     omapi_protocol_listener_stuff);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_object_type_register (&omapi_type_message,
					     "message",
					     omapi_message_set_value,
					     omapi_message_get_value,
					     omapi_message_destroy,
					     omapi_message_signal_handler,
					     omapi_message_stuff_values);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_object_type_register (&omapi_type_waiter,
					     "waiter",
					     0,
					     0,
					     0,
					     omapi_waiter_signal_handler, 0);
	if (status != ISC_R_SUCCESS)
		return status;

	/* This seems silly, but leave it. */
	return ISC_R_SUCCESS;
}

isc_result_t omapi_object_type_register (omapi_object_type_t **type,
					 char *name,
					 isc_result_t (*set_value)
						 (omapi_object_t *,
						  omapi_object_t *,
						  omapi_data_string_t *,
						  omapi_typed_data_t *),
					 isc_result_t (*get_value)
						(omapi_object_t *,
						 omapi_object_t *,
						 omapi_data_string_t *,
						 omapi_value_t **),
					 isc_result_t (*destroy)
						(omapi_object_t *, char *),
					 isc_result_t (*signal_handler)
						 (omapi_object_t *,
						  char *, va_list),
					 isc_result_t (*stuff_values)
						(omapi_object_t *,
						 omapi_object_t *,
						 omapi_object_t *))
{
	omapi_object_type_t *t;

	if (!omapi_object_types) {
		ot_max = 10;
		omapi_object_types = malloc (ot_max *
					     sizeof *omapi_object_types);
		if (!omapi_object_types)
			return ISC_R_NOMEMORY;
		memset (omapi_object_types, 0, (ot_max *
						sizeof *omapi_object_types));
	} else if (omapi_object_type_count == ot_max) {
		t = malloc (2 *ot_max * sizeof *t);
		if (!t)
			return ISC_R_NOMEMORY;
		memcpy (t, omapi_object_types, ot_max *sizeof *t);
		memset (t + ot_max, 0, ot_max * sizeof *t);
		free (omapi_object_types);
		omapi_object_types = t;
	}
	omapi_object_types [omapi_object_type_count].name = name;
	omapi_object_types [omapi_object_type_count].set_value = set_value;
	omapi_object_types [omapi_object_type_count].get_value = get_value;
	omapi_object_types [omapi_object_type_count].destroy = destroy;
	omapi_object_types [omapi_object_type_count].signal_handler =
		signal_handler;
	omapi_object_types [omapi_object_type_count].stuff_values =
		stuff_values;
	if (type)
		*type = &omapi_object_types [omapi_object_type_count];
	omapi_object_type_count++;
	return ISC_R_SUCCESS;
}

isc_result_t omapi_signal (omapi_object_t *handle, char *name, ...)
{
	va_list ap;
	omapi_object_t *outer;
	isc_result_t status;

	va_start (ap, name);
	for (outer = handle; outer -> outer; outer = outer -> outer)
		;
	if (outer -> type -> signal_handler)
		status = (*(outer -> type -> signal_handler)) (outer,
							       name, ap);
	else
		status = ISC_R_NOTFOUND;
	va_end (ap);
	return status;
}

isc_result_t omapi_signal_in (omapi_object_t *handle, char *name, ...)
{
	va_list ap;
	omapi_object_t *outer;
	isc_result_t status;

	if (!handle)
		return ISC_R_NOTFOUND;
	va_start (ap, name);

	if (handle -> type -> signal_handler)
		status = (*(handle -> type -> signal_handler)) (handle,
								name, ap);
	else
		status = ISC_R_NOTFOUND;
	va_end (ap);
	return status;
}

isc_result_t omapi_set_value (omapi_object_t *h,
			      omapi_object_t *id,
			      omapi_data_string_t *name,
			      omapi_typed_data_t *value)
{
	omapi_object_t *outer;

	for (outer = h; outer -> outer; outer = outer -> outer)
		;
	if (outer -> type -> set_value)
		return (*(outer -> type -> set_value)) (outer,
							id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t omapi_get_value (omapi_object_t *h,
			      omapi_object_t *id,
			      omapi_data_string_t *name,
			      omapi_value_t **value)
{
	omapi_object_t *outer;

	for (outer = h; outer -> outer; outer = outer -> outer)
		;
	if (outer -> type -> get_value)
		return (*(outer -> type -> get_value)) (outer,
							id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t omapi_stuff_values (omapi_object_t *c,
				 omapi_object_t *id,
				 omapi_object_t *o)
{
	omapi_object_t *outer;

	for (outer = o; outer -> outer; outer = outer -> outer)
		;
	if (outer -> type -> stuff_values)
		return (*(outer -> type -> stuff_values)) (c, id, outer);
	return ISC_R_NOTFOUND;
}

int omapi_data_string_cmp (omapi_data_string_t *s1, omapi_data_string_t *s2)
{
	int len;
	int rv;

	if (s1 -> len > s2 -> len)
		len = s2 -> len;
	else
		len = s1 -> len;
	rv = memcmp (s1 -> value, s2 -> value, len);
	if (rv)
		return rv;
	if (s1 -> len > s2 -> len)
		return 1;
	else if (s1 -> len < s2 -> len)
		return -1;
	return 0;
}

int omapi_ds_strcmp (omapi_data_string_t *s1, char *s2)
{
	int len, slen;
	int rv;

	slen = strlen (s2);
	if (slen > s1 -> len)
		len = s1 -> len;
	else
		len = slen;
	rv = memcmp (s1 -> value, s2, len);
	if (rv)
		return rv;
	if (s1 -> len > slen)
		return 1;
	else if (s1 -> len < slen)
		return -1;
	return 0;
}

isc_result_t omapi_make_value (omapi_value_t **vp, omapi_data_string_t *name,
			       omapi_typed_data_t *value, char *caller)
{
	isc_result_t status;

	status = omapi_value_new (vp, caller);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_data_string_reference (&(*vp) -> name, name, caller);
	if (status != ISC_R_SUCCESS) {
		omapi_value_dereference (vp, caller);
		return status;
	}
	if (value) {
		status = omapi_typed_data_reference (&(*vp) -> value,
						     value, caller);
		if (status != ISC_R_SUCCESS) {
			omapi_value_dereference (vp, caller);
			return status;
		}
	}
	return ISC_R_SUCCESS;
}

isc_result_t omapi_make_const_value (omapi_value_t **vp,
				     omapi_data_string_t *name,
				     u_int8_t *value, int len, char *caller)
{
	isc_result_t status;

	status = omapi_value_new (vp, caller);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_data_string_reference (&(*vp) -> name, name, caller);
	if (status != ISC_R_SUCCESS) {
		omapi_value_dereference (vp, caller);
		return status;
	}
	if (value) {
		status = omapi_typed_data_new (&(*vp) -> value,
					       omapi_datatype_data, len);
		if (status != ISC_R_SUCCESS) {
			omapi_value_dereference (vp, caller);
			return status;
		}
		memcpy ((*vp) -> value -> u.buffer.value, value, len);
	}
	return ISC_R_SUCCESS;
}

isc_result_t omapi_make_int_value (omapi_value_t **vp,
				   omapi_data_string_t *name,
				   int value, char *caller)
{
	isc_result_t status;

	status = omapi_value_new (vp, caller);
	if (status != ISC_R_SUCCESS)
		return status;

	status = omapi_data_string_reference (&(*vp) -> name, name, caller);
	if (status != ISC_R_SUCCESS) {
		omapi_value_dereference (vp, caller);
		return status;
	}
	if (value) {
		status = omapi_typed_data_new (&(*vp) -> value,
					       omapi_datatype_int);
		if (status != ISC_R_SUCCESS) {
			omapi_value_dereference (vp, caller);
			return status;
		}
		(*vp) -> value -> u.integer = value;
	}
	return ISC_R_SUCCESS;
}

