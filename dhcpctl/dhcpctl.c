/* dhcpctl.c

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

#include "dhcpctl.h"

omapi_object_type_t *dhcpctl_callback_type;
omapi_object_type_t *dhcpctl_remote_type;

/* dhcpctl_initialize ()

   Must be called before any other dhcpctl function. */

dhcpctl_status dhcpctl_initialize ()
{
	omapi_init();
	omapi_object_type_register (&dhcpctl_callback_type,
				    "dhcpctl-callback",
				    dhcpctl_callback_set_value,
				    dhcpctl_callback_get_value,
				    dhcpctl_callback_destroy,
				    dhcpctl_callback_signal_handler,
				    dhcpctl_callback_stuff_values, 0, 0, 0);
	omapi_object_type_register (&dhcpctl_remote_type,
				    "dhcpctl-remote",
				    dhcpctl_remote_set_value,
				    dhcpctl_remote_get_value,
				    dhcpctl_remote_destroy,
				    dhcpctl_remote_signal_handler,
				    dhcpctl_remote_stuff_values, 0, 0, 0);
	return ISC_R_SUCCESS;
}

/* dhcpctl_connect

   synchronous
   returns nonzero status code if it didn't connect, zero otherwise
   stores connection handle through connection, which can be used
   for subsequent access to the specified server. 
   server_name is the name of the server, and port is the TCP
   port on which it is listening.
   authinfo is the handle to an object containing authentication
   information. */

dhcpctl_status dhcpctl_connect (dhcpctl_handle *connection,
				const char *server_name, int port,
				dhcpctl_handle authinfo)
{
	isc_result_t status;

	status = omapi_generic_new (connection, "dhcpctl_connect");
	if (status != ISC_R_SUCCESS) {
		return status;
	}

	status = omapi_protocol_connect (*connection, server_name,
					 port, authinfo);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (connection, "dhcpctl_connect");
		return status;
	}

	status = omapi_wait_for_completion (*connection, 0);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (connection, "dhcpctl_connect");
		return status;
	}

	return status;
}

/* dhcpctl_wait_for_completion

   synchronous
   returns zero if the callback completes, a nonzero status if
   there was some problem relating to the wait operation.   The
   status of the queued request will be stored through s, and
   will also be either zero for success or nonzero for some kind
   of failure.    Never returns until completion or until the
   connection to the server is lost.   This performs the same
   function as dhcpctl_set_callback and the subsequent callback,
   for programs that want to do inline execution instead of using
   callbacks. */

dhcpctl_status dhcpctl_wait_for_completion (dhcpctl_handle h,
					    dhcpctl_status *s)
{
	isc_result_t status;
	status = omapi_wait_for_completion (h, 0);
	if (status != ISC_R_SUCCESS)
		return status;
	if (h -> type == dhcpctl_remote_type)
		*s = ((dhcpctl_remote_object_t *)h) -> waitstatus;
	return ISC_R_SUCCESS;
}

/* dhcpctl_get_value

   synchronous
   returns zero if the call succeeded, a nonzero status code if
   it didn't. 
   result is the address of an empty data string (initialized
   with bzero or cleared with data_string_forget).   On
   successful completion, the addressed data string will contain
   the value that was fetched.
   dhcpctl_handle refers to some dhcpctl item
   value_name refers to some value related to that item - e.g.,
   for a handle associated with a completed host lookup, value
   could be one of "hardware-address", "dhcp-client-identifier",
   "known" or "client-hostname". */

dhcpctl_status dhcpctl_get_value (dhcpctl_data_string *result,
				  dhcpctl_handle h, const char *value_name)
{
	isc_result_t status;
	omapi_value_t *tv = (omapi_value_t *)0;
	omapi_data_string_t *value = (omapi_data_string_t *)0;
	unsigned len;
	int ip;

	status = omapi_get_value_str (h, (omapi_object_t *)0, value_name, &tv);
	if (status != ISC_R_SUCCESS)
		return status;

	switch (tv -> value -> type) {
	      case omapi_datatype_int:
		len = sizeof (int);
		break;

	      case omapi_datatype_string:
	      case omapi_datatype_data:
		len = tv -> value -> u.buffer.len;
		break;

	      case omapi_datatype_object:
		len = sizeof (omapi_handle_t);
		break;

	      default:
		omapi_typed_data_dereference (&tv -> value,
					      "dhcpctl_get_value");
		return ISC_R_UNEXPECTED;
	}

	status = omapi_data_string_new (result, len, "dhcpctl_get_value");
	if (status != ISC_R_SUCCESS) {
		omapi_typed_data_dereference (&tv -> value,
					      "dhcpctl_get_value");
		return status;
	}

	switch (tv -> value -> type) {
	      case omapi_datatype_int:
		ip = htonl (tv -> value -> u.integer);
		memcpy ((*result) -> value, &ip, sizeof ip);
		break;

	      case omapi_datatype_string:
	      case omapi_datatype_data:
		memcpy ((*result) -> value,
			tv -> value -> u.buffer.value,
			tv -> value -> u.buffer.len);
		break;

	      case omapi_datatype_object:
		ip = htonl (tv -> value -> u.object -> handle);
		memcpy ((*result) -> value, &ip, sizeof ip);
		break;
	}

	omapi_value_dereference (&tv, "dhcpctl_get_value");
	return ISC_R_SUCCESS;
}

/* dhcpctl_get_boolean

   like dhcpctl_get_value, but more convenient for boolean
   values, since no data_string needs to be dealt with. */

dhcpctl_status dhcpctl_get_boolean (int *result,
				    dhcpctl_handle h, const char *value_name)
{
	isc_result_t status;
	dhcpctl_data_string data = (dhcpctl_data_string)0;
	int rv;
	
	status = dhcpctl_get_value (&data, h, value_name);
	if (status != ISC_R_SUCCESS)
		return status;
	if (data -> len != sizeof rv) {
		omapi_data_string_dereference (&data, "dhcpctl_get_boolean");
		return ISC_R_UNEXPECTED;
	}
	memcpy (&rv, data -> value, sizeof rv);
	*result = ntohl (rv);
	return ISC_R_SUCCESS;
}

/* dhcpctl_set_value

   Sets a value on an object referred to by a dhcpctl_handle.
   The opposite of dhcpctl_get_value.   Does not update the
   server - just sets the value on the handle. */

dhcpctl_status dhcpctl_set_value (dhcpctl_handle h, dhcpctl_data_string value,
				  const char *value_name)
{
	isc_result_t status;
	omapi_typed_data_t *tv = (omapi_typed_data_t *)0;
	omapi_data_string_t *name = (omapi_data_string_t *)0;
	int len;
	int ip;

	status = omapi_data_string_new (&name, strlen (value_name),
					"dhcpctl_set_value");
	if (status != ISC_R_SUCCESS)
		return status;
	memcpy (name -> value, value_name, strlen (value_name));

	status = omapi_typed_data_new (&tv, omapi_datatype_data,
				       value -> len);
	if (status != ISC_R_SUCCESS) {
		omapi_data_string_dereference (&name, "dhcpctl_set_value");
		return status;
	}
	memcpy (tv -> u.buffer.value, value -> value, value -> len);

	status = omapi_set_value (h, (omapi_object_t *)0, name, tv);
	omapi_data_string_dereference (&name, "dhcpctl_set_value");
	omapi_typed_data_dereference (&tv, "dhcpctl_set_value");
	return status;
}

/* dhcpctl_set_string_value

   Sets a NUL-terminated ASCII value on an object referred to by
   a dhcpctl_handle.   like dhcpctl_set_value, but saves the
   trouble of creating a data_string for a NUL-terminated string.
   Does not update the server - just sets the value on the handle. */

dhcpctl_status dhcpctl_set_string_value (dhcpctl_handle h, const char *value,
					 const char *value_name)
{
	isc_result_t status;
	omapi_typed_data_t *tv = (omapi_typed_data_t *)0;
	omapi_data_string_t *name = (omapi_data_string_t *)0;
	int len;
	int ip;

	status = omapi_data_string_new (&name, strlen (value_name),
					"dhcpctl_set_string_value");
	if (status != ISC_R_SUCCESS)
		return status;
	memcpy (name -> value, value_name, strlen (value_name));

	status = omapi_typed_data_new (&tv, omapi_datatype_string, value);
	if (status != ISC_R_SUCCESS) {
		omapi_data_string_dereference (&name,
					       "dhcpctl_set_string_value");
		return status;
	}

	status = omapi_set_value (h, (omapi_object_t *)0, name, tv);
	omapi_data_string_dereference (&name, "dhcpctl_set_string_value");
	omapi_typed_data_dereference (&tv, "dhcpctl_set_string_value");
	return status;
}

/* dhcpctl_set_boolean_value

   Sets a boolean value on an object - like dhcpctl_set_value,
   only more convenient for booleans. */

dhcpctl_status dhcpctl_set_boolean_value (dhcpctl_handle h, int value,
					  const char *value_name)
{
	isc_result_t status;
	omapi_typed_data_t *tv = (omapi_typed_data_t *)0;
	omapi_data_string_t *name = (omapi_data_string_t *)0;
	int len;
	int ip;

	status = omapi_data_string_new (&name, strlen (value_name),
					"dhcpctl_set_boolean_value");
	if (status != ISC_R_SUCCESS)
		return status;
	memcpy (name -> value, value_name, strlen (value_name));

	status = omapi_typed_data_new (&tv, omapi_datatype_int, value);
	if (status != ISC_R_SUCCESS) {
		omapi_data_string_dereference (&name,
					       "dhcpctl_set_boolean_value");
		return status;
	}

	status = omapi_set_value (h, (omapi_object_t *)0, name, tv);
	omapi_data_string_dereference (&name, "dhcpctl_set_boolean_value");
	omapi_typed_data_dereference (&tv, "dhcpctl_set_boolean_value");
	return status;
}

/* dhcpctl_set_int_value

   Sets a boolean value on an object - like dhcpctl_set_value,
   only more convenient for booleans. */

dhcpctl_status dhcpctl_set_int_value (dhcpctl_handle h, int value,
				      const char *value_name)
{
	isc_result_t status;
	omapi_typed_data_t *tv = (omapi_typed_data_t *)0;
	omapi_data_string_t *name = (omapi_data_string_t *)0;
	int len;
	int ip;

	status = omapi_data_string_new (&name, strlen (value_name),
					"dhcpctl_set_boolean_value");
	if (status != ISC_R_SUCCESS)
		return status;
	memcpy (name -> value, value_name, strlen (value_name));

	status = omapi_typed_data_new (&tv, omapi_datatype_int, value);
	if (status != ISC_R_SUCCESS) {
		omapi_data_string_dereference (&name,
					       "dhcpctl_set_boolean_value");
		return status;
	}

	status = omapi_set_value (h, (omapi_object_t *)0, name, tv);
	omapi_data_string_dereference (&name, "dhcpctl_set_boolean_value");
	omapi_typed_data_dereference (&tv, "dhcpctl_set_boolean_value");
	return status;
}

/* dhcpctl_object_update

   Queues an update on the object referenced by the handle (there
   can't be any other work in progress on the handle).   An
   update means local parameters will be sent to the server. */

dhcpctl_status dhcpctl_object_update (dhcpctl_handle connection,
				      dhcpctl_handle h)
{
	isc_result_t status;
	omapi_object_t *message = (omapi_object_t *)0;

	status = omapi_message_new (&message, "dhcpctl_object_update");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_object_update");
		return status;
	}
	status = omapi_set_int_value (message, (omapi_object_t *)0,
				      "op", OMAPI_OP_UPDATE);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_object_update");
		return status;
	}
	status = omapi_set_object_value (message, (omapi_object_t *)0,
					 "object", h);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_object_update");
		return status;
	}

	omapi_message_register (message);
	status = omapi_protocol_send_message (connection -> outer,
					      (omapi_object_t *)0,
					      message, (omapi_object_t *)0);
	omapi_object_dereference (&message, "dhcpctl_object_update");
	return status;
}

/* Requests a refresh on the object referenced by the handle (there
   can't be any other work in progress on the handle).   A
   refresh means local parameters are updated from the server. */

dhcpctl_status dhcpctl_object_refresh (dhcpctl_handle connection,
				       dhcpctl_handle h)
{
	isc_result_t status;
	omapi_object_t *message = (omapi_object_t *)0;

	status = omapi_message_new (&message, "dhcpctl_object_refresh");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_object_refresh");
		return status;
	}
	status = omapi_set_int_value (message, (omapi_object_t *)0,
				      "op", OMAPI_OP_REFRESH);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_object_refresh");
		return status;
	}
	status = omapi_set_int_value (message, (omapi_object_t *)0,
				      "handle", (int)(h -> handle));
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_object_refresh");
		return status;
	}

	omapi_message_register (message);
	status = omapi_protocol_send_message (connection -> outer,
					      (omapi_object_t *)0,
					      message, (omapi_object_t *)0);
	omapi_object_dereference (&message, "dhcpctl_object_update");
	return status;
}

/* Requests the removal of the object referenced by the handle (there
   can't be any other work in progress on the handle).   A
   removal means that all searchable references to the object on the
   server are deleted. */

dhcpctl_status dhcpctl_object_remove (dhcpctl_handle connection,
				      dhcpctl_handle h)
{
	isc_result_t status;
	omapi_object_t *message = (omapi_object_t *)0;
	dhcpctl_remote_object_t *ro;

	if (h -> type != dhcpctl_remote_type)
		return ISC_R_INVALIDARG;
	ro = (dhcpctl_remote_object_t *)h;

	status = omapi_message_new (&message, "dhcpctl_object_delete");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_object_delete");
		return status;
	}
	status = omapi_set_int_value (message, (omapi_object_t *)0,
				      "op", OMAPI_OP_DELETE);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_object_delete");
		return status;
	}

	status = omapi_set_int_value (message, (omapi_object_t *)0, "handle",
				      (int)(ro -> remote_handle));
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message,
					  "dhcpctl_object_delete");
		return status;
	}

	status = omapi_set_object_value (message, (omapi_object_t *)0,
					 "notify-object", h);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_object_delete");
		return status;
	}

	omapi_message_register (message);
	status = omapi_protocol_send_message (connection -> outer,
					      (omapi_object_t *)0,
					      message, (omapi_object_t *)0);
	omapi_object_dereference (&message, "dhcpctl_object_update");
	return status;
}

