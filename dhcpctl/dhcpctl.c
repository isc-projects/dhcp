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
				    dhcpctl_callback_stuff_values);
	return ISC_R_SUCCESS;
}

/* Callback methods (not meant to be called directly) */

isc_result_t dhcpctl_callback_set_value (omapi_object_t *h,
					 omapi_object_t *id,
					 omapi_data_string_t *name,
					 omapi_typed_data_t *value)
{
	if (h -> type != dhcpctl_callback_type)
		return ISC_R_INVALIDARG;

	if (h -> inner && h -> inner -> type -> set_value)
		return (*(h -> inner -> type -> set_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t dhcpctl_callback_get_value (omapi_object_t *h,
				       omapi_object_t *id,
				       omapi_data_string_t *name,
				       omapi_value_t **value)
{
	if (h -> type != dhcpctl_callback_type)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> get_value)
		return (*(h -> inner -> type -> get_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t omapi_callback_signal_handler (omapi_object_t *o,
					    char *name, va_list ap)
{
	dhcpctl_callback_object_t *p;
	if (o -> type != dhcpctl_callback_type)
		return ISC_R_INVALIDARG;
	p = (dhcpctl_callback_object_t *)o;

	/* Not a signal we recognize? */
	if (strcmp (name, "ready")) {
		if (p -> inner && p -> inner -> type -> signal_handler)
			return (*(p -> inner -> type -> signal_handler))
				(p -> inner, name, ap);
		return ISC_R_NOTFOUND;
	}

	/* Do the callback. */
	if (p -> callback)
		(*(p -> callback)) (p -> object, 0, p -> data);

	return ISC_R_SUCCESS;
}

isc_result_t dhcpctl_callback_destroy (omapi_object_t *h, char *name)
{
	dhcpctl_callback_object_t *p;
	if (h -> type != dhcpctl_callback_type)
		return ISC_R_INVALIDARG;
	p = (dhcpctl_callback_object_t *)h;
	if (p -> handle)
		omapi_object_dereference ((omapi_object_t **)&p -> handle,
					  name);
	return ISC_R_SUCCESS;
}

/* Write all the published values associated with the object through the
   specified connection. */

isc_result_t dhcpctl_callback_stuff_values (omapi_object_t *c,
					  omapi_object_t *id,
					  omapi_object_t *p)
{
	int i;

	if (p -> type != dhcpctl_callback_type)
		return ISC_R_INVALIDARG;

	if (p -> inner && p -> inner -> type -> stuff_values)
		return (*(p -> inner -> type -> stuff_values)) (c, id,
								p -> inner);
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
				char *server_name, int port,
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
		omapi_handle_dereference (connection, "dhcpctl_connect");
		return status;
	}

	status = omapi_wait_for_completion (*connection, 0);
	if (status != ISC_R_SUCCESS) {
		omapi_handle_dereference (connection, "dhcpctl_connect");
		return status;
	}

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

	status = omapi_message_new (&message, "dhcpctl_open_object");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}
	status = omapi_set_int_value (message, "op", OMAPI_OP_OPEN);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}
	status = omapi_set_object_value (message, "object", h);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}
	if (flags & DHCPCTL_CREATE) {
		status = omapi_set_boolean_value (message, "create", 1);
		if (status != ISC_R_SUCCESS) {
			omapi_object_dereference (&message,
						  "dhcpctl_open_object");
			return status;
		}
	}
	if (flags & DHCPCTL_UPDATE) {
		status = omapi_set_boolean_value (message, "update", 1);
		if (status != ISC_R_SUCCESS) {
			omapi_object_dereference (&message,
						  "dhcpctl_open_object");
			return status;
		}
	}
	if (flags & DHCPCTL_EXCL) {
		status = omapi_set_boolean_value (message, "exclusive", 1);
		if (status != ISC_R_SUCCESS) {
			omapi_object_dereference (&message,
						  "dhcpctl_open_object");
			return status;
		}
	}

	omapi_message_register (message);
	return omapi_protocol_send_message (connection -> outer,
					    (omapi_object_t *)0,
					    message, (omapi_object_t *)0);
}

/* dhcpctl_new_object

   synchronous - creates a local handle for a host entry.
   returns nonzero status code if the local host entry couldn't
   be created
   stores handle to host through h if successful, and returns zero.
   object_type is a pointer to a NUL-terminated string containing
   the ascii name of the type of object being accessed - e.g., "host" */

dhcpctl_status dhcpctl_new_object (dhcpctl_handle *h,
				   dhcpctl_handle connection,
				   char *object_type)
{
	isc_result_t status;

	status = omapi_generic_object_new (h, "dhcpctl_new_object");
	if (status != ISC_R_SUCCESS)
		return status;
	status = omapi_set_string_value (h, object_type);
	if (status != ISC_R_SUCCESS)
		omapi_object_dereference (h, "dhcpctl_new_object");
	return status;
}

/* dhcpctl_set_callback

   synchronous, with asynchronous aftereffect
   handle is some object upon which some kind of process has been
   started - e.g., an open, an update or a refresh.
   data is an anonymous pointer containing some information that
   the callback will use to figure out what event completed.
   return value of 0 means callback was successfully set, a nonzero
   status code is returned otherwise.
   Upon completion of whatever task is in process, the callback
   will be passed the handle to the object, a status code
   indicating what happened, and the anonymous pointer passed to  */

dhcpctl_status dhcpctl_set_callback (dhcpctl_handle h, void *data,
				     void (*func) (dhcpctl_handle,
						   dhcpctl_status, void *))
{
	dhcpctl_callback_object_t *callback;
	omapi_object_t *inner;
	isc_result_t status;

	callback = malloc (sizeof *callback);
	if (!callback)
		return ISC_R_NOMEMORY;

	/* Tie the callback object to the innermost object in the chain. */
	for (inner = h; inner -> inner; inner = inner -> inner)
		;
	omapi_object_reference (&inner -> inner, (omapi_object_t *)callback,
				"dhcpctl_set_callback");
	omapi_object_reference ((omapi_object_t **)&callback -> outer, inner,
				"dhcpctl_set_callback");

	/* Save the actual handle pointer we were passed for the callback. */
	omapi_object_reference (&callback -> object, h,
				"dhcpctl_set_callback");
	callback -> data = data;
	callback -> callback = func;
	
	return ISC_R_SUCCESS;
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
	*s = 0;
	return omapi_wait_for_completion (h, 0);
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
				  dhcpctl_handle h, char *value_name)
{
	isc_result_t status;
	omapi_value_t *tv = (omapi_value_t *)0;
	omapi_data_string_t *name = (omapi_data_string_t *)0;
	omapi_data_string_t *value = (omapi_data_string_t *)0;
	int len;
	int ip;

	status = omapi_data_string_new (&name, strlen (value_name) + 1,
					"dhcpctl_get_value");
	if (status != ISC_R_SUCCESS)
		return status;
	strcpy (name -> value, value_name);

	status = omapi_get_value (h, (omapi_object_t *)0, name, &tv);
	if (status != ISC_R_SUCCESS) {
		omapi_data_string_dereference (&name, "dhcpctl_get_value");
		return status;
	}

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
		omapi_data_string_dereference (&name, "dhcpctl_get_value");
		omapi_typed_data_dereference (&tv -> value,
					      "dhcpctl_get_value");
		return ISC_R_UNEXPECTED;
	}

	status = omapi_data_string_new (result, len, "dhcpctl_get_value");
	if (status != ISC_R_SUCCESS) {
		omapi_data_string_dereference (&name, "dhcpctl_get_value");
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

	omapi_data_string_dereference (&name, "dhcpctl_get_value");
	omapi_value_dereference (&tv, "dhcpctl_get_value");
	return ISC_R_SUCCESS;
}

/* dhcpctl_get_boolean

   like dhcpctl_get_value, but more convenient for boolean
   values, since no data_string needs to be dealt with. */

dhcpctl_status dhcpctl_get_boolean (int *result,
				    dhcpctl_handle h, char *value_name)
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
				  char *value_name)
{
	isc_result_t status;
	omapi_typed_data_t *tv = (omapi_typed_data_t *)0;
	omapi_data_string_t *name = (omapi_data_string_t *)0;
	int len;
	int ip;

	status = omapi_data_string_new (&name, strlen (value_name) + 1,
					"dhcpctl_set_value");
	if (status != ISC_R_SUCCESS)
		return status;
	strcpy (name -> value, value_name);

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

dhcpctl_status dhcpctl_set_string_value (dhcpctl_handle h, char *value,
					 char *value_name)
{
	isc_result_t status;
	omapi_typed_data_t *tv = (omapi_typed_data_t *)0;
	omapi_data_string_t *name = (omapi_data_string_t *)0;
	int len;
	int ip;

	status = omapi_data_string_new (&name, strlen (value_name) + 1,
					"dhcpctl_set_string_value");
	if (status != ISC_R_SUCCESS)
		return status;
	strcpy (name -> value, value_name);

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

/* dhcpctl_set_boolean

   Sets a boolean value on an object - like dhcpctl_set_value,
   only more convenient for booleans. */

dhcpctl_status dhcpctl_set_boolean (dhcpctl_handle h, int value,
				    char *value_name)
{
	isc_result_t status;
	omapi_typed_data_t *tv = (omapi_typed_data_t *)0;
	omapi_data_string_t *name = (omapi_data_string_t *)0;
	int len;
	int ip;

	status = omapi_data_string_new (&name, strlen (value_name) + 1,
					"dhcpctl_set_boolean_value");
	if (status != ISC_R_SUCCESS)
		return status;
	strcpy (name -> value, value_name);

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

	status = omapi_message_new (&message, "dhcpctl_open_object");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}
	status = omapi_set_int_value (message, "op", OMAPI_OP_UPDATE);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}
	status = omapi_set_object_value (message, "object", h);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
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

	status = omapi_message_new (&message, "dhcpctl_open_object");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}
	status = omapi_set_int_value (message, "op", OMAPI_OP_REFRESH);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}
	status = omapi_set_int_value (message, "handle", h -> handle);
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference (&message, "dhcpctl_open_object");
		return status;
	}

	omapi_message_register (message);
	status = omapi_protocol_send_message (connection -> outer,
					      (omapi_object_t *)0,
					      message, (omapi_object_t *)0);
	omapi_object_dereference (&message, "dhcpctl_object_update");
	return status;
}

