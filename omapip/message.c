/* message.c

   Subroutines for dealing with message objects. */

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

omapi_message_object_t *omapi_registered_messages;

isc_result_t omapi_message_new (omapi_object_t **o, char *name)
{
	omapi_message_object_t *m;
	isc_result_t status;

	m = malloc (sizeof *m);
	if (!m)
		return ISC_R_NOMEMORY;
	memset (m, 0, sizeof *m);
	m -> type = omapi_type_message;
	m -> refcnt = 1;

	status = omapi_object_reference (o, (omapi_object_t *)m, name);
	omapi_object_dereference ((omapi_object_t **)&m, name);
	return status;
}

isc_result_t omapi_message_set_value (omapi_object_t *h,
				      omapi_object_t *id,
				      omapi_data_string_t *name,
				      omapi_typed_data_t *value)
{
	omapi_message_object_t *m;
	isc_result_t status;

	if (h -> type != omapi_type_message)
		return ISC_R_INVALIDARG;
	m = (omapi_message_object_t *)h;

	/* Can't set authlen. */

	/* Can set authenticator, but the value must be typed data. */
	if (!omapi_ds_strcmp (name, "authenticator")) {
		if (m -> authenticator)
			omapi_typed_data_dereference
				(&m -> authenticator,
				 "omapi_message_set_value");
		omapi_typed_data_reference (&m -> authenticator,
					    value,
					    "omapi_message_set_value");
		return ISC_R_SUCCESS;

	/* Can set authid, but it has to be an integer. */
	} else if (!omapi_ds_strcmp (name, "authid")) {
		if (value -> type != omapi_datatype_int)
			return ISC_R_INVALIDARG;
		m -> authid = value -> u.integer;

	/* Can set op, but it has to be an integer. */
	} else if (!omapi_ds_strcmp (name, "op")) {
		if (value -> type != omapi_datatype_int)
			return ISC_R_INVALIDARG;
		m -> op = value -> u.integer;

	/* Handle also has to be an integer. */
	} else if (!omapi_ds_strcmp (name, "handle")) {
		if (value -> type != omapi_datatype_int)
			return ISC_R_INVALIDARG;
		m -> h = value -> u.integer;

	/* Transaction ID has to be an integer. */
	} else if (!omapi_ds_strcmp (name, "id")) {
		if (value -> type != omapi_datatype_int)
			return ISC_R_INVALIDARG;
		m -> id = value -> u.integer;

	/* Remote transaction ID has to be an integer. */
	} else if (!omapi_ds_strcmp (name, "rid")) {
		if (value -> type != omapi_datatype_int)
			return ISC_R_INVALIDARG;
		m -> rid = value -> u.integer;
	}

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> set_value) {
		status = ((*(h -> inner -> type -> set_value))
			  (h -> inner, id, name, value));
		if (status == ISC_R_SUCCESS)
			return status;
	}
			  
	return ISC_R_NOTFOUND;
}

isc_result_t omapi_message_get_value (omapi_object_t *h,
				      omapi_object_t *id,
				      omapi_data_string_t *name,
				      omapi_value_t **value)
{
	omapi_message_object_t *m;
	if (h -> type != omapi_type_message)
		return ISC_R_INVALIDARG;
	m = (omapi_message_object_t *)h;

	/* Look for values that are in the message data structure. */
	if (!omapi_ds_strcmp (name, "authlen"))
		return omapi_make_int_value (value, name, m -> authlen,
					     "omapi_message_get_value");
	else if (!omapi_ds_strcmp (name, "authenticator")) {
		if (m -> authenticator)
			return omapi_make_value (value,
						 name, m -> authenticator,
						 "omapi_message_get_value");
		else
			return ISC_R_NOTFOUND;
	} else if (!omapi_ds_strcmp (name, "authid")) {
		return omapi_make_int_value (value, name, m -> authid,
					     "omapi_message_get_value");
	} else if (!omapi_ds_strcmp (name, "op")) {
		return omapi_make_int_value (value, name, m -> op,
					     "omapi_message_get_value");
	} else if (!omapi_ds_strcmp (name, "handle")) {
		return omapi_make_int_value (value, name, m -> handle,
					     "omapi_message_get_value");
	} else if (!omapi_ds_strcmp (name, "id")) {
		return omapi_make_int_value (value, name, m -> id, 
					     "omapi_message_get_value");
	} else if (!omapi_ds_strcmp (name, "rid")) {
		return omapi_make_int_value (value, name, m -> rid,
					     "omapi_message_get_value");
	}

	/* See if there's an inner object that has the value. */
	if (h -> inner && h -> inner -> type -> get_value)
		return (*(h -> inner -> type -> get_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t omapi_message_destroy (omapi_object_t *h, char *name)
{
	int i;

	omapi_message_object_t *m;
	if (h -> type != omapi_type_message)
		return ISC_R_INVALIDARG;
	if (m -> authenticator) {
		omapi_typed_data_dereference (&m -> authenticator, name);
	}
	if (!m -> prev && omapi_registered_messages != m)
		omapi_message_unregister (h);
	if (m -> prev)
		omapi_object_dereference ((omapi_object_t **)&m -> prev, name);
	if (m -> next)
		omapi_object_dereference ((omapi_object_t **)&m -> next, name);
	if (m -> id_object)
		omapi_object_dereference ((omapi_object_t **)&m -> id_object,
					  name);
	if (m -> object)
		omapi_object_dereference ((omapi_object_t **)&m -> object,
					  name);
	return ISC_R_SUCCESS;
}

isc_result_t omapi_message_signal_handler (omapi_object_t *h,
					   char *name, va_list ap)
{
	if (h -> type != omapi_type_message)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> signal_handler)
		return (*(h -> inner -> type -> signal_handler)) (h -> inner,
								  name, ap);
	return ISC_R_NOTFOUND;
}

/* Write all the published values associated with the object through the
   specified connection. */

isc_result_t omapi_message_stuff_values (omapi_object_t *c,
					 omapi_object_t *id,
					 omapi_object_t *m)
{
	int i;

	if (m -> type != omapi_type_message)
		return ISC_R_INVALIDARG;

	if (m -> inner && m -> inner -> type -> stuff_values)
		return (*(m -> inner -> type -> stuff_values)) (c, id,
								m -> inner);
	return ISC_R_SUCCESS;
}

isc_result_t omapi_message_register (omapi_object_t *mo)
{
	omapi_message_object_t *m;

	if (mo -> type != omapi_type_message)
		return ISC_R_INVALIDARG;
	m = (omapi_message_object_t *)mo;
	
	/* Already registered? */
	if (m -> prev || m -> next || omapi_registered_messages == m)
		return ISC_R_INVALIDARG;

	if (omapi_registered_messages) {
		omapi_object_reference
			((omapi_object_t **)&m -> next,
			 (omapi_object_t *)omapi_registered_messages,
			 "omapi_message_register");
		omapi_object_reference
			((omapi_object_t **)&omapi_registered_messages -> prev,
			 (omapi_object_t *)m, "omapi_message_register");
		omapi_object_dereference
			((omapi_object_t **)&omapi_registered_messages,
			 "omapi_message_register");
	}
	omapi_object_reference
		((omapi_object_t **)&omapi_registered_messages,
		 (omapi_object_t *)m, "omapi_message_register");
	return ISC_R_SUCCESS;;
}

isc_result_t omapi_message_unregister (omapi_object_t *mo)
{
	omapi_message_object_t *m;
	omapi_message_object_t *n;

	if (mo -> type != omapi_type_message)
		return ISC_R_INVALIDARG;
	m = (omapi_message_object_t *)mo;
	
	/* Not registered? */
	if (!m -> prev && omapi_registered_messages != m)
		return ISC_R_INVALIDARG;

	n = (omapi_message_object_t *)0;
	if (m -> next) {
		omapi_object_reference ((omapi_object_t **)&n,
					(omapi_object_t *)m -> next,
					"omapi_message_unregister");
		omapi_object_dereference ((omapi_object_t **)&m -> next,
					  "omapi_message_unregister");
	}
	if (m -> prev) {
		omapi_message_object_t *tmp = (omapi_message_object_t *)0;
		omapi_object_reference ((omapi_object_t **)&tmp,
					(omapi_object_t *)m -> prev,
					"omapi_message_register");
		omapi_object_dereference ((omapi_object_t **)&m -> prev,
					  "omapi_message_unregister");
		if (tmp -> next)
			omapi_object_dereference
				((omapi_object_t **)&tmp -> next,
				 "omapi_message_unregister");
		if (n)
			omapi_object_reference
				((omapi_object_t **)&tmp -> next,
				 (omapi_object_t *)n,
				 "omapi_message_unregister");
		omapi_object_dereference ((omapi_object_t **)&tmp,
					  "omapi_message_unregister");
	} else {
		omapi_object_dereference
			((omapi_object_t **)&omapi_registered_messages,
			 "omapi_unregister_message");
		if (n)
			omapi_object_reference
				((omapi_object_t **)&omapi_registered_messages,
				 (omapi_object_t *)n,
				 "omapi_message_unregister");
	}
	if (n)
		omapi_object_dereference ((omapi_object_t **)&n,
					  "omapi_message_unregister");
	return ISC_R_SUCCESS;
}
