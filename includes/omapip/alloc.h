/* alloc.h

   Definitions for the object management API protocol memory allocation... */

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

isc_result_t omapi_object_reference (omapi_object_t **,
				     omapi_object_t *, char *);
isc_result_t omapi_object_dereference (omapi_object_t **, char *);

isc_result_t omapi_buffer_new (omapi_buffer_t **, char *);
isc_result_t omapi_buffer_reference (omapi_buffer_t **,
				     omapi_buffer_t *, char *);
isc_result_t omapi_buffer_dereference (omapi_buffer_t **, char *);
isc_result_t omapi_typed_data_new (omapi_typed_data_t **,
				   omapi_datatype_t, ...);
isc_result_t omapi_typed_data_reference (omapi_typed_data_t **,
					 omapi_typed_data_t *, char *);
isc_result_t omapi_typed_data_dereference (omapi_typed_data_t **, char *);
isc_result_t omapi_data_string_new (omapi_data_string_t **, int, char *);
isc_result_t omapi_data_string_reference (omapi_data_string_t **,
					  omapi_data_string_t *, char *);
isc_result_t omapi_data_string_dereference (omapi_data_string_t **, char *);
isc_result_t omapi_value_new (omapi_value_t **, char *);
isc_result_t omapi_value_reference (omapi_value_t **,
				    omapi_value_t *, char *);
isc_result_t omapi_value_dereference (omapi_value_t **, char *);
