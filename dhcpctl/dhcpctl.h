/* dhcpctl.h

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

#ifndef _DHCPCTL_H_
#define _DHCPCTL_H_

#include <omapip/omapip.h>

typedef isc_result_t dhcpctl_status;
typedef omapi_object_t *dhcpctl_handle;
typedef omapi_data_string_t *dhcpctl_data_string;

#define DHCPCTL_CREATE		1
#define DHCPCTL_UPDATE		2
#define DHCPCTL_EXCL		4

typedef struct {
	OMAPI_OBJECT_PREAMBLE;
	omapi_object_t *object;
	void *data;
	void (*callback) (dhcpctl_handle, dhcpctl_status, void *);
} dhcpctl_callback_object_t;

typedef struct {
	OMAPI_OBJECT_PREAMBLE;
	omapi_typed_data_t *rtype;
	isc_result_t waitstatus;
	omapi_typed_data_t *message;
	omapi_handle_t remote_handle;
} dhcpctl_remote_object_t;

#ifndef __cplusplus
// for some reason, these cause problems when included in C++ classes
omapi_object_type_t *dhcpctl_callback_type;
omapi_object_type_t *dhcpctl_remote_type;
#endif
#endif _DHCPCTL_H_

dhcpctl_status dhcpctl_initialize (void);
dhcpctl_status dhcpctl_connect (dhcpctl_handle *,
				char *, int, dhcpctl_handle);
dhcpctl_status dhcpctl_wait_for_completion (dhcpctl_handle, dhcpctl_status *);
dhcpctl_status dhcpctl_get_value (dhcpctl_data_string *,
				  dhcpctl_handle, char *);
dhcpctl_status dhcpctl_get_boolean (int *, dhcpctl_handle, char *);
dhcpctl_status dhcpctl_set_value (dhcpctl_handle, dhcpctl_data_string, char *);
dhcpctl_status dhcpctl_set_string_value (dhcpctl_handle, const char *,
					 const char *);
dhcpctl_status dhcpctl_set_boolean_value (dhcpctl_handle, int, char *);
dhcpctl_status dhcpctl_set_int_value (dhcpctl_handle, int, char *);
dhcpctl_status dhcpctl_object_update (dhcpctl_handle, dhcpctl_handle);
dhcpctl_status dhcpctl_object_refresh (dhcpctl_handle, dhcpctl_handle);
dhcpctl_status dhcpctl_object_remove (dhcpctl_handle, dhcpctl_handle);

dhcpctl_status dhcpctl_set_callback (dhcpctl_handle, void *,
				     void (*) (dhcpctl_handle,
					       dhcpctl_status, void *));
isc_result_t dhcpctl_callback_set_value  (omapi_object_t *, omapi_object_t *,
					  omapi_data_string_t *,
					  omapi_typed_data_t *);
isc_result_t dhcpctl_callback_get_value (omapi_object_t *, omapi_object_t *,
					 omapi_data_string_t *,
					 omapi_value_t **); 
isc_result_t dhcpctl_callback_destroy (omapi_object_t *, char *);
isc_result_t dhcpctl_callback_signal_handler (omapi_object_t *,
					      char *, va_list);
isc_result_t dhcpctl_callback_stuff_values (omapi_object_t *,
					    omapi_object_t *,
					    omapi_object_t *);

dhcpctl_status dhcpctl_open_object (dhcpctl_handle, dhcpctl_handle, int);
dhcpctl_status dhcpctl_new_object (dhcpctl_handle *, dhcpctl_handle, char *);
isc_result_t dhcpctl_remote_set_value  (omapi_object_t *, omapi_object_t *,
					omapi_data_string_t *,
					omapi_typed_data_t *);
isc_result_t dhcpctl_remote_get_value (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_value_t **); 
isc_result_t dhcpctl_remote_destroy (omapi_object_t *, char *);
isc_result_t dhcpctl_remote_signal_handler (omapi_object_t *,
					    char *, va_list);
isc_result_t dhcpctl_remote_stuff_values (omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *);
