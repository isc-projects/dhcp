/* test.c

   Example program that uses the dhcpctl library. */

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

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <isc/result.h>
#include "dhcpctl.h"

int main (int, char **);

int main (argc, argv)
	int argc;
	char **argv;
{
	isc_result_t status, waitstatus;
	dhcpctl_handle connection;
	dhcpctl_handle host_handle, group_handle, lease_handle;
	dhcpctl_data_string cid, ip_addr;
	dhcpctl_data_string result, groupname, identifier;
	int i;

	status = dhcpctl_initialize ();
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_initialize: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	memset (&connection, 0, sizeof connection);
	status = dhcpctl_connect (&connection, "127.0.0.1", 7911,
				  (dhcpctl_handle)0);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_connect: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	/* Create a named group that contains the values we want to assign
	   to the host. */
	memset (&group_handle, 0, sizeof group_handle);
	status = dhcpctl_new_object (&group_handle, connection, "group");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_new_object: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_set_string_value (group_handle, "\n\
option domain-name \"foo.org\";\n\
option domain-name-servers 10.0.0.1, 10.0.0.2;",
					   "statements");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_open_object (group_handle, connection,
				      DHCPCTL_CREATE | DHCPCTL_EXCL);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_open_object: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_wait_for_completion (group_handle, &waitstatus);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (status));
		exit (1);
	}
	if (waitstatus != ISC_R_SUCCESS) {
		fprintf (stderr, "group object create: %s\n",
			 isc_result_totext (waitstatus));
		exit (1);
	}

	memset (&groupname, 0, sizeof groupname);
	status = dhcpctl_get_value (&groupname, group_handle, "name");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_get_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	printf ("group name = %*s\n", groupname -> len, groupname -> value);

	memset (&host_handle, 0, sizeof host_handle);
	status = dhcpctl_new_object (&host_handle, connection, "host");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_new_object: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

/*#if 0 */
	memset (&cid, 0, sizeof cid);
	status = omapi_data_string_new (&cid, 6, MDL);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "omapi_data_string_new: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	cid -> value [0] = 0; cid -> value [1] = 0x10;
	cid -> value [2] = 0x5a; cid -> value [3] = 0xf8;
	cid -> value [4] = 0x00; cid -> value [5] = 0xbb;

      doitagain:
	status = dhcpctl_set_value (host_handle,
				    cid, "dhcp-client-identifier");
/*#else 
  doitagain: */
	status = dhcpctl_set_string_value (host_handle, "gnorf",
					   "name");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}
/*#endif*/

	status = dhcpctl_set_value (host_handle, groupname, "group");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

#if 0
	memset (&ip_addr, 0, sizeof ip_addr);
	status = omapi_data_string_new (&ip_addr, 4, MDL);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "omapi_data_string_new: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	ip_addr -> value [0] = 10; ip_addr -> value [1] = 0;
	ip_addr -> value [2] = 0; ip_addr -> value [3] = 2;

	status = dhcpctl_set_value (host_handle, ip_addr, "ip-address");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}
#endif

	/* Set the known flag to 1. */
	status = dhcpctl_set_boolean_value (host_handle, 1, "known");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_boolean_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

       status = dhcpctl_set_string_value (host_handle, "\n\
option host-name \"bar\";\n\
option smtp-server 10.0.0.1;",
                                          "statements");
       if (status != ISC_R_SUCCESS) {
               fprintf (stderr, "dhcpctl_set_value: %s\n",
                        isc_result_totext (status));
               exit (1);
       }

	status = dhcpctl_open_object (host_handle, connection,
				      DHCPCTL_CREATE | DHCPCTL_EXCL);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_open_object: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_wait_for_completion (host_handle, &waitstatus);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	if (waitstatus != ISC_R_SUCCESS) {
		status = dhcpctl_open_object (host_handle, connection, 0);
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "dhcpctl_open_object: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
		status = dhcpctl_wait_for_completion (host_handle,
						      &waitstatus);
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "dhcpctl_wait_for_completion: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
		if (waitstatus != ISC_R_SUCCESS) {
			fprintf (stderr, "dhcpctl_wait_for_completion: %s\n",
				 isc_result_totext (waitstatus));
			exit (1);
		}

		status = dhcpctl_object_remove (connection, host_handle);
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "dhcpctl_object_remove: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
		status = dhcpctl_wait_for_completion (host_handle,
						      &waitstatus);
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr,
				 "remove: dhcpctl_wait_for_completion: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
		if (waitstatus != ISC_R_SUCCESS) {
			fprintf (stderr,
				 "remove: dhcpctl_wait_for_completion: %s\n",
				 isc_result_totext (waitstatus));
			exit (1);
		}

		omapi_object_dereference (&host_handle, MDL);

		status = dhcpctl_new_object (&host_handle, connection, "host");
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "dhcpctl_new_object: %s\n",
				 isc_result_totext (status));
			exit (1);
		}

		goto doitagain;
	}

	memset (&result, 0, sizeof result);
	status = dhcpctl_get_value (&result, host_handle, "name");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_get_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	printf ("host name = %*s\n", result -> len, result -> value);

#if 0
	status = dhcpctl_object_remove (connection, host_handle);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_object_remove: %s\n",
			 isc_result_totext (status));
		exit (1);
	}
	status = dhcpctl_wait_for_completion (host_handle,
					      &waitstatus);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "remove: dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (status));
		exit (1);
	}
	if (waitstatus != ISC_R_SUCCESS) {
		fprintf (stderr, "remove: dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (waitstatus));
		exit (1);
	}
#endif

	/* Create a named group that contains the values we want to assign
	   to the host. */
	memset (&lease_handle, 0, sizeof lease_handle);
	status = dhcpctl_new_object (&lease_handle, connection, "lease");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_new_object: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	memset (&ip_addr, 0, sizeof ip_addr);
	status = omapi_data_string_new (&ip_addr, 4, MDL);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "omapi_data_string_new: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	ip_addr -> value [0] = 10; ip_addr -> value [1] = 0;
	ip_addr -> value [2] = 0; ip_addr -> value [3] = 4;

	status = dhcpctl_set_value (lease_handle, ip_addr, "ip-address");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_open_object (lease_handle, connection, 0);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_open_object: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_wait_for_completion (lease_handle, &waitstatus);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (status));
		exit (1);
	}
	if (waitstatus != ISC_R_SUCCESS) {
		fprintf (stderr, "lease object lookup: %s\n",
			 isc_result_totext (waitstatus));
		exit (1);
	}

	memset (&identifier, 0, sizeof identifier);
	status = dhcpctl_get_value (&identifier, lease_handle,
				    "dhcp-client-identifier");
	if (status == ISC_R_SUCCESS) {
		printf ("lease client-identifier = %02x",
			identifier -> value [0]);
		for (i = 1; i < identifier -> len; i++) {
			printf (":%02x", identifier -> value [i]);
		}
		putchar ('\n');
	} else {
		status = dhcpctl_get_value (&identifier, lease_handle,
					    "hardware-address");
		if (status == ISC_R_SUCCESS) {
			printf ("lease hardware address = %02x",
				identifier -> value [0]);
			for (i = 1; i < identifier -> len; i++) {
				printf (":%02x", identifier -> value [i]);
			}
			putchar ('\n');
			dhcpctl_data_string_dereference (&identifier, MDL);
			status = dhcpctl_get_value (&identifier, lease_handle,
						    "hardware-type");
			if (status == ISC_R_SUCCESS) {
				printf ("lease hardware type = %d\n",
					identifier -> value [0]);
				dhcpctl_data_string_dereference (&identifier,
								 MDL);
			}
		} else {
			printf ("Unable to find identifier for lease.\n");
		}
	}

	exit (0);
}
