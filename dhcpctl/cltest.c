/* cltest.c

   Example program that uses the dhcpctl library. */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <isc/result.h>
#include "dhcpctl.h"

int main (int, char **);

enum modes { up, down };

int main (argc, argv)
	int argc;
	char **argv;
{
	isc_result_t status, waitstatus;
	dhcpctl_handle connection;
	dhcpctl_handle host_handle, group_handle, interface_handle;
	dhcpctl_data_string cid;
	dhcpctl_data_string result, groupname, identifier;
	int i;
	int mode;
	char *action;

	if (!strcmp (argv [1], "-u")) {
		mode = up;
	} else if (!strcmp (argv [1], "-d")) {
		mode = down;
	} else {
		fprintf (stderr, "Unknown switch \"%s\"\n", argv [1]);
		exit (1);
	}

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

	memset (&interface_handle, 0, sizeof interface_handle);
	status = dhcpctl_new_object (&interface_handle, connection, "interface");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_new_object: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_set_string_value (interface_handle, argv [2], "name");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	if (mode == up) {
		/* "up" the interface */
		printf ("upping interface %s\n", argv [2]);
		action = "create";
		status = dhcpctl_open_object (interface_handle, connection,
					      DHCPCTL_CREATE | DHCPCTL_EXCL);
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "dhcpctl_open_object: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
	} else {
		/* down the interface */
		printf ("downing interface %s\n", argv [2]);
		action = "remove";
		status = dhcpctl_open_object (interface_handle, connection, 0);
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "dhcpctl_open_object: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
		status = dhcpctl_wait_for_completion (interface_handle,
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
		status = dhcpctl_object_remove (connection, interface_handle);
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "dhcpctl_open_object: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
	}

	status = dhcpctl_wait_for_completion (interface_handle, &waitstatus);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (status));
		exit (1);
	}
	if (waitstatus != ISC_R_SUCCESS) {
		fprintf (stderr, "interface object %s: %s\n", action,
			 isc_result_totext (waitstatus));
		exit (1);
	}

	memset (&result, 0, sizeof result);
	status = dhcpctl_get_value (&result, interface_handle, "state");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_get_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	exit (0);
}
