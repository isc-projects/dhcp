/* db.c

   Persistent database management routines for DHCPD... */

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

#ifndef lint
static char copyright[] =
"$Id: db.c,v 1.25.2.2 1999/10/26 15:20:25 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include <ctype.h>

FILE *db_file;

static int counting = 0;
static int count = 0;
TIME write_time;

/* Write the specified lease to the current lease database file. */

int write_lease (lease)
	struct lease *lease;
{
	struct tm *t;
	char tbuf [64];
	int errors = 0;
	int i;

	if (counting)
		++count;
	errno = 0;
	fprintf (db_file, "lease %s {\n", piaddr (lease -> ip_addr));
	if (errno) {
		++errors;
	}

	/* Note: the following is not a Y2K bug - it's a Y1.9K bug.   Until
	   somebody invents a time machine, I think we can safely disregard
	   it. */
	if (lease -> starts != MAX_TIME) {
		t = gmtime (&lease -> starts);
		sprintf (tbuf, "%d %d/%02d/%02d %02d:%02d:%02d;",
			 t -> tm_wday, t -> tm_year + 1900,
			 t -> tm_mon + 1, t -> tm_mday,
			 t -> tm_hour, t -> tm_min, t -> tm_sec);
	} else
		strcpy (tbuf, "never;");
	errno = 0;
	fprintf (db_file, "\tstarts %s\n", tbuf);
	if (errno) {
		++errors;
	}

	if (lease -> ends != MAX_TIME) {
		t = gmtime (&lease -> ends);
		sprintf (tbuf, "%d %d/%02d/%02d %02d:%02d:%02d;",
			 t -> tm_wday, t -> tm_year + 1900,
			 t -> tm_mon + 1, t -> tm_mday,
			 t -> tm_hour, t -> tm_min, t -> tm_sec);
	} else
		strcpy (tbuf, "never;");
	errno = 0;
	fprintf (db_file, "\tends %s", tbuf);
	if (errno) {
		++errors;
	}

	/* If this lease is billed to a class and is still valid,
	   write it out. */
	if (lease -> billing_class && lease -> ends > cur_time)
		if (!write_billing_class (lease -> billing_class))
			++errors;

	if (lease -> hardware_addr.hlen) {
		errno = 0;
		fprintf (db_file, "\n\thardware %s %s;",
			 hardware_types [lease -> hardware_addr.htype],
			 print_hw_addr (lease -> hardware_addr.htype,
					lease -> hardware_addr.hlen,
					lease -> hardware_addr.haddr));
		if (errno) {
			++errors;
		}
	}
	if (lease -> uid_len) {
		int i;
		errno = 0;
		fprintf (db_file, "\n\tuid %2.2x", lease -> uid [0]);
		if (errno) {
			++errors;
		}
		for (i = 1; i < lease -> uid_len; i++) {
			errno = 0;
			fprintf (db_file, ":%2.2x", lease -> uid [i]);
			if (errno) {
				++errors;
			}
		}
		putc (';', db_file);
	}
	if (lease -> flags & BOOTP_LEASE) {
		errno = 0;
		fprintf (db_file, "\n\tdynamic-bootp;");
		if (errno) {
			++errors;
		}
	}
	if (lease -> flags & ABANDONED_LEASE) {
		errno = 0;
		fprintf (db_file, "\n\tabandoned;");
		if (errno) {
			++errors;
		}
	}
	if (lease -> ddns_fwd_name && db_printable (lease -> ddns_fwd_name)) {
		errno = 0;
		fprintf (db_file, "\n\tddns-fwd-name \"%s\";",
			 lease -> ddns_fwd_name);
		if (errno) {
			++errors;
		}
	}
	if (lease -> ddns_rev_name && db_printable (lease -> ddns_rev_name)) {
		errno = 0;
		fprintf (db_file, "\n\tddns-rev-name \"%s\";",
			 lease -> ddns_rev_name);
		if (errno) {
			++errors;
		}
	}
	if (lease -> client_hostname &&
	    db_printable (lease -> client_hostname)) {
		errno = 0;
		fprintf (db_file, "\n\tclient-hostname \"%s\";",
			 lease -> client_hostname);
		if (errno) {
			++errors;
		}
	}
	if (lease -> hostname && db_printable (lease -> hostname)) {
		errno = 0;
		errno = 0;
		fprintf (db_file, "\n\thostname \"%s\";",
			 lease -> hostname);
		if (errno) {
			++errors;
		}
	}
	errno = 0;
	fputs ("\n}\n", db_file);
	if (errno) {
		++errors;
	}
	if (errors)
		log_info ("write_lease: unable to write lease %s",
		      piaddr (lease -> ip_addr));
	return !errors;
}

int db_printable (s)
	char *s;
{
	int i;
	for (i = 0; s [i]; i++)
		if (!isascii (s [i]) || !isprint (s [i]))
			return 0;
	return 1;
}

/* Write a spawned class to the database file. */

int write_billing_class (class)
	struct class *class;
{
	int errors = 0;
	int i;

	if (!class -> superclass) {
		errno = 0;
		fprintf (db_file, "\n\tbilling class \"%s\";", class -> name);
		return !errno;
	}

	errno = 0;
	fprintf (db_file, "\n\tbilling subclass \"%s\"",
		 class -> superclass -> name);
	if (errno)
		++errors;

	for (i = 0; i < class -> hash_string.len; i++)
		if (!isascii (class -> hash_string.data [i]) ||
		    !isprint (class -> hash_string.data [i]))
			break;
	if (i == class -> hash_string.len) {
		errno = 0;
		fprintf (db_file, " \"%*.*s\";",
			 class -> hash_string.len,
			 class -> hash_string.len,
			 class -> hash_string.data);
		if (errno)
			++errors;
	} else {
		errno = 0;
		fprintf (db_file, " %2.2x", class -> hash_string.data [0]);
		if (errno)
			++errors;
		for (i = 1; i < class -> hash_string.len; i++) {
			errno = 0;
			fprintf (db_file, ":%2.2x",
				 class -> hash_string.data [i]);
			if (errno)
				++errors;
		}
		errno = 0;
		fprintf (db_file, ";");
		if (errno)
			++errors;
	}

	class -> dirty = 0;
	return !errors;
}

/* Commit any leases that have been written out... */

int commit_leases ()
{
	/* Commit any outstanding writes to the lease database file.
	   We need to do this even if we're rewriting the file below,
	   just in case the rewrite fails. */
	if (fflush (db_file) == EOF) {
		log_info ("commit_leases: unable to commit: %m");
		return 0;
	}
	if (fsync (fileno (db_file)) < 0) {
		log_info ("commit_leases: unable to commit: %m");
		return 0;
	}

	/* If we've written more than a thousand leases or if
	   we haven't rewritten the lease database in over an
	   hour, rewrite it now. */
	if (count > 1000 || (count && cur_time - write_time > 3600)) {
		count = 0;
		write_time = cur_time;
		new_lease_file ();
	}
	return 1;
}

void db_startup (testp)
	int testp;
{
	/* Read in the existing lease file... */
	read_leases ();

	if (!testp) {
		expire_all_pools ();
		GET_TIME (&write_time);
		new_lease_file ();
	}
}

void new_lease_file ()
{
	char newfname [512];
	char backfname [512];
	TIME t;
	int db_fd;

	/* If we already have an open database, close it. */
	if (db_file) {
		fclose (db_file);
	}

	/* Make a temporary lease file... */
	GET_TIME (&t);
	sprintf (newfname, "%s.%d", path_dhcpd_db, (int)t);
	db_fd = open (newfname, O_WRONLY | O_TRUNC | O_CREAT, 0664);
	if (db_fd < 0) {
		log_fatal ("Can't create new lease file: %m");
	}
	if ((db_file = fdopen (db_fd, "w")) == NULL) {
		log_fatal ("Can't fdopen new lease file!");
	}

	/* Write an introduction so people don't complain about time
	   being off. */
	fprintf (db_file, "# All times in this file are in UTC (GMT), not %s",
		 "your local timezone.   This is\n");
	fprintf (db_file, "# not a bug, so please don't ask about it.   %s",
		 "There is no portable way to\n");
	fprintf (db_file, "# store leases in the local timezone, so please %s",
		 "don't request this as a\n");
	fprintf (db_file, "# feature.   If this is inconvenient or %s",
		 "confusing to you, we sincerely\n");
	fprintf (db_file, "# apologize.   Seriously, though - don't ask.\n");
	fprintf (db_file, "# The format of this file is documented in the %s",
		 "dhcpd.leases(5) manual page.\n\n");

	/* Write out all the leases that we know of... */
	counting = 0;
	write_leases ();

	/* Get the old database out of the way... */
	sprintf (backfname, "%s~", path_dhcpd_db);
	if (unlink (backfname) < 0 && errno != ENOENT)
		log_fatal ("Can't remove old lease database backup %s: %m",
		       backfname);
	if (link (path_dhcpd_db, backfname) < 0)
		log_fatal ("Can't backup lease database %s to %s: %m",
		       path_dhcpd_db, backfname);
	
	/* Move in the new file... */
	if (rename (newfname, path_dhcpd_db) < 0)
		log_fatal ("Can't install new lease database %s to %s: %m",
		       newfname, path_dhcpd_db);

	counting = 1;
}
