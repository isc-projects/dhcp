/* db.c

   Persistent database management routines for DHCPD... */

/*
 * Copyright (c) 1995, 1996 The Internet Software Consortium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

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

	if (counting)
		++count;
	errno = 0;
	fprintf (db_file, "lease %s\n", piaddr (lease -> ip_addr));

	t = gmtime (&lease -> starts);
	strftime (tbuf, sizeof tbuf, "%w %Y/%m/%d %H:%M:%S", t);
	fprintf (db_file, "\tstarts %s\n", tbuf);

	t = gmtime (&lease -> ends);
	strftime (tbuf, sizeof tbuf, "%w %Y/%m/%d %H:%M:%S", t);
	fprintf (db_file, "\tends %s", tbuf);

	if (lease -> hardware_addr.hlen) {
		fprintf (db_file, "\n\thardware %s %s",
			 hardware_types [lease -> hardware_addr.htype],
			 print_hw_addr (lease -> hardware_addr.htype,
					lease -> hardware_addr.hlen,
					lease -> hardware_addr.haddr));
	}
	if (lease -> uid_len) {
		int i;
		fprintf (db_file, "\n\tuid %x", lease -> uid [0]);
		for (i = 1; i < lease -> uid_len; i++)
			fprintf (db_file, ":%x", lease -> uid [i]);
	}
	if (lease -> flags & BOOTP_LEASE)
		fprintf (db_file, "\n\tdynamic-bootp");
	fputs (";\n", db_file);
	return !errno;
}

/* Commit any leases that have been written out... */

int commit_leases ()
{
	/* If we've written more than a thousand leases or if
	   we haven't rewritten the lease database in over an
	   hour, rewrite it now. */
	if (count > 1000 || (count && cur_time - write_time > 3600)) {
		count = 0;
		write_time = cur_time;
		new_lease_file ();
		return 1;
	}

	if (fflush (db_file) == EOF)
		return 0;
	if (fsync (fileno (db_file)) < 0)
		return 0;
	return 1;
}

void db_startup ()
{
	/* Read in the existing lease file... */
	read_leases ();

	new_lease_file ();
}

void new_lease_file ()
{
	char newfname [512];
	char backfname [512];
	TIME t;

	/* If we already have an open database, close it. */
	if (db_file) {
		fclose (db_file);
	}

	/* Make a temporary lease file... */
	time (&t);
	sprintf (newfname, "%s.%d", _PATH_DHCPD_DB, (int) (t & 32767));
	if ((db_file = fopen (newfname, "w")) == NULL) {
		error ("Can't start new lease file: %m");
	}

	/* Write out all the leases that we know of... */
	counting = 0;
	write_leases ();

	/* Get the old database out of the way... */
	sprintf (backfname, "%s~", _PATH_DHCPD_DB);
	unlink (backfname);
	link (_PATH_DHCPD_DB, backfname);
	
	/* Move in the new file... */
	rename (newfname, _PATH_DHCPD_DB);

	counting = 1;
}
