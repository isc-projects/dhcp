/* db.c

   IP Address Allocation database... */

/*
 * Copyright (c) 1995 The Internet Software Consortium.  All rights reserved.
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
"@(#) Copyright (c) 1995 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

/*
   The IP Address Allocation Database tracks addresses that have been
   allocated from the free pool as specified in dhcpd.conf.   The
   database is maintained in two parts to maintain integrity: the
   journal file and the data file.

   Both files are free-form flat files similar to dhcpd.conf, but with
   a more limited syntax - all that can be specified are leases and
   who they belong to.

   When dhcpd starts up, it reads the entire data file into memory.
   It then reads the journal file into memory and makes corrections to
   the data based on journal entries.

   While dhcpd is running, it periodically records the current time,
   forks (if possible) and dumps the recorded time and its internal
   database of temporarily assigned addresses into a temporary file.
   It then removes any existing backup file, renames the existing file
   with the backup filename, and then renames the new temporary file
   with the real data file name.  The link syscall is not present on
   most systems, so a synchronous ``rename'' that guarantees that
   exactly one file will be the master database may not be possible.
   Therefore the recovery routine needs to know what to do if it finds
   a backup and a temporary file, but no database file.

   Whenever a client requests that an address be allocated to it, or
   requests a lease renewal, and the server is able to satisfy the
   request, it writes a record into the journal file indicating what
   has been requested and waits for that information to reach the
   disk.  Once the file's dirty buffers have been flushed, the server
   responds to the request, and logs another record in the journal
   indicating that it has done so.

   Entries in the journal file are logged along with the time at which
   the logging occurred.  When the server forks to dump the database,
   it records the current time before forking.  The copy of the server
   that writes out the database records the time read prior to forking
   in the new data file.  The copy of the server that continues to
   serve DHCP requests ensures that any journal entries subsequent to
   the fork have time stamps that are greater than the time read
   before forking.  When recovering from a crash, the server discards
   any entries in the journal which have time stamps earlier than the
   time stamp on the data file.

   When recovering from a crash, dhcpd may find a journal entry for a
   request, but no entry indicating that it was satisfied.  There is
   no automatic way to recover from this, since the server may have
   sent out a response, so in this case the server must notify
   sysadmin of the problem and leave it to them to solve it.

   In addition to the actual data files, we also keep a running log of
   ``interesting'' events, which we mail to the dhcp-admin alias every
   morning at 7:00 AM.  This log can be tailed by paranoid sysadmins
   or in times of network trouble. */

/* Initialize the internal database, perform crash recovery as needed. */

void dbinit ()
{
	FILE *dbfile;

	/* We are assuming that on entry, there is no other dhcpd
	   running on this machine.  If there were, there would be the
	   potential for serious database corruption.  The main code
	   currently assures that there is only one server running by
	   listening on the bootps port with INADDR_ANY.  Unices that
	   I'm familiar with will only allow one process to do this,
	   even if the SO_REUSEADDR option is set.   'twouldn't surprise
	   me terribly, though, if this didn't work for some other
	   operating system.   Beware.   XXX */

	/* Look for a file under the official database name.
	   Failing that, look for a file under the backup name.
	   If we find neither, we assume that the database is empty. */

	if ((dbfile = fopen (_PATH_DHCP_DB, "r")) != NULL
	    (dbfile = fopen (_PATH_DHCP_DB_BACKUP, "r") != NULL)) {

		/* Read in the data file, making a list of assigned
		   addresses that have been removed from dhcpd.conf. */

	}

	/* Open the journal file and read through any entries which
           are out of date. */

	/* Now read entries that postdate the last database sync,
	   keeping track of incomplete entries (when we're done, there
	   should never be more than one such entry. */

	/* Now expire any leases that have lapsed since we last ran. */

	/* ...and we're done... */
}
