/* auth.c

   Subroutines having to do with authentication. */

/*
 * Copyright (c) 1995, 1996, 1997, 1998, 1999
 * The Internet Software Consortium.   All rights reserved.
 *
 * Redistribution and use of this source file, source files derived in whole
 * or in part from this source file, and binary files derived in whole or in
 * part from this source file, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *    This copyright notice must appear directly below any initial commentary
 *    describing the file, and may not be preceded by any other copyright
 *    notice.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium (hereafter
 *    referred to as "the ISC") nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 4. This software is a part of the ISC DHCP Distribution.  Redistributions
 *    of this source file or binary files derived from this source file
 *    MUST include all documentation accompanying the ISC release from
 *    which such redistributions are derived of this source file, specifically
 *    the following files (listed relative to the top of the ISC DHCP
 *    distribution directory tree):
 *
 *		README
 *		common/dhcp-contrib.5
 *		common/dhcp-options.5
 *		server/dhcpd.8
 *		server/dhcpd.conf.5
 *		server/dhcpd.leases.5
 *		client/dhclient.8
 *		client/dhclient.conf.5
 *		client/dhclient-script.8
 *		client/dhclient.leases.5
 *		relay/dhcrelay.8
 *
 *    Absence of these files from a distribution you receive does not excuse
 *    you from this requirement - if the distribution you receive does not
 *    contain these files, you must get them from the ISC and include them
 *    in any redistribution of this source file or any derivative work based
 *    wholly or in part on this source file.   It is permissible in a binary
 *    redistribution derived from this source file to include formatted
 *    versions of the manual pages mentioned above, and also to add to or
 *    correct the manual pages and README file mentioned above so long as the
 *    sections labeled CONTRIBUTIONS in these documents are unchanged except
 *    with respect to formatting, so long as the order in which the
 *    CONTRIBUTIONS section appears in these documents is not changed, and
 *    so long as the dhcp-contrib.5 manual page is unchanged except with
 *    respect to formatting.   It is also permissible to redistribute this
 *    source file, source files derived wholly or in part from this source
 *    file, and binaries derived wholly or in part from this source file
 *    accompanied by the aforementioned manual pages translated into another
 *    language.   In this case, the CONTRIBUTIONS section and the
 *    dhcp-contrib.5 section may either be left in their original language
 *    or translated into the new language with such care and diligence as
 *    is required to preserve the original meaning.
 * 5. If, in addition to the documentation mentioned in section 4, this
 *    source file, a source file derived wholly or in part from this source
 *    file, or a binary file derived wholly or in part from this source file
 *    is redistributed with additional printed or electronic documentation,
 *    then that documentation must refer to the dhcp-contrib.5 manual page
 *    in as conspicuous a way as the aforementioned documentation refers to
 *    it, and the dhcp-contrib.5 manual page must be converted into the same
 *    format and be made easily accessible to any recipient of such
 *    redistributions.
 *
 * THIS SOFTWARE IS PROVIDED BY THE ISC AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE ISC OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the ISC by Ted Lemon <mellon@isc.org>
 * in cooperation with Vixie Enterprises and Internet Engines, Inc.  To
 * learn more about the ISC, see ``http://www.vix.com/isc''.   Development
 * of this software is funded through contributions and support contracts.
 * Please see the dhcp-contrib manual page that accompanies this file for
 * information on how you can contribute.
 */

#ifndef lint
static char ocopyright[] =
"$Id: auth.c,v 1.1 1999/02/25 23:30:33 mellon Exp $ Copyright 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.";
#endif

#include "dhcpd.h"

static struct hash_table *auth_key_hash;

void enter_auth_key (key_id, key)
	struct data_string *key_id;
	struct auth_key *key;
{
	if (!auth_key_hash)
		auth_key_hash = new_hash ();
	if (!auth_key_hash)
		log_fatal ("Can't allocate authentication key hash.");
	add_hash (auth_key_hash, key_id -> data, key_id -> len,
		  (unsigned char *)key);
}

struct auth_key *auth_key_lookup (key_id)
	struct data_string *key_id;
{
	return (struct auth_key *)hash_lookup (auth_key_hash,
					       key_id -> data, key_id -> len);
}

