/* resolv.c

   Parser for /etc/resolv.conf file. */

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
"$Id: resolv.c,v 1.8 1999/03/16 05:50:37 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "dhctoken.h"

struct name_server *name_servers;
struct domain_search_list *domains;
char path_resolv_conf [] = _PATH_RESOLV_CONF;

void read_resolv_conf (parse_time)
	TIME parse_time;
{
	FILE *cfile;
	char *val;
	int token;
	int declaration = 0;
	struct name_server *sp, *sl, *ns;
	struct domain_search_list *dp, *dl, *nd;
	struct iaddr *iaddr;

	new_parse (path_resolv_conf);

	eol_token = 1;
	if ((cfile = fopen (path_resolv_conf, "r")) == NULL) {
		log_error ("Can't open %s: %m", path_resolv_conf);
		return;
	}

	do {
		token = next_token (&val, cfile);
		if (token == EOF)
			break;
		else if (token == EOL)
			continue;
		else if (token == DOMAIN || token == SEARCH) {
			do {
				struct domain_search_list *nd, **dp;
				char *dn;

				dn = parse_host_name (cfile);
				if (!dn)
					break;

				dp = &domains;
				for (nd = domains; nd; nd = nd -> next) {
					dp = &nd -> next;
					if (!strcmp (nd -> domain, dn))
						break;
				}
				if (!nd) {
					nd = new_domain_search_list
						("read_resolv_conf");
					if (!nd)
						log_fatal ("No memory for %s", dn);
					nd -> next =
						(struct domain_search_list *)0;
					*dp = nd;
					nd -> domain = dn;
					dn = (char *)0;
				}
				nd -> rcdate = parse_time;
				token = peek_token (&val, cfile);
			} while (token != EOL);
			if (token != EOL) {
				parse_warn ("junk after domain declaration");
				skip_to_semi (cfile);
			}
			token = next_token (&val, cfile);
		} else if (token == NAMESERVER) {
			struct name_server *ns, **sp;
			struct iaddr iaddr;

			parse_ip_addr (cfile, &iaddr);

			sp = &name_servers;
			for (ns = name_servers; ns; ns = ns -> next) {
				sp = &ns -> next;
				if (!memcmp (&ns -> addr.sin_addr,
					     iaddr.iabuf, iaddr.len))
					break;
			}
			if (!ns) {
				ns = new_name_server ("read_resolv_conf");
				if (!ns)
					log_fatal ("No memory for nameserver %s",
					       piaddr (iaddr));
				ns -> next = (struct name_server *)0;
				*sp = ns;
				memcpy (&ns -> addr.sin_addr,
					iaddr.iabuf, iaddr.len);
#ifdef HAVE_SA_LEN
				ns -> addr.sin_len = sizeof ns -> addr;
#endif
				ns -> addr.sin_family = AF_INET;
				ns -> addr.sin_port = htons (53);
				memset (ns -> addr.sin_zero, 0,
					sizeof ns -> addr.sin_zero);
			}
			ns -> rcdate = parse_time;
			skip_to_semi (cfile);
		} else
			skip_to_semi (cfile); /* Ignore what we don't grok. */
	} while (1);
	token = next_token (&val, cfile); /* Clear the peek buffer */

	/* Lose servers that are no longer in /etc/resolv.conf. */
	sl = (struct name_server *)0;
	for (sp = name_servers; sp; sp = ns) {
		ns = sp -> next;
		if (sp -> rcdate != parse_time) {
			if (sl)
				sl -> next = sp -> next;
			else
				name_servers = sp -> next;
			/* We can't actually free the name server structure,
			   because somebody might be hanging on to it.    If
			   your /etc/resolv.conf file changes a lot, this
			   could be a noticable memory leak. */
		} else
			sl = sp;
	}

	/* Lose domains that are no longer in /etc/resolv.conf. */
	dl = (struct domain_search_list *)0;
	for (dp = domains; dp; dp = nd) {
		nd = dp -> next;
		if (dp -> rcdate != parse_time) {
			if (dl)
				dl -> next = dp -> next;
			else
				domains = dp -> next;
			free_domain_search_list (dp, "pick_name_server");
		} else
			dl = dp;
	}
	eol_token = 0;
}

/* Pick a name server from the /etc/resolv.conf file. */

struct name_server *first_name_server ()
{
	FILE *rc;
	static TIME rcdate;
	struct stat st;

	/* Check /etc/resolv.conf and reload it if it's changed. */
	if (cur_time > rcdate) {
		if (stat (path_resolv_conf, &st) < 0) {
			log_error ("Can't stat %s", path_resolv_conf);
			return (struct name_server *)0;
		}
		if (st.st_mtime > rcdate) {
			char rcbuf [512];
			char *s, *t, *u;
			rcdate = cur_time + 1;
			
			read_resolv_conf (rcdate);
		}
	}

	return name_servers;
}
