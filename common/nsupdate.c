/* nsupdate.c

   Tables of information... */

/*
 * Copyright (c) 1999 Internet Software Consortium.
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
 *
 * Note: file is currently based on work done by Brian Murrell, Irina
 * Goble and others.   The copyright message is not final.
 */

#ifndef lint
static char copyright[] =
"$Id: nsupdate.c,v 1.3.2.9 1999/10/28 16:07:38 mellon Exp $ Copyright (c) 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

#if defined (NSUPDATE)
/* Yet another new plan.
   First thing to be done is to determine if a change actually needs to be
   done.  This can be done by figuring out the hostname.domain and revname
   and then comparing them to the lease->ddns* values.  Only make the changes
   necessary which can be any combination and number of remove A, add A,
   remove PTR, add PTR */

/* Return the forward name of a lease. */
char *ddns_rev_name (lease, state, packet)
	struct lease *lease;
	struct lease_state *state;
	struct packet *packet;
{
	struct option_cache *oc = NULL;
	char *revname;
	char pdq [128]; /* 4*3 %d +3 . +1 NUL */
	struct data_string revdomain;
	unsigned pqlen, rdlen;
	static char inaddr [] = "inaddr.arpa";

	/* Figure out what reverse domain to update
	   First take the scoped "ddns-rev-domainname" option if present
	   then assume d.c.b.a.in-addr.arpa. if not present
	   error if neither are present */
	oc = lookup_option (&server_universe, state -> options,
			    SV_DDNS_REV_DOMAIN_NAME);
	memset (&revdomain, 0, sizeof revdomain);
	if (oc)
		evaluate_option_cache (&revdomain, packet,
				       packet -> options, lease, oc);
	if (lease -> ip_addr.len != 4) { /* IPv4 */
		log_error("unsupported IP address length: %d",
			  lease -> ip_addr.len);
		return NULL;
	}
	
	sprintf (pdq, "%u.%u.%u.%u", lease -> ip_addr.iabuf [3],
		 lease -> ip_addr.iabuf [2], lease -> ip_addr.iabuf [1],
		 lease -> ip_addr.iabuf [0]);
	pqlen = strlen (pdq);
	if (revdomain.len)
		rdlen = revdomain.len + 2;
	else
		rdlen += sizeof inaddr + 1;
	revname = dmalloc (pqlen + rdlen, "ddns_rev_name");
	if (!revname) {
		log_error ("No memory to compute PTR name for %s", pdq);
		if (revdomain.len)
			data_string_forget (&revdomain, "ddns_rev_name");
		return NULL;
	}
	strcpy (revname, pdq);
	revname [pqlen] = '.';
	if (revdomain.len) {
		memcpy (revname + pqlen + 1, revdomain.data, revdomain.len);
		revname [pqlen + revdomain.len + 1] = 0;
	} else
		strcpy (revname + pqlen + 1, inaddr);
	if (revdomain.len)
		data_string_forget (&revdomain, "ddns_rev_name");
	return revname;
}

/* Return the forward name of a lease. */
char *ddns_fwd_name (lease, state, packet)
	struct lease *lease;
	struct lease_state *state;
	struct packet *packet;
{
	struct option_cache *oc = NULL;
	struct data_string hostname;
	struct data_string domain;
	char *rv;

	/* Figure out the domain name of a lease.
	   First take the scoped "ddns-domainname" option if present
	   then the dhcp option "domain-name" if present
	   error if neither are present */
	oc = lookup_option (&server_universe, state -> options,
			    SV_DDNS_DOMAIN_NAME);
	memset (&domain, 0, sizeof domain);
	if (!(oc && evaluate_option_cache (&domain, packet,
					   packet -> options, lease, oc))) {
		oc = lookup_option (&dhcp_universe, state -> options,
				    DHO_DOMAIN_NAME);
		if (!(oc &&
		      evaluate_option_cache (&domain, packet,
					     packet -> options, lease, oc))) {
			log_info ("dns-update: no domain name specified.");
			log_info ("Please specify a domain-name option or %s",
				  "use the ddns-domainname parameter.");
			return NULL;
		}
	}

	/* Figure out what host in the domain to assign to.
	   First take the scoped "ddns-hostname" option
	   then the dhcp option "host-name" if present
	   then the dhcp host_decl "name" if present
	   error if neither are present. */
	oc = lookup_option (&server_universe, state -> options,
			    SV_DDNS_HOST_NAME);
	memset (&hostname, 0, sizeof hostname);
	if (!(oc && evaluate_option_cache (&hostname, packet,
					   state -> options, lease, oc))) {
		oc = lookup_option (&dhcp_universe,
				    packet -> options, DHO_HOST_NAME);
		if (!(oc &&
		      evaluate_option_cache (&hostname, packet,
					     packet -> options, lease, oc))) {
			if (lease -> host && lease -> host -> name) {
				hostname.data =
					(unsigned char *)lease -> host -> name;
				hostname.len = strlen ((char *)hostname.data);
			} else {
				log_info ("ddns_fwd_name: no hostname.");
				log_info ("either client must specify %s",
					  "hostname, or server must provide");
				log_info ("it through the host-name option %s",
					  "or a host declaration.");
				data_string_forget (&hostname,
						    "ddns-fwd-name");
				return NULL;
			}
		}
	}

	rv = dmalloc (hostname.len + domain.len + 2, "ddns-fwd-name");
	if (!rv) {
		log_error ("dns update: no memory for client FQDN.");
		data_string_forget (&domain, "ddns-fwd-name");
		data_string_forget (&hostname, "ddns-fwd-name");
		return NULL;
	}
	
	memcpy (rv, hostname.data, hostname.len);
	rv [hostname.len] = '.';
	memcpy (rv + hostname.len + 1, domain.data, domain.len);
	rv [hostname.len + 1 + domain.len] = 0;
	data_string_forget (&domain, "ddns-fwd-name");
	data_string_forget (&hostname, "ddns-fwd-name");
	
	if (!res_hnok (rv) ) {
		log_error("nsupdate: Bad hostname \"%s\"", rv);
		dfree (rv, "ddns-fwd-name");
		return NULL;
	}
	return rv;
}

int nsupdateA (hostname, ip_addr, ttl, opcode)
	char *hostname;
	char *ip_addr;
	u_int32_t ttl;
	int opcode;
{
	int z;
	ns_updrec *u, *n;
	ns_updque listuprec;
	static struct __res_state res;

	res_ninit(&res);
	INIT_LIST(listuprec);

	switch (opcode) {
	      case ADD:
		if (!(u = res_mkupdrec (S_PREREQ, hostname, C_IN, T_A, 0))) 
			return 0;
		u -> r_opcode = NXRRSET;
		u -> r_data = NULL;
		u -> r_size = 0;
		if (!(n = res_mkupdrec (S_UPDATE, hostname, C_IN, T_A, ttl))) {
			res_freeupdrec (u);
			return 0;
		}
		n -> r_opcode = opcode;
		n -> r_data = (unsigned char *)ip_addr;
		n -> r_size = strlen (ip_addr);
		APPEND (listuprec, u, r_link);
		APPEND (listuprec, n, r_link);
		z = res_nupdate (&res, HEAD (listuprec), NULL);
		log_info ("add %s: %s %ld IN A %s",
			  z == 1 ? "succeeded" : "failed", hostname,
			  (unsigned long)ttl,
			  n -> r_data);
		break;

	      case DELETE:
		ttl = 0;
		if (!(u = res_mkupdrec (S_UPDATE, hostname, C_IN, T_A, ttl)))
			return 0;
		u -> r_opcode = opcode;
		u -> r_data = (unsigned char *)ip_addr;
		u -> r_size = strlen (ip_addr);
		APPEND (listuprec, u, r_link);
		z = res_nupdate (&res, HEAD (listuprec), NULL);
		log_info ("delete %s: %s %ld IN A %s",
			  z == 1 ? "succeeded" : "failed",
			  hostname, (unsigned long)ttl, u->r_data);
		break;

	      default:
		return 0;
	}

	while (!EMPTY (listuprec)) {
		ns_updrec *tmprrecp = HEAD (listuprec);
		UNLINK (listuprec, tmprrecp, r_link);
		res_freeupdrec (tmprrecp);
	}

	return z;
}

int nsupdatePTR (hostname, revname, ttl, opcode)
	char *hostname;
	char *revname;
	u_int32_t ttl;
	int opcode;
{
	int z;
	ns_updrec *u, *n;
	ns_updque listuprec;
	static struct __res_state res;

	if (opcode == DELETE) {
		ttl = 0;
		n = 0;
	} else {
		if (!(n = res_mkupdrec (S_UPDATE, revname, C_IN, T_PTR, 0)))
			return 0;
		n -> r_opcode = DELETE;
		n -> r_data = NULL;
		n -> r_size = 0;
	}
	if (!(u = res_mkupdrec (S_UPDATE, revname, C_IN, T_PTR, ttl))) {
		if (n)
			res_freeupdrec (n);
		return 0;
	}
	u -> r_opcode = opcode;
	u -> r_data = (unsigned char *)hostname;
	u -> r_size = strlen (hostname);
	INIT_LIST (listuprec);
	if (n) {
		APPEND(listuprec, n, r_link);
	}
	APPEND (listuprec, u, r_link);
	res_ninit (&res);
	z = res_nupdate (&res, HEAD (listuprec), NULL);
	log_info ("%s %s: %s %ld IN PTR %s", 
		  opcode == ADD ? "add" : "delete",
		  z == 1 ? "succeeded" : "failed",
		 revname, (unsigned long)ttl, hostname);
	while (!EMPTY (listuprec)) {
		ns_updrec *tmprrecp = HEAD (listuprec);
		UNLINK (listuprec, tmprrecp, r_link);
		res_freeupdrec (tmprrecp);
	}
	return z;
}

void nsupdate (lease, state, packet, opcode)
	struct lease *lease;
	struct lease_state *state;
	struct packet *packet;
	int opcode;
{
	char *hostname, *revname;
	u_int32_t ttl = 0;

	if (!(opcode == ADD || opcode == DELETE))
		return;
	
	if (!lease){
		log_info("invalid pointer at %s:%d",
			 __FILE__, __LINE__-2);
		return;
	}
	
	switch (opcode) {
	      case ADD:
		if (!packet){
			log_info("invalid pointer at %s:%d",
				 __FILE__, __LINE__-2);
			return;
		}
		if (!packet -> options) {
			log_info("invalid pointer at %s:%d",
				 __FILE__, __LINE__-2);
			return;
		}
		if (!state) {
			log_info("invalid pointer at %s:%d",
				 __FILE__, __LINE__-2);
			return;
		}
		if (!state -> options) {
			log_info("invalid pointer at %s:%d",
				 __FILE__, __LINE__-2);
			return;
		}

		hostname = ddns_fwd_name (lease, state, packet);
		if (!hostname)	/* there is nothing we can do now */
			return;
		revname = ddns_rev_name (lease, state, packet);
		
		if (state -> offered_expiry > cur_time)
			ttl = state -> offered_expiry - cur_time;
		else
			log_error("nsupdate: ttl < 0");

		/* Delete the existing A if the one to be added is different */
		if (lease -> ddns_fwd_name &&
		    strcmp (hostname, lease -> ddns_fwd_name)) {
			int y;
			y = nsupdateA (lease -> ddns_fwd_name,
				       piaddr (lease -> ip_addr), ttl, DELETE);

			/* delete an existing PTR if new one is different */
			if (lease -> ddns_rev_name &&
			    (strcmp(hostname, lease -> ddns_fwd_name) ||
			     strcmp(revname, lease -> ddns_rev_name)) &&
			    nsupdatePTR (lease -> ddns_fwd_name, revname,
					 ttl, DELETE)) {
				/* clear the forward DNS name pointer */
				if (lease -> ddns_rev_name)
					dfree (lease -> ddns_rev_name,
					       "nsupdate");
				lease -> ddns_rev_name = 0;
			}
			if (y) {
				/* clear the forward DNS name pointer */
				if (lease -> ddns_fwd_name)
					dfree (lease -> ddns_fwd_name,
					       "nsupdate");
				lease -> ddns_fwd_name = 0;
			}
		}
		/* only update if there is no A record there already */
		if (!lease -> ddns_fwd_name) {
			int z;
		    	z = nsupdateA (hostname, piaddr (lease -> ip_addr),
				       ttl, ADD);
			if (z < 1) {
				dfree (hostname, "nsupdate");
				if (revname)
					dfree (revname, "nsupdate");
				return;
			}

			/* remember this in the lease structure for release */
			lease -> ddns_fwd_name = hostname;
			hostname = (char *)0;
		}

		if (!revname) {	/* there is nothing more we can do now */
			if (hostname)
				dfree (hostname, "nsupdate");
			return;
		}

		if (!lease -> ddns_rev_name && lease -> ddns_fwd_name) {
			/* add a PTR RR */
			if (nsupdatePTR (lease -> ddns_fwd_name,
					 revname, ttl, ADD)) {
				/* remember in lease struct for a release */
				lease -> ddns_rev_name = revname;
				revname = (char *)0;
			}
		}
		if (hostname)
			dfree (hostname, "nsupdate");
		if (revname)
			dfree (revname, "nsupdate");
		break;
	case DELETE:
		ttl = 0;
		if (lease -> ddns_fwd_name) {
			int y;
			y = nsupdateA (lease -> ddns_fwd_name,
				       piaddr (lease -> ip_addr), ttl, DELETE);


			if (lease -> ddns_rev_name &&
			    nsupdatePTR (lease -> ddns_fwd_name,
					 lease -> ddns_rev_name, ttl, opcode))
			{
				/* clear the reverse DNS name pointer */
				if (lease -> ddns_rev_name)
					dfree(lease -> ddns_rev_name,
					      "nsupdate");
				lease -> ddns_rev_name = 0;
			}

			if (y) {
				/* clear the forward DNS name pointer */
				if (lease -> ddns_fwd_name)
					dfree(lease -> ddns_fwd_name,
					      "nsupdate");
				lease -> ddns_fwd_name = 0;
			}
		}
		break;
	}
	return;
}
#endif /* defined (NSUPDATE) */
