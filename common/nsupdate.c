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
"$Id: nsupdate.c,v 1.3.2.2 1999/10/07 21:36:03 mellon Exp $ Copyright (c) 1999 The Internet Software Consortium.  All rights reserved.\n";
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
char *ddns_rev_name(lease, state, packet)
	struct lease *lease;
	struct lease_state *state;
	struct packet *packet;
{
	struct option_cache *oc = NULL;
	struct data_string d;
	static char revname[MAXDNAME];
	char	revdomain[MAXDNAME];

	revname[0]='\0';
	revdomain[0]='\0';

	/* Figure out what reverse domain to update
	   First take the scoped "ddns-rev-domainname" option if present
	   then assume d.c.b.a.in-addr.arpa. if not present
	   error if neither are present */
	oc = lookup_option (&server_universe, state -> options,
			    SV_DDNS_REV_DOMAIN_NAME);
	memset (&d, 0, sizeof d);
	if (oc && evaluate_option_cache (&d, packet,
					 packet -> options, lease, oc)) {
		memcpy(revdomain, d.data, d.len);
		revdomain[d.len]='\0';
		data_string_forget (&d, "nsupdate");
	} else
		strcpy(revdomain, "in-addr.arpa");
	if ( lease->ip_addr.len != 4 ) { /* IPv4 */
		log_error("unsupported IP address length: %d",
			  lease->ip_addr.len);
		return NULL;
	}
	snprintf(revname, MAXDNAME, "%d.%d.%d.%d.%s.",
		 lease->ip_addr.iabuf[3], lease->ip_addr.iabuf[2],
		 lease->ip_addr.iabuf[1], lease->ip_addr.iabuf[0], revdomain);

	return revname;
}

/* Return the forward name of a lease. */
char *ddns_fwd_name(lease, state, packet)
	struct lease *lease;
	struct lease_state *state;
	struct packet *packet;
{
	struct option_cache *oc = NULL;
	struct data_string d;
	static char hostname[MAXDNAME];
	char	domain[MAXDNAME];

	domain[0]='\0';
	hostname[0]='\0';

	/* Figure out the domain name of a lease.
	   First take the scoped "ddns-domainname" option if present
	   then the dhcp option "domain-name" if present
	   error if neither are present */
	oc = lookup_option (&server_universe, state -> options,
			    SV_DDNS_DOMAIN_NAME);
	memset (&d, 0, sizeof d);
	if (oc && evaluate_option_cache (&d, packet,
					 packet -> options, lease, oc)) {
		memcpy(domain, d.data, d.len);
		domain[d.len]='\0';
		data_string_forget (&d, "nsupdate");
	} else {
		oc = lookup_option (&dhcp_universe, state -> options,
				    DHO_DOMAIN_NAME);
		memset (&d, 0, sizeof d);
		if (oc && evaluate_option_cache (&d, packet, packet -> options,
						 lease, oc)) {
			memcpy(domain, d.data, d.len);
			domain[d.len]='\0';
			data_string_forget (&d, "nsupdate");
		} else {
			log_info("nsupdate failed: %s",
				 "unknown domain for update");
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
	memset (&d, 0, sizeof d);
	if (oc && evaluate_option_cache (&d, packet,
					 state -> options, lease, oc)) {
		memcpy(hostname, d.data, d.len);
		hostname[d.len]='\0';
		data_string_forget (&d, "nsupdate");
	} else {
		oc = lookup_option (&dhcp_universe,
				    packet -> options, DHO_HOST_NAME);
		memset (&d, 0, sizeof d);
		if (oc && evaluate_option_cache (&d, packet, packet -> options,
						 lease, oc)) {
			memcpy(hostname, d.data, d.len);
			hostname[d.len]='\0';
			data_string_forget (&d, "nsupdate");
		} else {
			if (lease -> host && lease -> host -> name &&
			    strcmp(lease -> host -> name, "")!=0)
				strcpy(hostname, lease -> host -> name);
			else {
				log_info("nsupdate failed: %s",
					 "unknown hostname for update");
				return NULL;
			}
		}
	}
	if ( !res_hnok(hostname) ) {
		log_error("nsupdate: Bad hostname \"%s\"", hostname);
		return NULL;
	}

	if (snprintf(hostname, MAXDNAME, "%s.%s.", hostname, domain) < 0) {
		log_error("nsupdate: Build FQDN failed");
		return NULL;
	}

	return hostname;
}

int nsupdateA(hostname, ip_addr, ttl, opcode)
	char *hostname;
	char *ip_addr;
	u_int32_t ttl;
	int	opcode;
{
	int 	z;
	ns_updrec	*u, *n;

	switch (opcode) {
	case ADD:
		if (!(u = res_mkupdrec(S_PREREQ, hostname, C_IN, T_A, 0))) 
			return 0;
		u->r_opcode = NXRRSET; u->r_data = NULL; u->r_size = 0;
		if (!(n = res_mkupdrec(S_UPDATE, hostname, C_IN, T_A, ttl))) {
			res_freeupdrec(u);
			return 0;
		}
		n->r_opcode = opcode;
		n->r_data = ip_addr;
		n->r_size = strlen(n->r_data);
		u->r_next = n;
		z = res_update(u);
		log_info("add %s: %s %d IN A %s",
			 z == 1 ? "succeeded" : "failed", hostname, ttl,
			 n->r_data);
		res_freeupdrec(u); 
		res_freeupdrec(n);
/* do we really need to do this?  If so, it needs to be done elsewehere as
   this function is strictly for manipulating the A record
		if (z < 1) 
			return 0;
*/
		/* delete all PTR RRs with the same ip address. Wow! */
/*
		if (!(u = res_mkupdrec(S_UPDATE, revname, C_IN, T_PTR, 0)))
			return 0;
		u->r_opcode = DELETE; u->r_data = NULL; u->r_size = 0;
		log_info("cleaning all PTR RRs for %s", revname);
		res_update(u);
		res_freeupdrec(u);
*/
		break;
	case	DELETE:
		ttl = 0;
		if (!(u = res_mkupdrec(S_UPDATE, hostname, C_IN, T_A, ttl)))
			return 0;
		u->r_opcode = opcode;
		u->r_data = ip_addr;
		u->r_size = strlen(u->r_data);
		z = res_update(u);
		log_info("delete %s: %s %d IN A %s",
			 z == 1 ? "succeeded" : "failed",
			 hostname, ttl, u->r_data);
		res_freeupdrec(u);
		break;
	}
	return z;
}

int nsupdatePTR(hostname, revname, ttl, opcode)
	char *hostname;
	char *revname;
	u_int32_t ttl;
	int	opcode;
{
	int 	z;
	ns_updrec	*u;

	if (opcode == DELETE)
		ttl = 0;
	if (!(u = res_mkupdrec(S_UPDATE, revname, C_IN, T_PTR, ttl)))
		return 0;
	u->r_opcode = opcode;
	u->r_data = hostname;
	u->r_size = strlen(u->r_data);
	z = res_update(u);
	log_info("%s %s: %s %d IN PTR %s", 
		 opcode == ADD ? "add" : 
				 "delete", z == 1 ? "succeeded" : "failed",
		 revname, ttl, hostname);
	res_freeupdrec(u);
	return z;
}

void nsupdate(lease, state, packet, opcode)
	struct lease *lease;
	struct lease_state *state;
	struct packet *packet;
	int	opcode;
{
	char	*hostname, *revname;
	u_int32_t	ttl = 0;

	if (!(opcode == ADD || opcode == DELETE))
		return;

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
	if (!lease){
		log_info("invalid pointer at %s:%d",
			 __FILE__, __LINE__-2);
		return;
	}
	
	switch (opcode) {
	case ADD:
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

		hostname = ddns_fwd_name(lease, state, packet);
		if (!hostname)	/* there is nothing we can do now */
			return;
		revname = ddns_rev_name(lease, state, packet);
		
		if (state -> offered_expiry > cur_time)
			ttl = state -> offered_expiry - cur_time;
		else
			log_error("nsupdate: ttl < 0");

		/* delete an existing A if the one to be added is different */
		if (lease -> ddns_fwd_name &&
		    strcmp(hostname, lease -> ddns_fwd_name)) {
			int y;
			y=nsupdateA(lease -> ddns_fwd_name,
				    piaddr(lease->ip_addr), ttl, DELETE);

			/* delete an existing PTR if new one is different */
			if (lease -> ddns_rev_name &&
			    (strcmp(hostname, lease -> ddns_fwd_name) ||
			     strcmp(revname, lease -> ddns_rev_name)) &&
			    nsupdatePTR(lease -> ddns_fwd_name, revname,
					      ttl, DELETE)) {
				/* clear the forward DNS name pointer */
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
		/* only update if there is no A record there already */
		if (!lease -> ddns_fwd_name) {
			int z;
		    	z=nsupdateA(hostname, piaddr(lease->ip_addr), ttl, ADD);
			if (z < 1)
				return;

			/* remember this in the lease structure for release */
			lease -> ddns_fwd_name = dmalloc(strlen(hostname) + 1,
						 	 "nsupdate");
			strcpy (lease -> ddns_fwd_name, hostname);
		}

		if (!revname)	/* there is nothing more we can do now */
			return;

	/* This is where a deletion of all PTRs for this addy could
	   go, but I am reluctant to overburden the DHCP and DNS
	   servers with requests that should be invalid if this is
	   really a problem then somebody else is inserting PTRs and
	   they should stop, rather than this being turned into a
	   garbage cleanup routine */

		if (!lease -> ddns_rev_name) {
			/* add a PTR RR */
			if (nsupdatePTR(hostname, revname, ttl, ADD)) {
				/* remember in the lease struct for a release */
				lease -> ddns_rev_name =
				       dmalloc(strlen(revname) + 1, "nsupdate");
				strcpy (lease -> ddns_rev_name, revname);
			}
		}
		break;
	case DELETE:
		ttl = 0;
		if (lease -> ddns_fwd_name) {
			int y;
			y = nsupdateA(lease -> ddns_fwd_name,
				      piaddr(lease->ip_addr), ttl, DELETE);

			if (lease -> ddns_rev_name &&
			    nsupdatePTR(lease -> ddns_fwd_name,
					lease -> ddns_rev_name, ttl, opcode)) {
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
