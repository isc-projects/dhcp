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
"$Id: nsupdate.c,v 1.12 1999/10/14 17:47:54 mellon Exp $ Copyright (c) 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

#if defined (NSUPDATE)
/* Yet another new plan.
   First thing to be done is to determine if a change actually needs to be
   done.  This can be done by figuring out the hostname.domain and revname
   and then comparing them to the lease->ddns* values.  Only make the changes
   necessary which can be any combination and number of remove A, add A,
   remove PTR, add PTR.

   Wed Sep 29 02:06:33 PDT 1999
   SCRAP THAT!  Let the DNS server determine whether an add/delete should
   be done by giving it pre-requisites to the add/delete.
 */

#define NAME(x)	(x) ? (char *)(x) : "(null)"

#if 0
/* Return the reverse name of a lease. */
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
	if (oc && evaluate_option_cache (&d, packet, lease,
					 packet -> options, state -> options,
					 oc)) {
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
#if defined (NO_SNPRINTF)
	sprintf(revname, "%d.%d.%d.%d.%s.",
		 lease->ip_addr.iabuf[3], lease->ip_addr.iabuf[2],
		 lease->ip_addr.iabuf[1], lease->ip_addr.iabuf[0], revdomain);
#else
	snprintf(revname, MAXDNAME, "%d.%d.%d.%d.%s.",
		 lease->ip_addr.iabuf[3], lease->ip_addr.iabuf[2],
		 lease->ip_addr.iabuf[1], lease->ip_addr.iabuf[0], revdomain);
#endif
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
	if (oc && evaluate_option_cache (&d, packet, lease,
					 packet -> options, state -> options,
					 oc)) {
		memcpy(domain, d.data, d.len);
		domain[d.len]='\0';
		data_string_forget (&d, "nsupdate");
	} else {
		oc = lookup_option (&dhcp_universe, state -> options,
				    DHO_DOMAIN_NAME);
		memset (&d, 0, sizeof d);
		if (oc && evaluate_option_cache (&d, packet, lease,
						 packet -> options,
						 state -> options,
						 oc)) {
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
	if (oc && evaluate_option_cache (&d, packet, lease,
					 packet -> options, state -> options,
					 oc)) {
		memcpy(hostname, d.data, d.len);
		hostname[d.len]='\0';
		data_string_forget (&d, "nsupdate");
	} else {
		oc = lookup_option (&dhcp_universe,
				    packet -> options, DHO_HOST_NAME);
		memset (&d, 0, sizeof d);
		if (oc && evaluate_option_cache (&d, packet, lease,
						 packet -> options,
						 state -> options, oc)) {
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

#if defined (NO_SNPRINTF)
	if (sprintf(hostname, "%s.%s.", hostname, domain) < 0) {
		log_error("nsupdate: Build FQDN failed");
		return NULL;
	}
#else
	if (snprintf(hostname, MAXDNAME, "%s.%s.", hostname, domain) < 0) {
		log_error("nsupdate: Build FQDN failed");
		return NULL;
	}
#endif
	return hostname;
}
#endif /* 0 */

int nsupdateA (hostname, ip_addr, ttl, opcode)
	const char *hostname;
	const unsigned char *ip_addr;
	u_int32_t ttl;
	int opcode;
{
	int z;
	ns_updrec *p, *u;

	/* set up update section */
	if (!(u = res_mkupdrec (S_UPDATE, hostname, C_IN, T_A, ttl)))
		return 0;
	u -> r_opcode = opcode;
	u -> r_data = (char *)ip_addr;

#if 0 /* no PREREQUISITES are needed for adds and deletes, as there is no zone
	 churn when you add a record that exists or delete a record that
	 doesn't exist */

	/* set up the prerequisite section */
	if (!(p = res_mkupdrec (S_PREREQ, hostname, C_IN, T_A, 0))) {
		res_freeupdrec (u);
		return 0;
	}
	p -> r_next = u;
	p -> r_data = (char *)ip_addr;
#endif

	switch (opcode) {
	      case ADD:
		if (!ip_addr) {		/* can't have NULL ip_addr for an ADD */
#if 0
			res_freeupdrec (p);
#endif
			res_freeupdrec (u);
			return 0;
		}
#if 0
		/* PREQUISITE: add only if the RR is not there already */
		p -> r_opcode = NXRRSET;
		p -> r_size = strlen ((const char *)p -> r_data);
#endif
		u -> r_size = strlen ((const char *)u -> r_data);
		break;
	      case DELETE:
		ttl = 0;	/* delete updates ALWAYS have a 0 TTL */
#if 0
		/* PREQUISITE: delete only if the RR to be deleted is there */
		p -> r_opcode = YXRRSET;
#endif
		/* NOTE: ip_addr could be NULL for a "DELETE all records" */
		if (u -> r_data) {
#if 0
			p -> r_size = strlen ((const char *)n -> r_data);
#endif
			u -> r_size = strlen ((const char *)u -> r_data);
		} else {
#if 0
			p -> r_size = 0;
#endif
			u -> r_size = 0;
		}
		break;
	}
	z = res_update (u);
	log_info ("%s %s: %s %ld IN A %s", opcode == ADD ? "add" : "delete",
		  z == 1 ? "succeeded" : "failed", NAME (hostname), ttl,
		  NAME (u -> r_data));
#if 0
	res_freeupdrec (p);
#endif
	res_freeupdrec (u);
	return z;
}

int nsupdatePTR (revname, hostname, ttl, opcode)
	const char *revname;
	const unsigned char *hostname;
	u_int32_t ttl;
	int opcode;
{
	int z;
	ns_updrec *u, *p;

	/* set up update section */
	if (!(u = res_mkupdrec (S_UPDATE, revname, C_IN, T_PTR, ttl)))
		return 0;
	u -> r_opcode = opcode;
	u -> r_data = (char *)hostname;

#if 0 /* don't need PREREQUISITES */
	/* set up the prerequisite section */
	if (!(p = res_mkupdrec (S_PREREQ, revname, C_IN, T_PTR, 0))) {
		res_freeupdrec (u);
		return 0;
	}
	p -> r_next = u;
	p -> r_data = (char *)hostname;
#endif
	
	switch (opcode) {
	      case ADD:
		/* can't have NULL ip_addr for an ADD */
		if (!hostname) {
#if 0
			res_freeupdrec (p);
#endif
			res_freeupdrec (u);
			return 0;
		}
#if 0
		/* PREQUISITE: add only if the RR is not there already */
		p -> r_opcode = NXRRSET;
		p -> r_size = strlen ((const char *)p -> r_data);
#endif
		u -> r_size = strlen ((const char *)u -> r_data);
		
		break;
	      case DELETE:
		ttl = 0;	/* delete updates ALWAYS have a 0 TTL */
#if 0
		/* PREQUISITE: delete only if the RR to be deleted is there */
		p->r_opcode = YXRRSET;
		/* NOTE: hostname could be NULL for a "DELETE all records" */
#endif
		if (u -> r_data) {
#if 0
			p -> r_size = strlen ((const char *)p -> r_data);
#endif
			u -> r_size = strlen ((const char *)u -> r_data);
		} else {
#if 0
			p -> r_size = 0;
#endif
			u -> r_size = 0;
		}
		break;
	}
	z = res_update(u);
	log_info ("%s %s: %s %ld IN PTR %s", opcode == ADD ? "add" : 
		  "delete", z == 1 ? "succeeded" : "failed",
		  NAME (revname), ttl, NAME (u -> r_data));
#if 0
	res_freeupdrec (p);
#endif
	res_freeupdrec (u);
	return z;
}

#if 0
void nsupdate(lease, state, packet, opcode)
	struct lease *lease;
	struct lease_state *state;
	struct packet *packet;
	int	opcode;
{
	char	*hostname, *revname;
	u_int32_t	ttl = 0;

return;
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
		
		if (state -> offered_expiry > lease -> timestamp)
			ttl = state -> offered_expiry -
			lease->timestamp;
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
			    nsupdatePTR(revname, lease -> ddns_fwd_name,
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
		    	z = nsupdateA (hostname,
				       piaddr (lease -> ip_addr), ttl, ADD);
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
			if (nsupdatePTR(revname, hostname, ttl, ADD)) {
				/* remember in the lease struct for release */
				lease -> ddns_rev_name =
				       dmalloc (strlen (revname) + 1,
						"nsupdate");
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
			    nsupdatePTR(lease -> ddns_rev_name,
					lease -> ddns_fwd_name,
					ttl, opcode)) {
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
#endif

/* public function to update an A record */
int updateA (lhs, rhs, ttl, lease)
	const struct data_string *lhs;
	const struct data_string *rhs;
	unsigned int ttl;
	struct lease *lease;
{

	static char hostname[MAXDNAME];
	static char ipaddr[MAXDNAME];
	int y;

	hostname[0] = '\0';
	strncat(hostname, (const char *)lhs -> data, lhs -> len);
	hostname[lhs -> len] = '\0';
	
	ipaddr[0] = '\0';
	strncat(ipaddr, (const char *)rhs -> data, rhs -> len);
	ipaddr[rhs -> len] = '\0';

#if 0	/* Wrong!  This causes zone churn on every DHCPREQUEST!
	   Besides, it is perfectly legal for a DHCP client to have more
	   than one lease, if (say) it was being served by two+ DHCP servers
	   serving the same subnet with different (i.e. disjoint) pools.
	   The right thing to do is have the A records cleaned by either a
	   DHCPRELEASE or the lease expiry.  */
    
	/* delete all existing A records for this host */
	nsupdateA (hostname, NULL, 0, DELETE);
#endif

	/* clear the forward DNS name pointer */
	if (lease -> ddns_fwd_name)
		dfree (lease -> ddns_fwd_name, "nsupdate");
	lease -> ddns_fwd_name = 0;

	y=nsupdateA (hostname, ipaddr, ttl, ADD);
	if (y < 1)
		return 0;

	/* remember this in the lease structure for release */
	lease -> ddns_fwd_name = dmalloc (strlen(hostname) + 1, "nsupdate");
	strcpy (lease -> ddns_fwd_name, hostname);

	return 1;
}

/* public function to update an PTR record */
int updatePTR (lhs, rhs, ttl, lease)
	const struct data_string *lhs;
	const struct data_string *rhs;
	unsigned int ttl;
	struct lease *lease;
{

	static char hostname[MAXDNAME];
	static char revname[MAXDNAME];
	int y;

	revname[0] = '\0';
	strncat(revname, (const char *)lhs -> data, lhs -> len);
	revname[lhs -> len] = '\0';

	hostname[0] = '\0';
	strncat(hostname, (const char *)rhs -> data, rhs -> len);
	hostname[rhs -> len] = '\0';

#if 0	/* Wrong!  This causes zone churn on every DHCPREQUEST!
	   Besides, it is perfectly legal for a DHCP client to have more
	   than one lease, if (say) it was being served by two+ DHCP servers
	   serving the same subnet with different (i.e. disjoint) pools.
	   The right thing to do is have the PTR records cleaned by either a
	   DHCPRELEASE or the lease expiry.  */
 	
	/* delete all existing PTR records */
	nsupdatePTR (revname, NULL, 0, DELETE);
#endif

	/* clear the reverse DNS name pointer */
	if (lease -> ddns_rev_name)
		dfree (lease -> ddns_rev_name, "nsupdate");
	lease -> ddns_rev_name = 0;

	y=nsupdatePTR (revname, hostname, ttl, ADD);
	if (y < 1)
		return 0;

	/* remember this in the lease structure for release */
	lease -> ddns_rev_name = dmalloc (strlen(revname) + 1, "nsupdate");
	strcpy (lease -> ddns_rev_name, revname);

	return 1;
}

/* public function to delete an A record */
int deleteA (lhs, rhs, lease)
	const struct data_string *lhs;
	const struct data_string *rhs;
	struct lease *lease;
{

	static char hostname[MAXDNAME];
	static char ipaddr[MAXDNAME];
	int y;

	hostname[0] = '\0';
	strncat(hostname, (const char *)lhs -> data, lhs -> len);
	hostname[lhs -> len] = '\0';
	
	ipaddr[0] = '\0';
	strncat(ipaddr, (const char *)rhs -> data, rhs -> len);
	ipaddr[rhs -> len] = '\0';

#if 0	/* Wrong!  This causes zone churn on every DHCPREQUEST!
	   Besides, it is perfectly legal for a DHCP client to have more
	   than one lease, if (say) it was being served by two+ DHCP servers
	   serving the same subnet with different (i.e. disjoint) pools.
	   The right thing to do is have the A records cleaned by either a
	   DHCPRELEASE or the lease expiry.  */
    
	/* delete all existing A records for this host */
	nsupdateA (hostname, NULL, 0, DELETE);
#endif

	y=nsupdateA (hostname, ipaddr, 0, DELETE);
	if (y < 1)
		return 0;

#if 0 /* do we really need to do this? */
	/* clear the forward DNS name pointer */
	if (lease -> ddns_fwd_name)
		dfree (lease -> ddns_fwd_name, "nsupdate");
	lease -> ddns_fwd_name = 0;
#endif

	return 1;
}

/* public function to delete a PTR record */
int deletePTR (lhs, rhs, lease)
	const struct data_string *lhs;
	const struct data_string *rhs;
	struct lease *lease;
{

	static char hostname[MAXDNAME];
	static char revname[MAXDNAME];
	int y;

	revname[0] = '\0';
	strncat(revname, (const char *)lhs -> data, lhs -> len);
	revname[lhs -> len] = '\0';

	hostname[0] = '\0';
	strncat(hostname, (const char *)rhs -> data, rhs -> len);
	hostname[rhs -> len] = '\0';

#if 0	/* Wrong!  This causes zone churn on every DHCPREQUEST!
	   Besides, it is perfectly legal for a DHCP client to have more
	   than one lease, if (say) it was being served by two+ DHCP servers
	   serving the same subnet with different (i.e. disjoint) pools.
	   The right thing to do is have the PTR records cleaned by either a
	   DHCPRELEASE or the lease expiry.  */
 	
	/* delete all existing PTR records */
	nsupdatePTR (revname, NULL, 0, DELETE);
#endif

	y=nsupdatePTR (revname, hostname, 0, DELETE);
	if (y < 1)
		return 0;

#if 0 /* do we really need to do this? */
	/* clear the reverse DNS name pointer */
	if (lease -> ddns_rev_name)
		dfree (lease -> ddns_rev_name, "nsupdate");
	lease -> ddns_rev_name = 0;
#endif

	return 1;
}
#endif /* defined (NSUPDATE) */

/* vim: set tabstop=8: */
