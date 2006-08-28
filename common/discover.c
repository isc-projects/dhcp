/* discover.c

   Find and identify the network interfaces. */

/*
 * Copyright (c) 2004-2006 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1995-2003 by Internet Software Consortium
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   http://www.isc.org/
 *
 * This software has been written for Internet Systems Consortium
 * by Ted Lemon in cooperation with Vixie Enterprises and Nominum, Inc.
 * To learn more about Internet Systems Consortium, see
 * ``http://www.isc.org/''.  To learn more about Vixie Enterprises,
 * see ``http://www.vix.com''.   To learn more about Nominum, Inc., see
 * ``http://www.nominum.com''.
 */

#ifndef lint
static char copyright[] =
"$Id: discover.c,v 1.50.90.3 2006/08/28 18:16:49 shane Exp $ Copyright (c) 2004-2006 Internet Systems Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include <sys/ioctl.h>

struct interface_info *interfaces, *dummy_interfaces, *fallback_interface;
int interfaces_invalidated;
int quiet_interface_discovery;
u_int16_t local_port;
u_int16_t remote_port;
int (*dhcp_interface_setup_hook) (struct interface_info *, struct iaddr *);
int (*dhcp_interface_discovery_hook) (struct interface_info *);
isc_result_t (*dhcp_interface_startup_hook) (struct interface_info *);
int (*dhcp_interface_shutdown_hook) (struct interface_info *);

struct in_addr limited_broadcast;

int local_family = AF_INET6;
struct in_addr local_address;
struct in6_addr local_address6;

void (*bootp_packet_handler) PROTO ((struct interface_info *,
				     struct dhcp_packet *, unsigned,
				     unsigned int,
				     struct iaddr, struct hardware *));
void (*dhcpv6_packet_handler)(struct interface_info *,
			      const struct dhcpv6_packet *, int,
			      int, const struct iaddr *);


omapi_object_type_t *dhcp_type_interface;
#if defined (TRACING)
trace_type_t *interface_trace;
trace_type_t *inpacket_trace;
trace_type_t *outpacket_trace;
#endif
struct interface_info **interface_vector;
int interface_count;
int interface_max;

OMAPI_OBJECT_ALLOC (interface, struct interface_info, dhcp_type_interface)

isc_result_t interface_setup ()
{
	isc_result_t status;
	status = omapi_object_type_register (&dhcp_type_interface,
					     "interface",
					     dhcp_interface_set_value,
					     dhcp_interface_get_value,
					     dhcp_interface_destroy,
					     dhcp_interface_signal_handler,
					     dhcp_interface_stuff_values,
					     dhcp_interface_lookup, 
					     dhcp_interface_create,
					     dhcp_interface_remove,
					     0, 0, 0,
					     sizeof (struct interface_info),
					     interface_initialize, RC_MISC);
	if (status != ISC_R_SUCCESS)
		log_fatal ("Can't register interface object type: %s",
			   isc_result_totext (status));

	return status;
}

#if defined (TRACING)
void interface_trace_setup ()
{
	interface_trace = trace_type_register ("interface", (void *)0,
					       trace_interface_input,
					       trace_interface_stop, MDL);
	inpacket_trace = trace_type_register ("inpacket", (void *)0,
					       trace_inpacket_input,
					       trace_inpacket_stop, MDL);
	outpacket_trace = trace_type_register ("outpacket", (void *)0,
					       trace_outpacket_input,
					       trace_outpacket_stop, MDL);
}
#endif

isc_result_t interface_initialize (omapi_object_t *ipo,
				   const char *file, int line)
{
	struct interface_info *ip = (struct interface_info *)ipo;
	ip -> rfdesc = ip -> wfdesc = -1;
	return ISC_R_SUCCESS;
}

/* XXX: needs to be autoconfiscated */
#define HAVE_SIOCGLIFCONF

/* 
 * Solaris' extended interface is documented in the if_tcp man page.
 */
#ifdef HAVE_SIOCGLIFCONF
struct iface_conf_list {
	int sock;
	int num;
	struct lifconf conf;
	int next;
};

struct iface_info {
	char name[LIFNAMSIZ];
	struct sockaddr_storage addr;
	isc_uint64_t flags;
};

int 
begin_iface_scan(struct iface_conf_list *ifaces) {
	struct lifnum lifnum;

	ifaces->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ifaces->sock < 0) {
		log_error("Error creating socket to list interfaces; %m");
		return 0;
	}

	memset(&lifnum, 0, sizeof(lifnum));
	lifnum.lifn_family = AF_UNSPEC;
	if (ioctl(ifaces->sock, SIOCGLIFNUM, &lifnum) < 0) {
		log_error("Error finding total number of interfaces; %m");
		close(ifaces->sock);
		ifaces->sock = -1;
		return 0;
	}

	ifaces->num = lifnum.lifn_count;
	memset(&ifaces->conf, 0, sizeof(ifaces->conf));
	ifaces->conf.lifc_family = AF_UNSPEC;
	ifaces->conf.lifc_len = ifaces->num * sizeof(struct lifreq);
	ifaces->conf.lifc_buf = dmalloc(ifaces->conf.lifc_len, MDL);
	if (ifaces->conf.lifc_buf == NULL) {
		log_fatal("Out of memory getting interface list.");
	}

	if (ioctl(ifaces->sock, SIOCGLIFCONF, &ifaces->conf) < 0) {
		log_error("Error getting interfaces configuration list; %m");
		dfree(ifaces->conf.lifc_buf, MDL);
		close(ifaces->sock);
		ifaces->sock = -1;
		return 0;
	}

	ifaces->next = 0;

	return 1;
}

int
next_iface(struct iface_info *info, int *err, struct iface_conf_list *ifaces) {
	struct lifreq *p;
	struct lifreq tmp;
	char *s;

	do {
		if (ifaces->next >= ifaces->num) {
			*err = 0;
			return 0;
		}

		p = ifaces->conf.lifc_req;
		p += ifaces->next;

		strcpy(info->name, p->lifr_name);
		info->addr = p->lifr_addr;

#ifdef ALIAS_NAMED_PERMUTED
		/* interface aliases look like "eth0:1" or "wlan1:3" */
		s = strchr(info->name, ':');
		if (s != NULL) {
			*s = '\0';
		}
#endif

#ifdef SKIP_DUMMY_INTERFACES
	} while (strncmp(info->name, "dummy", 5) == 0);
#else
	} while (0);
#endif
	
	memset(&tmp, 0, sizeof(tmp));
	strcpy(tmp.lifr_name, p->lifr_name);
	if (ioctl(ifaces->sock, SIOCGLIFFLAGS, &tmp) < 0) {
		log_error("Error getting interfaces flags for %s; %m", 
			  p->lifr_name);
		*err = 1;
		return 0;
	}
	info->flags = tmp.lifr_flags;

	ifaces->next++;
	*err = 0;
	return 1;
}

void
end_iface_scan(struct iface_conf_list *ifaces) {
	dfree(ifaces->conf.lifc_buf, MDL);
	close(ifaces->sock);
	ifaces->sock = -1;
}
#else
/* XXX: need non-Solaris versions */
#endif 

/* XXX: perhaps create drealloc() rather than do it manually */
void
add_ipv4_addr_to_interface(struct interface_info *iface, 
			   const struct in_addr *addr) {
	if (iface->addresses == NULL) {
		iface->addresses = dmalloc(4 * sizeof(struct in_addr), MDL);
		if (iface->addresses == NULL) {
			log_fatal("Out of memory saving IPv4 address "
			          "on interface.");
		}
		iface->address_count = 0;
		iface->address_max = 4;
	} else if (iface->address_count >= iface->address_max) {
		struct in_addr *tmp;
		int new_max;

		new_max = iface->address_max + 4;
		tmp = dmalloc(new_max * sizeof(struct in_addr), MDL);
		if (tmp == NULL) {
			log_fatal("Out of memory saving IPv4 address "
			          "on interface.");
		}
		memcpy(tmp, 
		       iface->addresses, 
		       iface->address_max * sizeof(struct in_addr));
		dfree(iface->addresses, MDL);
		iface->addresses = tmp;
		iface->address_max = new_max;
	}
	iface->addresses[iface->address_count++] = *addr;
}

/* XXX: perhaps create drealloc() rather than do it manually */
void
add_ipv6_addr_to_interface(struct interface_info *iface, 
			   const struct in6_addr *addr) {
	if (iface->v6addresses == NULL) {
		iface->v6addresses = dmalloc(4 * sizeof(struct in6_addr), MDL);
		if (iface->v6addresses == NULL) {
			log_fatal("Out of memory saving IPv6 address "
				  "on interface.");
		}
		iface->v6address_count = 0;
		iface->v6address_max = 8;
	} else if (iface->v6address_count >= iface->v6address_max) {
		struct in6_addr *tmp;
		int new_max;

		new_max = iface->v6address_max + 8;
		tmp = dmalloc(new_max * sizeof(struct in6_addr), MDL);
		if (tmp == NULL) {
			log_fatal("Out of memory saving IPv6 address "
				  "on interface.");
		}
		memcpy(tmp, 
		       iface->v6addresses, 
		       iface->v6address_max * sizeof(struct in6_addr));
		dfree(iface->v6addresses, MDL);
		iface->v6addresses = tmp;
		iface->v6address_max = new_max;
	}
	iface->v6addresses[iface->v6address_count++] = *addr;
}

/* Use the SIOCGIFCONF ioctl to get a list of all the attached interfaces.
   For each interface that's of type INET and not the loopback interface,
   register that interface with the network I/O software, figure out what
   subnet it's on, and add it to the list of interfaces. */

void 
discover_interfaces(int state) {
	struct iface_conf_list ifaces;
	struct iface_info info;
	int err;

	struct interface_info *tmp, *ip;
	struct interface_info *last, *next;

	char abuf[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];

	struct subnet *subnet;
	int ir;
	isc_result_t status;
	int wifcount = 0;

	static int setup_fallback = 0;

	if (!begin_iface_scan(&ifaces)) {
		log_fatal("Can't get list of interfaces.");
	}

	/* If we already have a list of interfaces, and we're running as
	   a DHCP server, the interfaces were requested. */
	if (interfaces && (state == DISCOVER_SERVER ||
			   state == DISCOVER_RELAY ||
			   state == DISCOVER_REQUESTED))
		ir = 0;
	else if (state == DISCOVER_UNCONFIGURED)
		ir = INTERFACE_REQUESTED | INTERFACE_AUTOMATIC;
	else
		ir = INTERFACE_REQUESTED;

	/* Cycle through the list of interfaces looking for IP addresses. */
	while (next_iface(&info, &err, &ifaces)) {

		/* See if we've seen an interface that matches this one. */
		for (tmp = interfaces; tmp; tmp = tmp->next) {
			if (!strcmp(tmp->name, info.name))
				break;
		}

		/* Skip non broadcast interfaces (plus loopback and
		   point-to-point in case an OS incorrectly marks them
		   as broadcast). Also skip down interfaces unless we're
		   trying to get a list of configurable interfaces. */
		if (((!(info.flags & IFF_BROADCAST) ||
		      info.flags & IFF_LOOPBACK ||
		      info.flags & IFF_POINTOPOINT) && !tmp) ||
		    (!(info.flags & IFF_UP) &&
		     state != DISCOVER_UNCONFIGURED))
			continue;
		
		/* If there isn't already an interface by this name,
		   allocate one. */
		if (tmp == NULL) {
			status = interface_allocate(&tmp, MDL);
			if (status != ISC_R_SUCCESS) {
				log_fatal("Error allocating interface %s: %s",
					  info.name, isc_result_totext(status));
			}
			strcpy(tmp->name, info.name);
			interface_snorf(tmp, ir);
			interface_dereference(&tmp, MDL);
			tmp = interfaces; /* XXX */
		}

		if (dhcp_interface_discovery_hook) {
			(*dhcp_interface_discovery_hook)(tmp);
		}

		/* If we have the capability, extract link information
		   and record it in. */
#ifdef HAVE_AF_LINK
		if (info.addr.ss_family == AF_LINK) {
			struct sockaddr_dl *d = (struct sockaddr_dl*)&info.addr;
			tmp->hw_address.hlen = d->sdl_alen;
			tmp->hw_address.hbuf[0] = HTYPE_ETHER; /* XXX */
			memcpy(&tmp->hw_address.hbuf[1], 
			       LLADDR(d),
			       tmp->hw_address.hlen);
			tmp->hw_address.hlen++;	/* for type. */
		} else
#endif /* AF_LINK */

		if ((info.addr.ss_family == AF_INET) && 
		    (local_family == AF_INET)) {
			struct sockaddr_in *a = (struct sockaddr_in*)&info.addr;
			struct iaddr addr;

			/* We don't want the loopback interface. */
			if (a->sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
			    ((tmp->flags & INTERFACE_AUTOMATIC) &&
			     state == DISCOVER_SERVER))
				continue;

			/* If the only address we have is 0.0.0.0, we
			   shouldn't consider the interface configured. */
			if (a->sin_addr.s_addr != htonl(INADDR_ANY))
				tmp->configured = 1;

			add_ipv4_addr_to_interface(tmp, &a->sin_addr);

/* 
 * XXX: We don't have ifreq in Solaris-land if we want IPv6. Fortunately,
 *      we don't actually need this for anything on Solaris.
 */
#if 0
			/* If this is the first real IP address we've
			   found, keep a pointer to ifreq structure in
			   which we found it. */
			if (!tmp -> ifp) {
#ifdef HAVE_SA_LEN
				unsigned len = ((sizeof ifp -> ifr_name) +
						ifp -> ifr_addr.sa_len);
#else
				unsigned len = sizeof *ifp;
#endif
				tif = (struct ifreq *)dmalloc (len, MDL);
				if (!tif)
					log_fatal ("no space for ifp.");
				memcpy (tif, ifp, len);
				tmp -> ifp = tif;
			}
#endif /* 0 */

			/* invoke the setup hook */
			addr.len = 4;
			memcpy(addr.iabuf, &a->sin_addr.s_addr, addr.len);
			if (dhcp_interface_setup_hook) {
				(*dhcp_interface_setup_hook)(tmp, &addr);
			}
		}
		else if ((info.addr.ss_family == AF_INET6) && 
			 (local_family == AF_INET6)) {
			struct sockaddr_in6 *a = 
					(struct sockaddr_in6*)&info.addr;
			struct iaddr addr;

			/* We don't want the loopback interface. */
			if (IN6_IS_ADDR_LOOPBACK(&a->sin6_addr) && 
			    ((tmp->flags & INTERFACE_AUTOMATIC) &&
			     state == DISCOVER_SERVER))
				continue;

			/* If the only address we have is 0.0.0.0, we
			   shouldn't consider the interface configured. */
			if (IN6_IS_ADDR_UNSPECIFIED(&a->sin6_addr))
				tmp->configured = 1;

			add_ipv6_addr_to_interface(tmp, &a->sin6_addr);

/* 
 * XXX: We don't have ifreq in Solaris-land if we want IPv6. Fortunately,
 *      we don't actually need this for anything on Solaris.
 */
#if 0
			/* If this is the first real IP address we've
			   found, keep a pointer to ifreq structure in
			   which we found it. */
			if (!tmp -> ifp) {
#ifdef HAVE_SA_LEN
				unsigned len = ((sizeof ifp -> ifr_name) +
						ifp -> ifr_addr.sa_len);
#else
				unsigned len = sizeof *ifp;
#endif
				tif = (struct ifreq *)dmalloc (len, MDL);
				if (!tif)
					log_fatal ("no space for ifp.");
				memcpy (tif, ifp, len);
				tmp -> ifp = tif;
			}
#endif /* 0 */

			/* invoke the setup hook */
			addr.len = 16;
			memcpy(addr.iabuf, &a->sin6_addr, addr.len);
			if (dhcp_interface_setup_hook) {
				(*dhcp_interface_setup_hook)(tmp, &addr);
			}
		}
	}

	if (err) {
		log_fatal("Error getting interface information.");
	}

	end_iface_scan(&ifaces);

#if defined (LINUX_SLASHPROC_DISCOVERY)
	/* On Linux, interfaces that don't have IP addresses don't
	   show up in the SIOCGIFCONF syscall.  This only matters for
	   the DHCP client, of course - the relay agent and server
	   should only care about interfaces that are configured with
	   IP addresses anyway.

	   The PROCDEV_DEVICE (/proc/net/dev) is a kernel-supplied file
	   that, when read, prints a human readable network status.   We
	   extract the names of the network devices by skipping the first
	   two lines (which are header) and then parsing off everything
	   up to the colon in each subsequent line - these lines start
	   with the interface name, then a colon, then a bunch of
	   statistics. */

	if (state == DISCOVER_UNCONFIGURED) {
		FILE *proc_dev;
		char buffer [256];
		int skip = 2;

		proc_dev = fopen (PROCDEV_DEVICE, "r");
		if (!proc_dev)
			log_fatal ("%s: %m", PROCDEV_DEVICE);

		while (fgets (buffer, sizeof buffer, proc_dev)) {
			char *name = buffer;
			char *sep;

			/* Skip the first two blocks, which are header
			   lines. */
			if (skip) {
				--skip;
				continue;
			}

			sep = strrchr (buffer, ':');
			if (sep)
				*sep = '\0';
			while (*name == ' ')
				name++;

			/* See if we've seen an interface that matches
			   this one. */
			for (tmp = interfaces; tmp; tmp = tmp -> next)
				if (!strcmp (tmp -> name, name))
					break;

			/* If we found one, nothing more to do.. */
			if (tmp)
				continue;

			strncpy (ifr.ifr_name, name, IFNAMSIZ);

			/* Skip non broadcast interfaces (plus loopback and
			 * point-to-point in case an OS incorrectly marks them
			 * as broadcast).
			 */
			if ((ioctl (sock, SIOCGIFFLAGS, &ifr) < 0) ||
			    (!(ifr.ifr_flags & IFF_BROADCAST)) ||
			    (ifr.ifr_flags & IFF_LOOPBACK ) ||
			    (ifr.ifr_flags & IFF_POINTOPOINT))
				continue;

			/* Otherwise, allocate one. */
			tmp = (struct interface_info *)0;
			status = interface_allocate (&tmp, MDL);
			if (status != ISC_R_SUCCESS)
				log_fatal ("Can't allocate interface %s: %s",
					   name, isc_result_totext (status));
			tmp -> flags = ir;
			strncpy (tmp -> name, name, IFNAMSIZ);
			if (interfaces) {
				interface_reference (&tmp -> next,
						     interfaces, MDL);
				interface_dereference (&interfaces, MDL);
			}
			interface_reference (&interfaces, tmp, MDL);
			interface_dereference (&tmp, MDL);
			tmp = interfaces;

			if (dhcp_interface_discovery_hook)
				(*dhcp_interface_discovery_hook) (tmp);

		}
		fclose (proc_dev);
	}
#endif

	/* Now cycle through all the interfaces we found, looking for
	   hardware addresses. */
	/* XXX: The dlpi interface code will get this information in Solaris */
#if 0
#if defined (HAVE_SIOCGIFHWADDR) && !defined (HAVE_AF_LINK)
	for (tmp = interfaces; tmp != NULL; tmp = tmp->next) {
		struct ifreq ifr;
		struct sockaddr sa;
		int b, sk;
		
		if (!tmp -> ifp) {
			/* Make up an ifreq structure. */
			tif = (struct ifreq *)dmalloc (sizeof (struct ifreq),
						       MDL);
			if (!tif)
				log_fatal ("no space to remember ifp.");
			memset (tif, 0, sizeof (struct ifreq));
			strcpy (tif -> ifr_name, tmp -> name);
			tmp -> ifp = tif;
		}

		/* Read the hardware address from this interface. */
		ifr = *tmp -> ifp;
		if (ioctl (sock, SIOCGIFHWADDR, &ifr) < 0)
			continue;
		
		sa = *(struct sockaddr *)&ifr.ifr_hwaddr;
		
		switch (sa.sa_family) {
#ifdef HAVE_ARPHRD_TUNNEL
		      case ARPHRD_TUNNEL:
			/* ignore tunnel interfaces. */
#endif
#ifdef HAVE_ARPHRD_ROSE
		      case ARPHRD_ROSE:
#endif
#ifdef HAVE_ARPHRD_IRDA
		     case ARPHRD_IRDA:
			/* ignore infrared interfaces. */
#endif
#ifdef HAVE_ARPHRD_SIT
		     case ARPHRD_SIT:
			/* ignore IPv6-in-IPv4 interfaces. */
#endif
#ifdef HAVE_ARPHRD_IEEE1394
		     case ARPHRD_IEEE1394:
			/* ignore IEEE1394 interfaces. */
#endif
#ifdef HAVE_ARPHRD_LOOPBACK
		      case ARPHRD_LOOPBACK:
			/* ignore loopback interface */
			break;
#endif

		      case ARPHRD_ETHER:
			tmp -> hw_address.hlen = 7;
			tmp -> hw_address.hbuf [0] = ARPHRD_ETHER;
			memcpy (&tmp -> hw_address.hbuf [1], sa.sa_data, 6);
			break;

#ifndef HAVE_ARPHRD_IEEE802
# define ARPHRD_IEEE802 HTYPE_IEEE802
#endif
#if defined (HAVE_ARPHRD_IEEE802_TR)
		      case ARPHRD_IEEE802_TR:
#endif
		      case ARPHRD_IEEE802:
			tmp -> hw_address.hlen = 7;
			tmp -> hw_address.hbuf [0] = ARPHRD_IEEE802;
			memcpy (&tmp -> hw_address.hbuf [1], sa.sa_data, 6);
			break;

#ifndef HAVE_ARPHRD_FDDI
# define ARPHRD_FDDI HTYPE_FDDI
#endif
		      case ARPHRD_FDDI:
			tmp -> hw_address.hlen = 17;
			tmp -> hw_address.hbuf [0] = HTYPE_FDDI; /* XXX */
			memcpy (&tmp -> hw_address.hbuf [1], sa.sa_data, 16);
			break;

#ifdef HAVE_ARPHRD_METRICOM
		      case ARPHRD_METRICOM:
			tmp -> hw_address.hlen = 7;
			tmp -> hw_address.hbuf [0] = ARPHRD_METRICOM;
			memcpy (&tmp -> hw_address.hbuf [0], sa.sa_data, 6);
			break;
#endif

#ifdef HAVE_ARPHRD_AX25
		      case ARPHRD_AX25:
			tmp -> hw_address.hlen = 7;
			tmp -> hw_address.hbuf [0] = ARPHRD_AX25;
			memcpy (&tmp -> hw_address.hbuf [1], sa.sa_data, 6);
			break;
#endif

#ifdef HAVE_ARPHRD_NETROM
		      case ARPHRD_NETROM:
			tmp -> hw_address.hlen = 7;
			tmp -> hw_address.hbuf [0] = ARPHRD_NETROM;
			memcpy (&tmp -> hw_address.hbuf [1], sa.sa_data, 6);
			break;
#endif

		      default:
			log_error ("%s: unknown hardware address type %d",
				   ifr.ifr_name, sa.sa_family);
			break;
		}
	}
#endif /* defined (HAVE_SIOCGIFHWADDR) && !defined (HAVE_AF_LINK) */
#endif /* 0 */

	/* If we're just trying to get a list of interfaces that we might
	   be able to configure, we can quit now. */
	if (state == DISCOVER_UNCONFIGURED) {
		return;
	}

	/* Weed out the interfaces that did not have IP addresses. */
	tmp = last = next = NULL;
	if (interfaces)
		interface_reference (&tmp, interfaces, MDL);
	while (tmp) {
		if (next)
			interface_dereference (&next, MDL);
		if (tmp -> next)
			interface_reference (&next, tmp -> next, MDL);
		/* skip interfaces that are running already */
		if (tmp -> flags & INTERFACE_RUNNING) {
			interface_dereference(&tmp, MDL);
			if(next)
				interface_reference(&tmp, next, MDL);
			continue;
		}
		if ((tmp -> flags & INTERFACE_AUTOMATIC) &&
		    state == DISCOVER_REQUESTED)
			tmp -> flags &= ~(INTERFACE_AUTOMATIC |
					  INTERFACE_REQUESTED);
/* XXX: no ifp in Solaris */
/*		if (!tmp -> ifp || !(tmp -> flags & INTERFACE_REQUESTED)) {*/
		if (!(tmp->flags & INTERFACE_REQUESTED)) {
			if ((tmp -> flags & INTERFACE_REQUESTED) != ir)
				log_fatal ("%s: not found", tmp -> name);
			if (!last) {
				if (interfaces)
					interface_dereference (&interfaces,
							       MDL);
				if (next)
				interface_reference (&interfaces, next, MDL);
			} else {
				interface_dereference (&last -> next, MDL);
				if (next)
					interface_reference (&last -> next,
							     next, MDL);
			}
			if (tmp -> next)
				interface_dereference (&tmp -> next, MDL);

			/* Remember the interface in case we need to know
			   about it later. */
			if (dummy_interfaces) {
				interface_reference (&tmp -> next,
						     dummy_interfaces, MDL);
				interface_dereference (&dummy_interfaces, MDL);
			}
			interface_reference (&dummy_interfaces, tmp, MDL);
			interface_dereference (&tmp, MDL);
			if (next)
				interface_reference (&tmp, next, MDL);
			continue;
		}
		last = tmp;

/* XXX: no ifp in Solaris */
/*		memcpy (&foo, &tmp -> ifp -> ifr_addr,
			sizeof tmp -> ifp -> ifr_addr);*/

		/* We must have a subnet declaration for each interface. */
		if (!tmp->shared_network && (state == DISCOVER_SERVER)) {
			log_error("%s", "");
			if (local_family == AF_INET) {
				log_error("No subnet declaration for %s (%s).",
					  tmp->name, 
					  inet_ntoa(tmp->addresses[0]));
			} else {
				if (tmp->v6addresses != NULL) {
					inet_ntop(AF_INET6, 
						  &tmp->v6addresses[0],
						  abuf,
						  sizeof(abuf));
				} else {
					strcpy(abuf, "no addresses");
				}
				log_error("No subnet declaration for %s (%s).",
					  tmp->name,
					  abuf);
			}
			if (supports_multiple_interfaces(tmp)) {
				log_error ("** Ignoring requests on %s.  %s",
					   tmp -> name, "If this is not what");
				log_error ("   you want, please write %s",
					   "a subnet declaration");
				log_error ("   in your dhcpd.conf file %s",
					   "for the network segment");
				log_error ("   to %s %s %s",
					   "which interface",
					   tmp -> name, "is attached. **");
				log_error ("%s", "");
				goto next;
			} else {
				log_error ("You must write a subnet %s",
					   " declaration for this");
				log_error ("subnet.   You cannot prevent %s",
					   "the DHCP server");
				log_error ("from listening on this subnet %s",
					   "because your");
				log_fatal ("operating system does not %s.",
					   "support this capability");
			}
		}

		/* Find subnets that don't have valid interface
		   addresses... */
		for (subnet = (tmp -> shared_network
			       ? tmp -> shared_network -> subnets
			       : (struct subnet *)0);
		     subnet; subnet = subnet -> next_sibling) {
			if (!subnet -> interface_address.len) {
				/* Set the interface address for this subnet
				   to the first address we found. */
				subnet -> interface_address.len = 4;
				memcpy (subnet -> interface_address.iabuf,
					&tmp->addresses[0].s_addr, 4);
			}
		}

		/* Flag the index as not having been set, so that the
		   interface registerer can set it or not as it chooses. */
		tmp -> index = -1;

		/* Register the interface... */
		if (local_family == AF_INET) {
			if_register_receive(tmp);
			if_register_send(tmp);
		} else {
			if (state == DISCOVER_SERVER) { 
				if_register6(tmp, 1);
			} else {
				if_register6(tmp, 0);
			}
		}

		interface_stash (tmp);
		wifcount++;
#if defined (HAVE_SETFD)
		if (fcntl (tmp -> rfdesc, F_SETFD, 1) < 0)
			log_error ("Can't set close-on-exec on %s: %m",
				   tmp -> name);
		if (tmp -> rfdesc != tmp -> wfdesc) {
			if (fcntl (tmp -> wfdesc, F_SETFD, 1) < 0)
				log_error ("Can't set close-on-exec on %s: %m",
					   tmp -> name);
		}
#endif
	      next:
		interface_dereference (&tmp, MDL);
		if (next)
			interface_reference (&tmp, next, MDL);
	}

	/* Now register all the remaining interfaces as protocols. */
	for (tmp = interfaces; tmp; tmp = tmp -> next) {
		/* not if it's been registered before */
		if (tmp -> flags & INTERFACE_RUNNING)
			continue;
		if (tmp -> rfdesc == -1)
			continue;
		if (local_family == AF_INET) {
			status = omapi_register_io_object((omapi_object_t *)tmp,
							  if_readsocket, 
							  0, got_one, 0, 0);
		} else {
			status = omapi_register_io_object((omapi_object_t *)tmp,
							  if_readsocket, 
							  0, got_one_v6, 0, 0);
		}
		if (status != ISC_R_SUCCESS)
			log_fatal ("Can't register I/O handle for %s: %s",
				   tmp -> name, isc_result_totext (status));
	}

	if (state == DISCOVER_SERVER && wifcount == 0) {
		log_info ("%s", "");
		log_fatal ("Not configured to listen on any interfaces!");
	}

	if ((local_family == AF_INET) && !setup_fallback) {
		setup_fallback = 1;
		maybe_setup_fallback();
	}

#if defined (HAVE_SETFD)
	if (fallback_interface) {
	    if (fcntl (fallback_interface -> rfdesc, F_SETFD, 1) < 0)
		log_error ("Can't set close-on-exec on fallback: %m");
	    if (fallback_interface -> rfdesc != fallback_interface -> wfdesc) {
		if (fcntl (fallback_interface -> wfdesc, F_SETFD, 1) < 0)
		    log_error ("Can't set close-on-exec on fallback: %m");
	    }
	}
#endif
}

int if_readsocket (h)
	omapi_object_t *h;
{
	struct interface_info *ip;

	if (h -> type != dhcp_type_interface)
		return -1;
	ip = (struct interface_info *)h;
	return ip -> rfdesc;
}

int setup_fallback (struct interface_info **fp, const char *file, int line)
{
	isc_result_t status;

	status = interface_allocate (&fallback_interface, file, line);
	if (status != ISC_R_SUCCESS)
		log_fatal ("Error allocating fallback interface: %s",
			   isc_result_totext (status));
	strcpy (fallback_interface -> name, "fallback");
	if (dhcp_interface_setup_hook)
		(*dhcp_interface_setup_hook) (fallback_interface,
					      (struct iaddr *)0);
	status = interface_reference (fp, fallback_interface, file, line);

	fallback_interface -> index = -1;
	interface_stash (fallback_interface);
	return status == ISC_R_SUCCESS;
}

void reinitialize_interfaces ()
{
	struct interface_info *ip;

	for (ip = interfaces; ip; ip = ip -> next) {
		if_reinitialize_receive (ip);
		if_reinitialize_send (ip);
	}

	if (fallback_interface)
		if_reinitialize_send (fallback_interface);

	interfaces_invalidated = 1;
}

isc_result_t got_one (h)
	omapi_object_t *h;
{
	struct sockaddr_in from;
	struct hardware hfrom;
	struct iaddr ifrom;
	int result;
	union {
		unsigned char packbuf [4095]; /* Packet input buffer.
					 	 Must be as large as largest
						 possible MTU. */
		struct dhcp_packet packet;
	} u;
	struct interface_info *ip;

	if (h -> type != dhcp_type_interface)
		return ISC_R_INVALIDARG;
	ip = (struct interface_info *)h;

      again:
	if ((result =
	     receive_packet (ip, u.packbuf, sizeof u, &from, &hfrom)) < 0) {
		log_error ("receive_packet failed on %s: %m", ip -> name);
		return ISC_R_UNEXPECTED;
	}
	if (result == 0)
		return ISC_R_UNEXPECTED;

	/* If we didn't at least get the fixed portion of the BOOTP
	   packet, drop the packet.  We're allowing packets with no
	   sname or filename, because we're aware of at least one
	   client that sends such packets, but this definitely falls
	   into the category of being forgiving. */
	if (result < DHCP_FIXED_NON_UDP - DHCP_SNAME_LEN - DHCP_FILE_LEN)
		return ISC_R_UNEXPECTED;

	if (bootp_packet_handler) {
		ifrom.len = 4;
		memcpy (ifrom.iabuf, &from.sin_addr, ifrom.len);

		(*bootp_packet_handler) (ip, &u.packet, (unsigned)result,
					 from.sin_port, ifrom, &hfrom);
	}

	/* If there is buffered data, read again.    This is for, e.g.,
	   bpf, which may return two packets at once. */
	if (ip -> rbuf_offset != ip -> rbuf_len)
		goto again;
	return ISC_R_SUCCESS;
}

isc_result_t
got_one_v6(omapi_object_t *h) {
	struct sockaddr_in6 from;
	struct iaddr ifrom;
	int result;
	char buf[65536];	/* maximum size for a UDP packet is 65536 */
	struct interface_info *ip;

	if (h->type != dhcp_type_interface) {
		return ISC_R_INVALIDARG;
	}
	ip = (struct interface_info *)h;

	result = receive_packet6(ip, buf, sizeof(buf), &from);
	if (result < 0) {
		log_error("receive_packet6() failed on %s: %m", ip->name);
		return ISC_R_UNEXPECTED;
	}

	/* 
	 * If we didn't get at least the fixed portion of the DHCPv6
	 * packet, drop the packet. 
	 */
	if (result < 4) {
		return ISC_R_UNEXPECTED;
	}

	if (dhcpv6_packet_handler != NULL) {
		ifrom.len = 16;
		memcpy(ifrom.iabuf, &from.sin6_addr, ifrom.len);

		(*dhcpv6_packet_handler)(ip, (struct dhcpv6_packet *)buf, 
					 result, from.sin6_port, &ifrom);
	}

	return ISC_R_SUCCESS;
}

isc_result_t dhcp_interface_set_value  (omapi_object_t *h,
					omapi_object_t *id,
					omapi_data_string_t *name,
					omapi_typed_data_t *value)
{
	struct interface_info *interface;
	isc_result_t status;
	int foo;

	if (h -> type != dhcp_type_interface)
		return ISC_R_INVALIDARG;
	interface = (struct interface_info *)h;

	if (!omapi_ds_strcmp (name, "name")) {
		if ((value -> type == omapi_datatype_data ||
		     value -> type == omapi_datatype_string) &&
		    value -> u.buffer.len < sizeof interface -> name) {
			memcpy (interface -> name,
				value -> u.buffer.value,
				value -> u.buffer.len);
			interface -> name [value -> u.buffer.len] = 0;
		} else
			return ISC_R_INVALIDARG;
		return ISC_R_SUCCESS;
	}

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> set_value) {
		status = ((*(h -> inner -> type -> set_value))
			  (h -> inner, id, name, value));
		if (status == ISC_R_SUCCESS || status == ISC_R_UNCHANGED)
			return status;
	}
			  
	return ISC_R_NOTFOUND;
}


isc_result_t dhcp_interface_get_value (omapi_object_t *h,
				       omapi_object_t *id,
				       omapi_data_string_t *name,
				       omapi_value_t **value)
{
	return ISC_R_NOTIMPLEMENTED;
}

isc_result_t dhcp_interface_destroy (omapi_object_t *h,
					 const char *file, int line)
{
	struct interface_info *interface;
	isc_result_t status;

	if (h -> type != dhcp_type_interface)
		return ISC_R_INVALIDARG;
	interface = (struct interface_info *)h;

	if (interface -> ifp) {
		dfree (interface -> ifp, file, line);
		interface -> ifp = 0;
	}
	if (interface -> next)
		interface_dereference (&interface -> next, file, line);
	if (interface -> rbuf) {
		dfree (interface -> rbuf, file, line);
		interface -> rbuf = (unsigned char *)0;
	}
	if (interface -> client)
		interface -> client = (struct client_state *)0;

	if (interface -> shared_network)
		omapi_object_dereference ((omapi_object_t **)
					  &interface -> shared_network, MDL);

	return ISC_R_SUCCESS;
}

isc_result_t dhcp_interface_signal_handler (omapi_object_t *h,
					    const char *name, va_list ap)
{
	struct interface_info *ip, *interface;
	struct client_config *config;
	struct client_state *client;
	isc_result_t status;

	if (h -> type != dhcp_type_interface)
		return ISC_R_INVALIDARG;
	interface = (struct interface_info *)h;

	/* If it's an update signal, see if the interface is dead right
	   now, or isn't known at all, and if that's the case, revive it. */
	if (!strcmp (name, "update")) {
		for (ip = dummy_interfaces; ip; ip = ip -> next)
			if (ip == interface)
				break;
		if (ip && dhcp_interface_startup_hook)
			return (*dhcp_interface_startup_hook) (ip);

		for (ip = interfaces; ip; ip = ip -> next)
			if (ip == interface)
				break;
		if (!ip && dhcp_interface_startup_hook)
			return (*dhcp_interface_startup_hook) (ip);
	}

	/* Try to find some inner object that can take the value. */
	if (h -> inner && h -> inner -> type -> get_value) {
		status = ((*(h -> inner -> type -> signal_handler))
			  (h -> inner, name, ap));
		if (status == ISC_R_SUCCESS)
			return status;
	}
	return ISC_R_NOTFOUND;
}

isc_result_t dhcp_interface_stuff_values (omapi_object_t *c,
					  omapi_object_t *id,
					  omapi_object_t *h)
{
	struct interface_info *interface;
	isc_result_t status;

	if (h -> type != dhcp_type_interface)
		return ISC_R_INVALIDARG;
	interface = (struct interface_info *)h;

	/* Write out all the values. */

	status = omapi_connection_put_name (c, "state");
	if (status != ISC_R_SUCCESS)
		return status;
	if (interface -> flags && INTERFACE_REQUESTED)
	    status = omapi_connection_put_string (c, "up");
	else
	    status = omapi_connection_put_string (c, "down");
	if (status != ISC_R_SUCCESS)
		return status;

	/* Write out the inner object, if any. */
	if (h -> inner && h -> inner -> type -> stuff_values) {
		status = ((*(h -> inner -> type -> stuff_values))
			  (c, id, h -> inner));
		if (status == ISC_R_SUCCESS)
			return status;
	}

	return ISC_R_SUCCESS;
}

isc_result_t dhcp_interface_lookup (omapi_object_t **ip,
				    omapi_object_t *id,
				    omapi_object_t *ref)
{
	omapi_value_t *tv = (omapi_value_t *)0;
	isc_result_t status;
	struct interface_info *interface;

	if (!ref)
		return ISC_R_NOKEYS;

	/* First see if we were sent a handle. */
	status = omapi_get_value_str (ref, id, "handle", &tv);
	if (status == ISC_R_SUCCESS) {
		status = omapi_handle_td_lookup (ip, tv -> value);

		omapi_value_dereference (&tv, MDL);
		if (status != ISC_R_SUCCESS)
			return status;

		/* Don't return the object if the type is wrong. */
		if ((*ip) -> type != dhcp_type_interface) {
			omapi_object_dereference (ip, MDL);
			return ISC_R_INVALIDARG;
		}
	}

	/* Now look for an interface name. */
	status = omapi_get_value_str (ref, id, "name", &tv);
	if (status == ISC_R_SUCCESS) {
		char *s;
		unsigned len;
		for (interface = interfaces; interface;
		     interface = interface -> next) {
		    s = memchr (interface -> name, 0, IFNAMSIZ);
		    if (s)
			    len = s - &interface -> name [0];
		    else
			    len = IFNAMSIZ;
		    if ((tv -> value -> u.buffer.len == len &&
			 !memcmp (interface -> name,
				  (char *)tv -> value -> u.buffer.value,
				  len)))
			    break;
		}
		if (!interface) {
		    for (interface = dummy_interfaces;
			 interface; interface = interface -> next) {
			    s = memchr (interface -> name, 0, IFNAMSIZ);
			    if (s)
				    len = s - &interface -> name [0];
			    else
				    len = IFNAMSIZ;
			    if ((tv -> value -> u.buffer.len == len &&
				 !memcmp (interface -> name,
					  (char *)
					  tv -> value -> u.buffer.value,
					  len)))
				    break;
		    }
		}

		omapi_value_dereference (&tv, MDL);
		if (*ip && *ip != (omapi_object_t *)interface) {
			omapi_object_dereference (ip, MDL);
			return ISC_R_KEYCONFLICT;
		} else if (!interface) {
			if (*ip)
				omapi_object_dereference (ip, MDL);
			return ISC_R_NOTFOUND;
		} else if (!*ip)
			omapi_object_reference (ip,
						(omapi_object_t *)interface,
						MDL);
	}

	/* If we get to here without finding an interface, no valid key was
	   specified. */
	if (!*ip)
		return ISC_R_NOKEYS;
	return ISC_R_SUCCESS;
}

/* actually just go discover the interface */
isc_result_t dhcp_interface_create (omapi_object_t **lp,
				    omapi_object_t *id)
{
 	struct interface_info *hp;
	isc_result_t status;
	
	hp = (struct interface_info *)0;
	status = interface_allocate (&hp, MDL);
 	if (status != ISC_R_SUCCESS)
		return status;
 	hp -> flags = INTERFACE_REQUESTED;
	status = interface_reference ((struct interface_info **)lp, hp, MDL);
	interface_dereference (&hp, MDL);
	return status;
}

isc_result_t dhcp_interface_remove (omapi_object_t *lp,
				    omapi_object_t *id)
{
 	struct interface_info *interface, *ip, *last;

	interface = (struct interface_info *)lp;

	/* remove from interfaces */
	last = 0;
	for (ip = interfaces; ip; ip = ip -> next) {
		if (ip == interface) {
			if (last) {
				interface_dereference (&last -> next, MDL);
				if (ip -> next)
					interface_reference (&last -> next,
							     ip -> next, MDL);
			} else {
				interface_dereference (&interfaces, MDL);
				if (ip -> next)
					interface_reference (&interfaces,
							     ip -> next, MDL);
			}
			if (ip -> next)
				interface_dereference (&ip -> next, MDL);
			break;
		}
		last = ip;
	}
	if (!ip)
		return ISC_R_NOTFOUND;

	/* add the interface to the dummy_interface list */
	if (dummy_interfaces) {
		interface_reference (&interface -> next,
				     dummy_interfaces, MDL);
		interface_dereference (&dummy_interfaces, MDL);
	}
	interface_reference (&dummy_interfaces, interface, MDL);

	/* do a DHCPRELEASE */
	if (dhcp_interface_shutdown_hook)
		(*dhcp_interface_shutdown_hook) (interface);

	/* remove the io object */
	omapi_unregister_io_object ((omapi_object_t *)interface);

	if (local_family == AF_INET) {
		if_deregister_send(interface);
		if_deregister_receive(interface);
	} else {
		if_deregister6(interface);
	}

	return ISC_R_SUCCESS;
}

void interface_stash (struct interface_info *tptr)
{
	struct interface_info **vec;
	int delta;

	/* If the registerer didn't assign an index, assign one now. */
	if (tptr -> index == -1) {
		tptr -> index = interface_count++;
		while (tptr -> index < interface_max &&
		       interface_vector [tptr -> index])
			tptr -> index = interface_count++;
	}

	if (interface_max <= tptr -> index) {
		delta = tptr -> index - interface_max + 10;
		vec = dmalloc ((interface_max + delta) *
			       sizeof (struct interface_info *), MDL);
		if (!vec)
			return;
		memset (&vec [interface_max], 0,
			(sizeof (struct interface_info *)) * delta);
		interface_max += delta;
		if (interface_vector) {
		    memcpy (vec, interface_vector,
			    (interface_count *
			     sizeof (struct interface_info *)));
		    dfree (interface_vector, MDL);
		}
		interface_vector = vec;
	}
	if (interface_vector [tptr -> index]) {
		log_fatal("invalid tracefile - two interfaces with "
			  "same index - %s and %s",
			  interface_vector [tptr->index] -> name,
			  tptr -> name);
	}
	interface_reference (&interface_vector [tptr -> index], tptr, MDL);
	if (tptr -> index >= interface_count)
		interface_count = tptr -> index + 1;
#if defined (TRACING)
	trace_interface_register (interface_trace, tptr);
#endif
}

void interface_snorf (struct interface_info *tmp, int ir)
{
	tmp -> circuit_id = (u_int8_t *)tmp -> name;
	tmp -> circuit_id_len = strlen (tmp -> name);
	tmp -> remote_id = 0;
	tmp -> remote_id_len = 0;
	tmp -> flags = ir;
	if (interfaces) {
		interface_reference (&tmp -> next,
				     interfaces, MDL);
		interface_dereference (&interfaces, MDL);
	}
	interface_reference (&interfaces, tmp, MDL);
}
