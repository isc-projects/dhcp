/* route.c
 *
 * Routines for updating routing tables and configuring interfaces.
 * 
 * Copyright 1996 The Board of Trustees of The Leland Stanford
 * Junior University. All Rights Reserved.
 * Code originally written by Elliot Poger (poger@leland.stanford.edu).
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies.  Stanford University
 * makes no representations about the suitability of this
 * software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 */

#include "dhcpd.h"

/* Add a route to this destination through this interface. */
void add_route_direct(interface, destination)
     struct interface_info *interface;
     struct in_addr destination;
{
	note ("add_route_direct %s: %s",
	      interface -> name, inet_ntoa (destination));
#if 0
	struct in_addr directmask;

	directmask.s_addr = htonl (INADDR_BROADCAST); /* this addr only */
	add_route_net(interface, destination, &directmask);
#endif
}

/* Add a route to this subnet through this interface. */
void add_route_net(interface, destination, netmask)
     struct interface_info *interface;
     struct in_addr destination;
     struct in_addr netmask;
{
	char nbuf [128];

	strncpy (nbuf, inet_ntoa (netmask), sizeof nbuf);
	nbuf [(sizeof nbuf) - 1] = 0;

	note ("add_route_net %s: %s %s",
	      interface -> name, inet_ntoa (destination), nbuf);
#if 0
 	int sock;
 	struct sockaddr_in *sin;
	struct rtentry rt;

	memset((char *) &rt, 0, sizeof(struct rtentry));
	sin = (struct sockaddr_in *) &rt.rt_dst;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = destination.s_addr;
	sin = (struct sockaddr_in *) &rt.rt_genmask;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = netmask.s_addr;
	rt.rt_flags = RTF_UP;
	rt.rt_dev = interface->name;
	if (ioctl(interface -> rfdesc, SIOCADDRT, &rt) < 0)
		error ("Can't add route to %s through %s: %m",
		       inet_ntoa (destination), interface->name);
#endif
}

/* Add a route to the default gateway through this interface. */
void add_route_default_gateway(interface, gateway)
     struct interface_info *interface;
     struct in_addr gateway;
{
	note ("add_route_default_gateway %s: %s",
	      interface -> name, inet_ntoa (gateway));
#if 0
 	int sock;
 	struct sockaddr_in *sin;
	struct rtentry rt;

	/* Route through the gateway. */
	memset((char *) &rt, 0, sizeof(struct rtentry));
	sin = (struct sockaddr_in *) &rt.rt_dst;
	sin->sin_family = AF_INET;
	sin = (struct sockaddr_in *) &rt.rt_gateway;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = gateway.s_addr;
	rt.rt_flags = RTF_UP | RTF_GATEWAY;
	rt.rt_dev = interface->name;
	if (ioctl(interface -> rfdesc, SIOCADDRT, &rt) < 0)
		error ("Can't add route to default gateway");
#endif
}
		

/* Remove all routes matching the specified destination. */
void remove_routes(destination)
     struct in_addr destination;
{
	note ("remove_routes: %s", inet_ntoa (destination));
#if 0
 	int sock;
 	struct ifreq ifr;
 	struct sockaddr_in *sin;
	struct rtentry rt;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
 		error("Can't open socket to remove routes");
	}

	/* Remove all routes to this IP destination. */
	memset((char *) &rt, 0, sizeof(struct rtentry));
	sin = (struct sockaddr_in *) &rt.rt_dst;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = destination->s_addr;
	while (ioctl(sock, SIOCDELRT, &rt) >= 0)
		;
	close(sock);
#endif
}

/* Remove routes on the specified interface matching the specified
   destination. */
void remove_if_route (interface, destination)
     struct interface_info *interface;
     struct in_addr destination;
{
	note ("remove_if_routes %s: %s",
	      interface -> name, inet_ntoa (destination));
#if 0
 	int sock;
 	struct ifreq ifr;
 	struct sockaddr_in *sin;
	struct rtentry rt;

	/* Remove one specific route. */
	/* XXX: does this even work? */
	memset((char *) &rt, 0, sizeof(struct rtentry));
	sin = (struct sockaddr_in *) &rt.rt_dst;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = destination.s_addr;
	rt.rt_dev = interface->name;
	if (ioctl(interface -> rfdesc, SIOCDELRT, &rt) == -1)
		warn("Error removing route.");
#endif
}

/* Remove all routes on the specified interface. */

void remove_all_if_routes(interface)
     struct interface_info *interface;
{
	note ("remove_all_if_routes %s", interface -> name);
#if 0
 	struct ifreq ifr;

	/* Bring the interface down and then up again to clear
	 * all its routes. */
	strncpy(ifr.ifr_name, interface->name, IFNAMSIZ);
	if (ioctl(interface -> rfdesc, SIOCGIFFLAGS, &ifr) == -1)
		error ("SIOCGIFFLAGS %s: %m", interface -> name);

	ifr.ifr_flags &= ~(IFF_UP|IFF_RUNNING);
	if (ioctl(interface -> rfdesc, SIOCSIFFLAGS, &ifr) == -1)
		error ("Can't bring down interface");

	strncpy(ifr.ifr_name,interface->name,IFNAMSIZ);
	ifr.ifr_flags |= (IFF_UP|IFF_RUNNING);
	if (ioctl(interface -> rfdesc, SIOCSIFFLAGS, &ifr) == -1)
		error("Can't bring interface back up");
#endif
}

/* Set the netmask (in network byte order!) of this interface. */
void set_netmask(interface, netmask)
     struct interface_info *interface;
     struct in_addr netmask;
{
	note ("set_netmask %s: %s",
	      interface -> name, inet_ntoa (netmask));
#if 0
 	int sock;
 	struct ifreq ifr;

	if (ioctl (interface -> rfdesc, SIOCGIFNETMASK, &ifr) == -1)
		error ("Can't get old netmask of interface");

	(*(struct sockaddr_in *)&ifr.ifr_netmask).sin_addr = netmask;
	if (ioctl (interface -> rfdesc, SIOCSIFNETMASK, &ifr) == -1)
		error ("Can't set new netmask");
#endif
}

/* Set the broadcast address (in network byte order!) of this interface. */
void set_broadcast_addr(interface, broadcast_addr)
     struct interface_info *interface;
     struct in_addr broadcast_addr;
{
	note ("set_broadcast_addr %s: %s",
	      interface -> name, inet_ntoa (broadcast_addr));
#if 0
 	int sock;
 	struct ifreq ifr;

	if (ioctl(interface -> rfdesc, SIOCGIFBRDADDR, &ifr) == -1)
		error("Can't get old broadcast address of interface");

	(*(struct sockaddr_in *)&ifr.ifr_broadaddr).sin_addr = broadcast_addr;
	if (ioctl(sock, SIOCSIFBRDADDR, &ifr) == -1) {
		error("Can't set new broadcast address");
	}
#endif
}

/* Set the IP address (in network byte order!) of this interface. */
void set_ip_address(interface, ip_addr)
     struct interface_info *interface;
     struct in_addr ip_addr;
{
	note ("set_ip_address %s: %s",
	      interface -> name, inet_ntoa (ip_addr));
#if 0
 	int sock;
 	struct ifreq ifr;

	strncpy(ifr.ifr_name, interface->name, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
		error ("Can't get old IP address of interface");

	(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr = ip_addr;
	if (ioctl(sock, SIOCSIFADDR, &ifr) < 0)
		error("Can't set IP address");
	}
#endif
}
