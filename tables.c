/* tables.c

   Tables of information... */

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

/* DHCP Option names, formats and codes, from RFC1533.

   Format codes:

   e - end of data
   I - IP address
   l - 32-bit signed integer
   L - 32-bit unsigned integer
   s - 16-bit signed integer
   S - 16-bit unsigned integer
   b - 8-bit signed integer
   B - 8-bit unsigned integer
   t - ASCII text
   f - flag (true or false)
   A - array of whatever precedes (e.g., IA means array of IP addresses)
*/

struct universe dhcp_universe;
struct option dhcp_options [256] = {
	{ "pad", "",					&dhcp_universe, 0 },
	{ "subnet-mask", "I",				&dhcp_universe, 1 },
	{ "time-offset", "l",				&dhcp_universe, 2 },
	{ "routers", "IA",				&dhcp_universe, 3 },
	{ "time-servers", "IA",				&dhcp_universe, 4 },
	{ "name-servers", "IA",				&dhcp_universe, 5 },
	{ "domain-name-servers", "IA",			&dhcp_universe, 6 },
	{ "log-servers", "IA",				&dhcp_universe, 7 },
	{ "cookie-servers", "IA",			&dhcp_universe, 8 },
	{ "lpr-servers", "IA",				&dhcp_universe, 9 },
	{ "impress-servers", "IA",			&dhcp_universe, 10 },
	{ "resource-location-servers", "IA",		&dhcp_universe, 11 },
	{ "host-name", "t",				&dhcp_universe, 12 },
	{ "boot-size", "S",				&dhcp_universe, 13 },
	{ "merit-dump", "t",				&dhcp_universe, 14 },
	{ "domain-name", "t",				&dhcp_universe, 15 },
	{ "swap-server", "I",				&dhcp_universe, 16 },
	{ "root-path", "t",				&dhcp_universe, 17 },
	{ "extensions-path", "t",			&dhcp_universe, 18 },
	{ "ip-forwarding", "f",				&dhcp_universe, 19 },
	{ "non-local-source-routing", "f",		&dhcp_universe, 20 },
	{ "policy-filter", "IIA",			&dhcp_universe, 21 },
	{ "max-dgram-reassembly", "S",			&dhcp_universe, 22 },
	{ "default-ip-ttl", "B",			&dhcp_universe, 23 },
	{ "path-mtu-aging-timeout", "L",		&dhcp_universe, 24 },
	{ "path-mtu-plateau-table", "SA",		&dhcp_universe, 25 },
	{ "interface-mtu", "S",				&dhcp_universe, 26 },
	{ "all-subnets-local", "f",			&dhcp_universe, 27 },
	{ "broadcast-address", "I",			&dhcp_universe, 28 },
	{ "perform-mask-discovery", "f",		&dhcp_universe, 29 },
	{ "mask-supplier", "f",				&dhcp_universe, 30 },
	{ "router-discovery", "f",			&dhcp_universe, 31 },
	{ "router-solicitation-address", "I",		&dhcp_universe, 32 },
	{ "static-routes", "IIA",			&dhcp_universe, 33 },
	{ "trailer-encapsulation", "f",			&dhcp_universe, 34 },
	{ "arp-cache-timeout", "L",			&dhcp_universe, 35 },
	{ "ieee802.3-encapsulation", "f",		&dhcp_universe, 36 },
	{ "default-tcp-ttl", "B",			&dhcp_universe, 37 },
	{ "tcp-keepalive-interval", "L",		&dhcp_universe, 38 },
	{ "tcp-keepalive-garbage", "f",			&dhcp_universe, 39 },
	{ "nis-domain", "t",				&dhcp_universe, 40 },
	{ "nis-servers", "IA",				&dhcp_universe, 41 },
	{ "ntp-servers", "IA",				&dhcp_universe, 42 },
	{ "vendor-encapsulated-options", "t",		&dhcp_universe, 43 },
	{ "netbios-name-servers", "IA",			&dhcp_universe, 44 },
	{ "netbios-dd-server", "IA",			&dhcp_universe, 45 },
	{ "netbios-node-type", "B",			&dhcp_universe, 46 },
	{ "netbios-scope", "t",				&dhcp_universe, 47 },
	{ "font-servers", "IA",				&dhcp_universe, 48 },
	{ "x-display-manager", "IA",			&dhcp_universe, 49 },
	{ "dhcp-requested-address", "I",		&dhcp_universe, 50 },
	{ "dhcp-lease-time", "L",			&dhcp_universe, 51 },
	{ "dhcp-option-overload", "B",			&dhcp_universe, 52 },
	{ "dhcp-message-type", "B",			&dhcp_universe, 53 },
	{ "dhcp-server-identifier", "I",		&dhcp_universe, 54 },
	{ "dhcp-parameter-request-list", "BA",		&dhcp_universe, 55 },
	{ "dhcp-message", "t",				&dhcp_universe, 56 },
	{ "dhcp-max-message-size", "S",			&dhcp_universe, 57 },
	{ "dhcp-renewal-time", "L",			&dhcp_universe, 58 },
	{ "dhcp-rebinding-time", "L",			&dhcp_universe, 59 },
	{ "dhcp-class-identifier", "t",			&dhcp_universe, 60 },
	{ "dhcp-client-identifier", "t",		&dhcp_universe, 61 },
	{ "option-62", "",				&dhcp_universe, 62 },
	{ "option-63", "",				&dhcp_universe, 63 },
	{ "option-64", "",				&dhcp_universe, 64 },
	{ "option-65", "",				&dhcp_universe, 65 },
	{ "option-66", "",				&dhcp_universe, 66 },
	{ "option-67", "",				&dhcp_universe, 67 },
	{ "option-68", "",				&dhcp_universe, 68 },
	{ "option-69", "",				&dhcp_universe, 69 },
	{ "option-70", "",				&dhcp_universe, 70 },
	{ "option-71", "",				&dhcp_universe, 71 },
	{ "option-72", "",				&dhcp_universe, 72 },
	{ "option-73", "",				&dhcp_universe, 73 },
	{ "option-74", "",				&dhcp_universe, 74 },
	{ "option-75", "",				&dhcp_universe, 75 },
	{ "option-76", "",				&dhcp_universe, 76 },
	{ "option-77", "",				&dhcp_universe, 77 },
	{ "option-78", "",				&dhcp_universe, 78 },
	{ "option-79", "",				&dhcp_universe, 79 },
	{ "option-80", "",				&dhcp_universe, 80 },
	{ "option-81", "",				&dhcp_universe, 81 },
	{ "option-82", "",				&dhcp_universe, 82 },
	{ "option-83", "",				&dhcp_universe, 83 },
	{ "option-84", "",				&dhcp_universe, 84 },
	{ "option-85", "",				&dhcp_universe, 85 },
	{ "option-86", "",				&dhcp_universe, 86 },
	{ "option-87", "",				&dhcp_universe, 87 },
	{ "option-88", "",				&dhcp_universe, 88 },
	{ "option-89", "",				&dhcp_universe, 89 },
	{ "option-90", "",				&dhcp_universe, 90 },
	{ "option-91", "",				&dhcp_universe, 91 },
	{ "option-92", "",				&dhcp_universe, 92 },
	{ "option-93", "",				&dhcp_universe, 93 },
	{ "option-94", "",				&dhcp_universe, 94 },
	{ "option-95", "",				&dhcp_universe, 95 },
	{ "option-96", "",				&dhcp_universe, 96 },
	{ "option-97", "",				&dhcp_universe, 97 },
	{ "option-98", "",				&dhcp_universe, 98 },
	{ "option-99", "",				&dhcp_universe, 99 },
	{ "option-100", "",				&dhcp_universe, 100 },
	{ "option-101", "",				&dhcp_universe, 101 },
	{ "option-102", "",				&dhcp_universe, 102 },
	{ "option-103", "",				&dhcp_universe, 103 },
	{ "option-104", "",				&dhcp_universe, 104 },
	{ "option-105", "",				&dhcp_universe, 105 },
	{ "option-106", "",				&dhcp_universe, 106 },
	{ "option-107", "",				&dhcp_universe, 107 },
	{ "option-108", "",				&dhcp_universe, 108 },
	{ "option-109", "",				&dhcp_universe, 109 },
	{ "option-110", "",				&dhcp_universe, 110 },
	{ "option-111", "",				&dhcp_universe, 111 },
	{ "option-112", "",				&dhcp_universe, 112 },
	{ "option-113", "",				&dhcp_universe, 113 },
	{ "option-114", "",				&dhcp_universe, 114 },
	{ "option-115", "",				&dhcp_universe, 115 },
	{ "option-116", "",				&dhcp_universe, 116 },
	{ "option-117", "",				&dhcp_universe, 117 },
	{ "option-118", "",				&dhcp_universe, 118 },
	{ "option-119", "",				&dhcp_universe, 119 },
	{ "option-120", "",				&dhcp_universe, 120 },
	{ "option-121", "",				&dhcp_universe, 121 },
	{ "option-122", "",				&dhcp_universe, 122 },
	{ "option-123", "",				&dhcp_universe, 123 },
	{ "option-124", "",				&dhcp_universe, 124 },
	{ "option-125", "",				&dhcp_universe, 125 },
	{ "option-126", "",				&dhcp_universe, 126 },
	{ "option-127", "",				&dhcp_universe, 127 },
	{ "option-128", "",				&dhcp_universe, 128 },
	{ "option-129", "",				&dhcp_universe, 129 },
	{ "option-130", "",				&dhcp_universe, 130 },
	{ "option-131", "",				&dhcp_universe, 131 },
	{ "option-132", "",				&dhcp_universe, 132 },
	{ "option-133", "",				&dhcp_universe, 133 },
	{ "option-134", "",				&dhcp_universe, 134 },
	{ "option-135", "",				&dhcp_universe, 135 },
	{ "option-136", "",				&dhcp_universe, 136 },
	{ "option-137", "",				&dhcp_universe, 137 },
	{ "option-138", "",				&dhcp_universe, 138 },
	{ "option-139", "",				&dhcp_universe, 139 },
	{ "option-140", "",				&dhcp_universe, 140 },
	{ "option-141", "",				&dhcp_universe, 141 },
	{ "option-142", "",				&dhcp_universe, 142 },
	{ "option-143", "",				&dhcp_universe, 143 },
	{ "option-144", "",				&dhcp_universe, 144 },
	{ "option-145", "",				&dhcp_universe, 145 },
	{ "option-146", "",				&dhcp_universe, 146 },
	{ "option-147", "",				&dhcp_universe, 147 },
	{ "option-148", "",				&dhcp_universe, 148 },
	{ "option-149", "",				&dhcp_universe, 149 },
	{ "option-150", "",				&dhcp_universe, 150 },
	{ "option-151", "",				&dhcp_universe, 151 },
	{ "option-152", "",				&dhcp_universe, 152 },
	{ "option-153", "",				&dhcp_universe, 153 },
	{ "option-154", "",				&dhcp_universe, 154 },
	{ "option-155", "",				&dhcp_universe, 155 },
	{ "option-156", "",				&dhcp_universe, 156 },
	{ "option-157", "",				&dhcp_universe, 157 },
	{ "option-158", "",				&dhcp_universe, 158 },
	{ "option-159", "",				&dhcp_universe, 159 },
	{ "option-160", "",				&dhcp_universe, 160 },
	{ "option-161", "",				&dhcp_universe, 161 },
	{ "option-162", "",				&dhcp_universe, 162 },
	{ "option-163", "",				&dhcp_universe, 163 },
	{ "option-164", "",				&dhcp_universe, 164 },
	{ "option-165", "",				&dhcp_universe, 165 },
	{ "option-166", "",				&dhcp_universe, 166 },
	{ "option-167", "",				&dhcp_universe, 167 },
	{ "option-168", "",				&dhcp_universe, 168 },
	{ "option-169", "",				&dhcp_universe, 169 },
	{ "option-170", "",				&dhcp_universe, 170 },
	{ "option-171", "",				&dhcp_universe, 171 },
	{ "option-172", "",				&dhcp_universe, 172 },
	{ "option-173", "",				&dhcp_universe, 173 },
	{ "option-174", "",				&dhcp_universe, 174 },
	{ "option-175", "",				&dhcp_universe, 175 },
	{ "option-176", "",				&dhcp_universe, 176 },
	{ "option-177", "",				&dhcp_universe, 177 },
	{ "option-178", "",				&dhcp_universe, 178 },
	{ "option-179", "",				&dhcp_universe, 179 },
	{ "option-180", "",				&dhcp_universe, 180 },
	{ "option-181", "",				&dhcp_universe, 181 },
	{ "option-182", "",				&dhcp_universe, 182 },
	{ "option-183", "",				&dhcp_universe, 183 },
	{ "option-184", "",				&dhcp_universe, 184 },
	{ "option-185", "",				&dhcp_universe, 185 },
	{ "option-186", "",				&dhcp_universe, 186 },
	{ "option-187", "",				&dhcp_universe, 187 },
	{ "option-188", "",				&dhcp_universe, 188 },
	{ "option-189", "",				&dhcp_universe, 189 },
	{ "option-190", "",				&dhcp_universe, 190 },
	{ "option-191", "",				&dhcp_universe, 191 },
	{ "option-192", "",				&dhcp_universe, 192 },
	{ "option-193", "",				&dhcp_universe, 193 },
	{ "option-194", "",				&dhcp_universe, 194 },
	{ "option-195", "",				&dhcp_universe, 195 },
	{ "option-196", "",				&dhcp_universe, 196 },
	{ "option-197", "",				&dhcp_universe, 197 },
	{ "option-198", "",				&dhcp_universe, 198 },
	{ "option-199", "",				&dhcp_universe, 199 },
	{ "option-200", "",				&dhcp_universe, 200 },
	{ "option-201", "",				&dhcp_universe, 201 },
	{ "option-202", "",				&dhcp_universe, 202 },
	{ "option-203", "",				&dhcp_universe, 203 },
	{ "option-204", "",				&dhcp_universe, 204 },
	{ "option-205", "",				&dhcp_universe, 205 },
	{ "option-206", "",				&dhcp_universe, 206 },
	{ "option-207", "",				&dhcp_universe, 207 },
	{ "option-208", "",				&dhcp_universe, 208 },
	{ "option-209", "",				&dhcp_universe, 209 },
	{ "option-210", "",				&dhcp_universe, 210 },
	{ "option-211", "",				&dhcp_universe, 211 },
	{ "option-212", "",				&dhcp_universe, 212 },
	{ "option-213", "",				&dhcp_universe, 213 },
	{ "option-214", "",				&dhcp_universe, 214 },
	{ "option-215", "",				&dhcp_universe, 215 },
	{ "option-216", "",				&dhcp_universe, 216 },
	{ "option-217", "",				&dhcp_universe, 217 },
	{ "option-218", "",				&dhcp_universe, 218 },
	{ "option-219", "",				&dhcp_universe, 219 },
	{ "option-220", "",				&dhcp_universe, 220 },
	{ "option-221", "",				&dhcp_universe, 221 },
	{ "option-222", "",				&dhcp_universe, 222 },
	{ "option-223", "",				&dhcp_universe, 223 },
	{ "option-224", "",				&dhcp_universe, 224 },
	{ "option-225", "",				&dhcp_universe, 225 },
	{ "option-226", "",				&dhcp_universe, 226 },
	{ "option-227", "",				&dhcp_universe, 227 },
	{ "option-228", "",				&dhcp_universe, 228 },
	{ "option-229", "",				&dhcp_universe, 229 },
	{ "option-230", "",				&dhcp_universe, 230 },
	{ "option-231", "",				&dhcp_universe, 231 },
	{ "option-232", "",				&dhcp_universe, 232 },
	{ "option-233", "",				&dhcp_universe, 233 },
	{ "option-234", "",				&dhcp_universe, 234 },
	{ "option-235", "",				&dhcp_universe, 235 },
	{ "option-236", "",				&dhcp_universe, 236 },
	{ "option-237", "",				&dhcp_universe, 237 },
	{ "option-238", "",				&dhcp_universe, 238 },
	{ "option-239", "",				&dhcp_universe, 239 },
	{ "option-240", "",				&dhcp_universe, 240 },
	{ "option-241", "",				&dhcp_universe, 241 },
	{ "option-242", "",				&dhcp_universe, 242 },
	{ "option-243", "",				&dhcp_universe, 243 },
	{ "option-244", "",				&dhcp_universe, 244 },
	{ "option-245", "",				&dhcp_universe, 245 },
	{ "option-246", "",				&dhcp_universe, 246 },
	{ "option-247", "",				&dhcp_universe, 247 },
	{ "option-248", "",				&dhcp_universe, 248 },
	{ "option-249", "",				&dhcp_universe, 249 },
	{ "option-250", "",				&dhcp_universe, 250 },
	{ "option-251", "",				&dhcp_universe, 251 },
	{ "option-252", "",				&dhcp_universe, 252 },
	{ "option-253", "",				&dhcp_universe, 253 },
	{ "option-254", "",				&dhcp_universe, 254 },
	{ "option-end", "e",				&dhcp_universe, 255 },
};

/* Default dhcp option priority list (this is ad hoc and should not be
   mistaken for a carefully crafted and optimized list). */
unsigned char dhcp_option_default_priority_list [] = {
	DHO_SUBNET_MASK,
	DHO_TIME_OFFSET,
	DHO_ROUTERS,
	DHO_TIME_SERVERS,
	DHO_NAME_SERVERS,
	DHO_DOMAIN_NAME_SERVERS,
	DHO_LOG_SERVERS,
	DHO_COOKIE_SERVERS,
	DHO_LPR_SERVERS,
	DHO_IMPRESS_SERVERS,
	DHO_RESOURCE_LOCATION_SERVERS,
	DHO_HOST_NAME,
	DHO_BOOT_SIZE,
	DHO_MERIT_DUMP,
	DHO_DOMAIN_NAME,
	DHO_SWAP_SERVER,
	DHO_ROOT_PATH,
	DHO_EXTENSIONS_PATH,
	DHO_IP_FORWARDING,
	DHO_NON_LOCAL_SOURCE_ROUTING,
	DHO_POLICY_FILTER,
	DHO_MAX_DGRAM_REASSEMBLY,
	DHO_DEFAULT_IP_TTL,
	DHO_PATH_MTU_AGING_TIMEOUT,
	DHO_PATH_MTU_PLATEAU_TABLE,
	DHO_INTERFACE_MTU,
	DHO_ALL_SUBNETS_LOCAL,
	DHO_BROADCAST_ADDRESS,
	DHO_PERFORM_MASK_DISCOVERY,
	DHO_MASK_SUPPLIER,
	DHO_ROUTER_DISCOVERY,
	DHO_ROUTER_SOLICITATION_ADDRESS,
	DHO_STATIC_ROUTES,
	DHO_TRAILER_ENCAPSULATION,
	DHO_ARP_CACHE_TIMEOUT,
	DHO_IEEE802_3_ENCAPSULATION,
	DHO_DEFAULT_TCP_TTL,
	DHO_TCP_KEEPALIVE_INTERVAL,
	DHO_TCP_KEEPALIVE_GARBAGE,
	DHO_NIS_DOMAIN,
	DHO_NIS_SERVERS,
	DHO_NTP_SERVERS,
	DHO_VENDOR_ENCAPSULATED_OPTIONS,
	DHO_NETBIOS_NAME_SERVERS,
	DHO_NETBIOS_DD_SERVER,
	DHO_NETBIOS_NODE_TYPE,
	DHO_NETBIOS_SCOPE,
	DHO_FONT_SERVERS,
	DHO_X_DISPLAY_MANAGER,
	DHO_DHCP_REQUESTED_ADDRESS,
	DHO_DHCP_LEASE_TIME,
	DHO_DHCP_OPTION_OVERLOAD,
	DHO_DHCP_MESSAGE_TYPE,
	DHO_DHCP_SERVER_IDENTIFIER,
	DHO_DHCP_PARAMETER_REQUEST_LIST,
	DHO_DHCP_MESSAGE,
	DHO_DHCP_MAX_MESSAGE_SIZE,
	DHO_DHCP_RENEWAL_TIME,
	DHO_DHCP_REBINDING_TIME,
	DHO_DHCP_CLASS_IDENTIFIER,
	DHO_DHCP_CLIENT_IDENTIFIER,
};

int sizeof_dhcp_option_default_priority_list =
	sizeof dhcp_option_default_priority_list;


struct hash_table universe_hash;

void initialize_universes()
{
	int i;

	dhcp_universe.name = "dhcp";
	dhcp_universe.hash = new_hash ();
	if (!dhcp_universe.hash)
		error ("Can't allocate dhcp option hash table.");
	for (i = 0; i < 256; i++) {
		dhcp_universe.options [i] = &dhcp_options [i];
		add_hash (dhcp_universe.hash, dhcp_options [i].name, 0,
			  (unsigned char *)&dhcp_options [i]);
	}
	universe_hash.hash_count = DEFAULT_HASH_SIZE;
	add_hash (&universe_hash, dhcp_universe.name, 0,
		  (unsigned char *)&dhcp_universe);
}
