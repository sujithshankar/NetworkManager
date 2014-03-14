/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_TEST_UTILS_H__
#define __NM_TEST_UTILS_H__


#include <arpa/inet.h>
#include <glib.h>


struct __nmtst_internal
{
	GRand *rand0;
};

extern struct __nmtst_internal __nmtst_internal;

#define NMTST_INIT() \
	struct __nmtst_internal __nmtst_internal = { 0 };

inline GRand *nmtst_get_rand0 (void);

inline GRand *
nmtst_get_rand0 ()
{
	if (G_UNLIKELY (!__nmtst_internal.rand0))
		__nmtst_internal.rand0 = g_rand_new_with_seed (0);

	return __nmtst_internal.rand0;
}

inline guint32 nmtst_inet4_from_string (const char *str);
inline guint32
nmtst_inet4_from_string (const char *str)
{
	guint32 addr;
	int success;

	if (!str)
		return 0;

	success = inet_pton (AF_INET, str, &addr);

	g_assert (success == 1);

	return addr;
}

inline struct in6_addr *nmtst_inet6_from_string (const char *str);
inline struct in6_addr *
nmtst_inet6_from_string (const char *str)
{
	static struct in6_addr addr;
	int success;

	if (!str)
		addr = in6addr_any;
	else {
		success = inet_pton (AF_INET6, str, &addr);
		g_assert (success == 1);
	}

	return &addr;
}

#ifdef __NM_PLATFORM_H__

inline NMPlatformIP6Address *nmtst_platform_ip6_address (const char *address, const char *peer_address, guint plen);

inline NMPlatformIP6Address *
nmtst_platform_ip6_address (const char *address, const char *peer_address, guint plen)
{
	static NMPlatformIP6Address addr;

	memset (&addr, 0, sizeof (addr));
	addr.address = *nmtst_inet6_from_string (address);
	addr.peer_address = *nmtst_inet6_from_string (peer_address);
	addr.plen = plen;

	return &addr;
}


inline NMPlatformIP6Address *
nmtst_platform_ip6_address_full (const char *address, const char *peer_address, guint plen,
                                 int ifindex, NMPlatformSource source, guint32 timestamp,
                                 guint32 lifetime, guint32 preferred, guint flags);

inline NMPlatformIP6Address *
nmtst_platform_ip6_address_full (const char *address, const char *peer_address, guint plen,
                                 int ifindex, NMPlatformSource source, guint32 timestamp,
                                 guint32 lifetime, guint32 preferred, guint flags)
{
	NMPlatformIP6Address *addr = nmtst_platform_ip6_address (address, peer_address, plen);

	addr->ifindex = ifindex;
	addr->source = source;
	addr->timestamp = timestamp;
	addr->lifetime = lifetime;
	addr->preferred = preferred;
	addr->flags = flags;

	return addr;
}


inline NMPlatformIP6Route * nmtst_platform_ip6_route (const char *network, guint plen, const char *gateway);

inline NMPlatformIP6Route *
nmtst_platform_ip6_route (const char *network, guint plen, const char *gateway)
{
	static NMPlatformIP6Route route;

	memset (&route, 0, sizeof (route));
	route.network = *nmtst_inet6_from_string (network);
	route.plen = plen;
	route.gateway = *nmtst_inet6_from_string (gateway);

	return &route;
}


inline NMPlatformIP6Route *
nmtst_platform_ip6_route_full (const char *network, guint plen, const char *gateway,
                               int ifindex, NMPlatformSource source,
                               guint metric, guint mss);

inline NMPlatformIP6Route *
nmtst_platform_ip6_route_full (const char *network, guint plen, const char *gateway,
                               int ifindex, NMPlatformSource source,
                               guint metric, guint mss)
{
	NMPlatformIP6Route *route = nmtst_platform_ip6_route (network, plen, gateway);

	route->ifindex = ifindex;
	route->source = source;
	route->metric = metric;
	route->mss = mss;

	return route;
}

#endif


#endif /* __NM_TEST_UTILS_H__ */

