/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2015 Red Hat, Inc.
 *
 */

#include "config.h"

#include <glib.h>
#include <arpa/inet.h>

#include "nm-fake-platform.h"
#include "nm-platform.h"
#include "nm-route-manager.h"
#include "nm-logging.h"

#include "nm-test-utils.h"

static void
flush_eth0 (void)
{
	nm_route_manager_route_flush (nm_route_manager_get (), 2);
}

static void
flush_eth1 (void)
{
	nm_route_manager_route_flush (nm_route_manager_get (), 3);
}

static void
setup_eth0_ip4 (void)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));
	NMPlatformIP4Route route;

	route.ifindex = 2;
	route.mss = 0;

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "6.6.6.0", &route.network);
	route.plen = 24;
	route.gateway = INADDR_ANY;
	route.metric = 20;
	g_array_append_val (routes, route);

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "7.0.0.0", &route.network);
	route.plen = 8;
	inet_pton (AF_INET, "6.6.6.1", &route.gateway);
	route.metric = 21;
	g_array_append_val (routes, route);

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), 2, routes);
	g_array_free (routes, TRUE);
}

static void
setup_eth1_ip4 (void)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP4Route));
	NMPlatformIP4Route route;

	route.ifindex = 3;
	route.mss = 0;

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "6.6.6.0", &route.network);
	route.plen = 24;
	route.gateway = INADDR_ANY;
	route.metric = 20;
	g_array_append_val (routes, route);

	route.source = NM_IP_CONFIG_SOURCE_USER;
	inet_pton (AF_INET, "7.0.0.0", &route.network);
	route.plen = 8;
	route.gateway = INADDR_ANY;
	route.metric = 22;
	g_array_append_val (routes, route);

	nm_route_manager_ip4_route_sync (nm_route_manager_get (), 3, routes);
	g_array_free (routes, TRUE);
}

static void
test_ip4 (void)
{
	GArray *routes;

	NMPlatformIP4Route state1[] = {
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("7.0.0.0"),
			.plen = 8,
			.ifindex = 2,
			.gateway = nmtst_inet4_from_string ("6.6.6.1"),
			.metric = 21,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("6.6.6.0"),
			.plen = 24,
			.ifindex = 2,
			.gateway = INADDR_ANY,
			.metric = 20,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("7.0.0.0"),
			.plen = 8,
			.ifindex = 3,
			.gateway = INADDR_ANY,
			.metric = 22,
			.mss = 0,
		},
	};

	NMPlatformIP4Route state2[] = {
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("7.0.0.0"),
			.plen = 8,
			.ifindex = 3,
			.gateway = INADDR_ANY,
			.metric = 22,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = nmtst_inet4_from_string ("6.6.6.0"),
			.plen = 24,
			.ifindex = 3,
			.gateway = INADDR_ANY,
			.metric = 20,
			.mss = 0,
		},
	};

	setup_eth0_ip4 ();
	setup_eth1_ip4 ();

	/* Check that the 6.6.6.0/24 didn't clash and everything else is fine too. */
	routes = nm_platform_ip4_route_get_all (0, NM_PLATFORM_GET_ROUTE_MODE_ALL);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state1));
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, state1, routes->len);
	g_array_free (routes, TRUE);


	setup_eth1_ip4 ();
	setup_eth0_ip4 ();

	/* Ensure nothing changed. */
	routes = nm_platform_ip4_route_get_all (0, NM_PLATFORM_GET_ROUTE_MODE_ALL);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state1));
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, state1, routes->len);
	g_array_free (routes, TRUE);

	flush_eth0 ();

	/* Check that the 6.6.6.0/24 is now on eth1 and other eth0 routes went away. */
	routes = nm_platform_ip4_route_get_all (0, NM_PLATFORM_GET_ROUTE_MODE_ALL);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state2));
	nmtst_platform_ip4_routes_equal ((NMPlatformIP4Route *) routes->data, state2, routes->len);
	g_array_free (routes, TRUE);

	flush_eth1 ();

	/* No routes left. */
	routes = nm_platform_ip4_route_get_all (0, NM_PLATFORM_GET_ROUTE_MODE_ALL);
	g_assert_cmpint (routes->len, ==, 0);
	g_array_free (routes, TRUE);
}

static void
setup_eth0_ip6 (void)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP6Route));
	NMPlatformIP6Route *route;

	route = nmtst_platform_ip6_route_full ("2001:db8:8086::",
	                                       48,
	                                       NULL,
	                                       2,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       20,
	                                       0);
	g_array_append_val (routes, *route);

	route = nmtst_platform_ip6_route_full ("2001:db8:abad:c0de::",
	                                       64,
	                                       "2001:db8:8086::1",
	                                       2,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       21,
	                                       0);
	g_array_append_val (routes, *route);

	nm_route_manager_ip6_route_sync (nm_route_manager_get (), 2, routes);
	g_array_free (routes, TRUE);
}

static void
setup_eth1_ip6 (void)
{
	GArray *routes = g_array_new (FALSE, FALSE, sizeof (NMPlatformIP6Route));
	NMPlatformIP6Route *route;

	route = nmtst_platform_ip6_route_full ("2001:db8:8086::",
	                                       48,
	                                       NULL,
	                                       3,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       20,
	                                       0);
	g_array_append_val (routes, *route);

	route = nmtst_platform_ip6_route_full ("2001:db8:abad:c0de::",
	                                       64,
	                                       NULL,
	                                       3,
	                                       NM_IP_CONFIG_SOURCE_USER,
	                                       22,
	                                       0);
	g_array_append_val (routes, *route);

	nm_route_manager_ip6_route_sync (nm_route_manager_get (), 3, routes);
	g_array_free (routes, TRUE);
}

static void
test_ip6 (void)
{
	GArray *routes;

	NMPlatformIP6Route state1[] = {
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:abad:c0de::"),
			.plen = 64,
			.ifindex = 2,
			.gateway = *nmtst_inet6_from_string ("2001:db8:8086::1"),
			.metric = 21,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:8086::"),
			.plen = 48,
			.ifindex = 2,
			.gateway = in6addr_any,
			.metric = 20,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:abad:c0de::"),
			.plen = 64,
			.ifindex = 3,
			.gateway = in6addr_any,
			.metric = 22,
			.mss = 0,
		},
	};

	NMPlatformIP6Route state2[] = {
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:abad:c0de::"),
			.plen = 64,
			.ifindex = 3,
			.gateway = in6addr_any,
			.metric = 22,
			.mss = 0,
		},
		{
			.source = NM_IP_CONFIG_SOURCE_USER,
			.network = *nmtst_inet6_from_string ("2001:db8:8086::"),
			.plen = 48,
			.ifindex = 3,
			.gateway = in6addr_any,
			.metric = 20,
			.mss = 0,
		},
	};

	setup_eth0_ip6 ();
	setup_eth1_ip6 ();

	/* Check that the 2001:db8:8086::/48 didn't clash and everything else is fine too. */
	routes = nm_platform_ip6_route_get_all (0, NM_PLATFORM_GET_ROUTE_MODE_ALL);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state1));
	nmtst_platform_ip6_routes_equal ((NMPlatformIP6Route *) routes->data, state1, routes->len);
	g_array_free (routes, TRUE);

	setup_eth1_ip6 ();
	setup_eth0_ip6 ();

	/* Ensure nothing changed. */
	routes = nm_platform_ip6_route_get_all (0, NM_PLATFORM_GET_ROUTE_MODE_ALL);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state1));
	nmtst_platform_ip6_routes_equal ((NMPlatformIP6Route *) routes->data, state1, routes->len);
	g_array_free (routes, TRUE);

	flush_eth0 ();

	/* Check that the 2001:db8:8086::/48 is now on eth1 and other eth0 routes went away. */
	routes = nm_platform_ip6_route_get_all (0, NM_PLATFORM_GET_ROUTE_MODE_ALL);
	g_assert_cmpint (routes->len, ==, G_N_ELEMENTS (state2));
	nmtst_platform_ip6_routes_equal ((NMPlatformIP6Route *) routes->data, state2, routes->len);
	g_array_free (routes, TRUE);

	flush_eth1 ();

	/* No routes left. */
	routes = nm_platform_ip6_route_get_all (0, NM_PLATFORM_GET_ROUTE_MODE_ALL);
	g_assert_cmpint (routes->len, ==, 0);
	g_array_free (routes, TRUE);
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv);

	nm_fake_platform_setup ();

	g_test_add_func ("/route-manager/ip4", test_ip4);
	g_test_add_func ("/route-manager/ip6", test_ip6);

	return g_test_run ();
}
