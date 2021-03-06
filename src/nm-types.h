/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_TYPES_H__
#define __NETWORKMANAGER_TYPES_H__

/* core */
typedef struct _NMActiveConnection   NMActiveConnection;
typedef struct _NMVpnConnection      NMVpnConnection;
typedef struct _NMActRequest         NMActRequest;
typedef struct _NMAuthSubject        NMAuthSubject;
typedef struct _NMConnectionProvider NMConnectionProvider;
typedef struct _NMConnectivity       NMConnectivity;
typedef struct _NMDBusManager        NMDBusManager;
typedef struct _NMDefaultRouteManager NMDefaultRouteManager;
typedef struct _NMDevice             NMDevice;
typedef struct _NMDhcp4Config        NMDhcp4Config;
typedef struct _NMDhcp6Config        NMDhcp6Config;
typedef struct _NMIP4Config          NMIP4Config;
typedef struct _NMIP6Config          NMIP6Config;
typedef struct _NMManager            NMManager;
typedef struct _NMPolicy             NMPolicy;
typedef struct _NMRfkillManager      NMRfkillManager;
typedef struct _NMSessionMonitor     NMSessionMonitor;
typedef struct _NMSleepMonitor       NMSleepMonitor;

typedef enum {
	/* In priority order; higher number == higher priority */
	NM_IP_CONFIG_SOURCE_UNKNOWN,
	NM_IP_CONFIG_SOURCE_KERNEL,
	NM_IP_CONFIG_SOURCE_SHARED,
	NM_IP_CONFIG_SOURCE_IP4LL,
	NM_IP_CONFIG_SOURCE_PPP,
	NM_IP_CONFIG_SOURCE_WWAN,
	NM_IP_CONFIG_SOURCE_VPN,
	NM_IP_CONFIG_SOURCE_DHCP,
	NM_IP_CONFIG_SOURCE_RDISC,
	NM_IP_CONFIG_SOURCE_USER,
} NMIPConfigSource;

/* platform */
typedef struct _NMPlatformIP4Address NMPlatformIP4Address;
typedef struct _NMPlatformIP4Route   NMPlatformIP4Route;
typedef struct _NMPlatformIP6Address NMPlatformIP6Address;
typedef struct _NMPlatformIP6Route   NMPlatformIP6Route;
typedef struct _NMPlatformLink       NMPlatformLink;

typedef enum {
	/* Please don't interpret type numbers outside nm-platform and use functions
	 * like nm_platform_link_is_software() and nm_platform_supports_slaves().
	 *
	 * type & 0x10000 -> Software device type
	 * type & 0x20000 -> Type supports slaves
	 */

	/* No type, used as error value */
	NM_LINK_TYPE_NONE,

	/* Unknown type  */
	NM_LINK_TYPE_UNKNOWN,

	/* Hardware types */
	NM_LINK_TYPE_ETHERNET,
	NM_LINK_TYPE_INFINIBAND,
	NM_LINK_TYPE_OLPC_MESH,
	NM_LINK_TYPE_WIFI,
	NM_LINK_TYPE_WWAN_ETHERNET,   /* WWAN pseudo-ethernet */
	NM_LINK_TYPE_WIMAX,

	/* Software types */
	NM_LINK_TYPE_DUMMY = 0x10000,
	NM_LINK_TYPE_GRE,
	NM_LINK_TYPE_GRETAP,
	NM_LINK_TYPE_IFB,
	NM_LINK_TYPE_LOOPBACK,
	NM_LINK_TYPE_MACVLAN,
	NM_LINK_TYPE_MACVTAP,
	NM_LINK_TYPE_OPENVSWITCH,
	NM_LINK_TYPE_TAP,
	NM_LINK_TYPE_TUN,
	NM_LINK_TYPE_VETH,
	NM_LINK_TYPE_VLAN,
	NM_LINK_TYPE_VXLAN,

	/* Software types with slaves */
	NM_LINK_TYPE_BRIDGE = 0x10000 | 0x20000,
	NM_LINK_TYPE_BOND,
	NM_LINK_TYPE_TEAM,
} NMLinkType;

/* settings */
typedef struct _NMAgentManager       NMAgentManager;
typedef struct _NMSecretAgent        NMSecretAgent;
typedef struct _NMSettings           NMSettings;
typedef struct _NMSettingsConnection NMSettingsConnection;

#endif  /* NM_TYPES_H */
