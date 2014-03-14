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
 * Copyright (C) 2014 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <string.h>
#include <errno.h>

#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-logging.h"


static void
ASSERT_CONTAINS_SUBSTR (const char *str, const char *substr)
{
	g_assert (str);
	g_assert (substr);
	if (strstr (str, substr) == NULL) {
		nm_log_dbg (LOGD_PLATFORM, "Expects \"%s\" but got \"%s\"", substr, str ? str : "(null)");
		g_assert_cmpstr (str, ==, substr);
	}
}

static void
test_nm_platform_ip6_address_to_string_flags (void)
{
	NMPlatformIP6Address addr = { 0 };

	g_assert_cmpstr (strstr (nm_platform_ip6_address_to_string (&addr), " flags "), ==, NULL);

	addr.flags = IFA_F_MANAGETEMPADDR;
	ASSERT_CONTAINS_SUBSTR (nm_platform_ip6_address_to_string (&addr), " flags mngtmpaddr ");

	addr.flags = IFA_F_NOPREFIXROUTE;
	ASSERT_CONTAINS_SUBSTR (nm_platform_ip6_address_to_string (&addr), " flags noprefixroute ");

	addr.flags = IFA_F_MANAGETEMPADDR | IFA_F_NOPREFIXROUTE;
	ASSERT_CONTAINS_SUBSTR (nm_platform_ip6_address_to_string (&addr), " flags mngtmpaddr,noprefixroute ");

	addr.flags = IFA_F_TENTATIVE | IFA_F_NOPREFIXROUTE;
	ASSERT_CONTAINS_SUBSTR (nm_platform_ip6_address_to_string (&addr), " flags tentative,noprefixroute ");

	addr.flags = IFA_F_TENTATIVE | IFA_F_PERMANENT | IFA_F_MANAGETEMPADDR| IFA_F_NOPREFIXROUTE;
	ASSERT_CONTAINS_SUBSTR (nm_platform_ip6_address_to_string (&addr), " flags tentative,permanent,mngtmpaddr,noprefixroute ");

	addr.flags = IFA_F_TENTATIVE | IFA_F_PERMANENT | IFA_F_MANAGETEMPADDR| IFA_F_NOPREFIXROUTE | 0x8000;
	ASSERT_CONTAINS_SUBSTR (nm_platform_ip6_address_to_string (&addr), " flags tentative,permanent,mngtmpaddr,noprefixroute, ");

	addr.flags = IFA_F_TENTATIVE | IFA_F_PERMANENT | IFA_F_MANAGETEMPADDR| IFA_F_NOPREFIXROUTE | ((G_MAXUINT - (G_MAXUINT >> 1)) >> 1);
	ASSERT_CONTAINS_SUBSTR (nm_platform_ip6_address_to_string (&addr), " flags tentative,permanent,mngtmpaddr,noprefixroute, ");
}

/*******************************************/

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_type_init ();

	nm_logging_setup ("DEBUG", "ALL", NULL, NULL);

	g_test_add_func ("/general/nm_platform_ip6_address_to_string/flags", test_nm_platform_ip6_address_to_string_flags);

	return g_test_run ();
}

