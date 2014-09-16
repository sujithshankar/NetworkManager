/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2005 - 2014 Red Hat, Inc.
 */

#ifndef __NM_UTILS_PRIVATE_H__
#define __NM_UTILS_PRIVATE_H__

#include "nm-setting-private.h"

gboolean    _nm_utils_string_in_list   (const char *str,
                                        const char **valid_strings);

gboolean    _nm_utils_string_slist_validate (GSList *list,
                                             const char **valid_values);

gboolean    _nm_utils_gvalue_array_validate (GValueArray *elements,
                                             guint n_expected, ...);

void        _nm_value_transforms_register (void);

void        _nm_utils_hwaddr_to_dbus   (const GValue *prop_value,
                                        GValue *dbus_value);
void        _nm_utils_hwaddr_from_dbus (const GValue *dbus_value,
                                        GValue *prop_value);

void        _nm_utils_strdict_to_dbus   (const GValue *prop_value,
                                         GValue *dbus_value);
void        _nm_utils_strdict_from_dbus (const GValue *dbus_value,
                                         GValue *prop_value);

void        _nm_utils_bytes_to_dbus     (const GValue *prop_value,
                                         GValue *dbus_value);
void        _nm_utils_bytes_from_dbus   (const GValue *dbus_value,
                                         GValue *prop_value);

void        _nm_utils_ip4_dns_to_dbus         (const GValue *prop_value,
                                               GValue *dbus_value);
void        _nm_utils_ip4_dns_from_dbus       (const GValue *dbus_value,
                                               GValue *prop_value);
void        _nm_utils_ip4_addresses_to_dbus   (const GValue *prop_value,
                                               GValue *dbus_value);
void        _nm_utils_ip4_addresses_from_dbus (const GValue *dbus_value,
                                               GValue *prop_value);
void        _nm_utils_ip4_routes_to_dbus      (const GValue *prop_value,
                                               GValue *dbus_value);
void        _nm_utils_ip4_routes_from_dbus    (const GValue *dbus_value,
                                               GValue *prop_value);

void        _nm_utils_ip6_dns_to_dbus         (const GValue *prop_value,
                                               GValue *dbus_value);
void        _nm_utils_ip6_dns_from_dbus       (const GValue *dbus_value,
                                               GValue *prop_value);
void        _nm_utils_ip6_addresses_to_dbus   (const GValue *prop_value,
                                               GValue *dbus_value);
void        _nm_utils_ip6_addresses_from_dbus (const GValue *dbus_value,
                                               GValue *prop_value);
void        _nm_utils_ip6_routes_to_dbus      (const GValue *prop_value,
                                               GValue *dbus_value);
void        _nm_utils_ip6_routes_from_dbus    (const GValue *dbus_value,
                                               GValue *prop_value);

GSList *    _nm_utils_strv_to_slist (char **strv);
char **     _nm_utils_slist_to_strv (GSList *slist);

char **     _nm_utils_strsplit_set (const char *str,
                                    const char *delimiters,
                                    int max_tokens);

#endif