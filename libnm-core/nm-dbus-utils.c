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
 * Copyright 2013-2014 Red Hat, Inc.
 */

#include <config.h>

#include "nm-dbus-utils.h"

void
_nm_dbus_check_name_has_owner (GDBusConnection *connection,
                               const gchar *name,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	g_dbus_connection_call (connection,
	                        "org.freedesktop.DBus",
	                        "/org/freedesktop/DBus",
	                        "org.freedesktop.DBus",
	                        "NameHasOwner",
	                        g_variant_new ("(s)", name),
	                        G_VARIANT_TYPE ("(b)"),
	                        G_DBUS_CALL_FLAGS_NONE, -1,
	                        cancellable,
	                        callback, user_data);
}

gboolean
_nm_dbus_check_name_has_owner_finish (GDBusConnection *connection,
                                      GAsyncResult *result,
                                      gboolean *has_owner,
                                      GError **error)
{
	GVariant *ret;

	ret = g_dbus_connection_call_finish (connection, result, error);
	if (ret) {
		g_variant_get (ret, "(b)", has_owner);
		g_variant_unref (ret);
	}

	return ret != NULL;
}

gboolean
_nm_dbus_check_name_has_owner_sync (GDBusConnection *connection,
                                    const gchar *name,
                                    gboolean *has_owner,
                                    GCancellable *cancellable,
                                    GError **error)
{
	GVariant *ret;

	ret = g_dbus_connection_call_sync (connection,
	                                   "org.freedesktop.DBus",
	                                   "/org/freedesktop/DBus",
	                                   "org.freedesktop.DBus",
	                                   "NameHasOwner",
	                                   g_variant_new ("(s)", name),
	                                   G_VARIANT_TYPE ("(b)"),
	                                   G_DBUS_CALL_FLAGS_NONE, -1,
	                                   cancellable, error);
	if (ret) {
		g_variant_get (ret, "(b)", has_owner);
		g_variant_unref (ret);
	}

	return ret != NULL;
}

void
_nm_dbus_request_name (GDBusConnection *connection,
                       const gchar *name,
                       guint flags,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	g_dbus_connection_call (connection,
	                        "org.freedesktop.DBus",
	                        "/org/freedesktop/DBus",
	                        "org.freedesktop.DBus",
	                        "RequestName",
	                        g_variant_new ("(su)", name, flags),
	                        G_VARIANT_TYPE ("(u)"),
	                        G_DBUS_CALL_FLAGS_NONE, -1,
	                        cancellable,
	                        callback, user_data);
}

int
_nm_dbus_request_name_finish (GDBusConnection *connection,
                              GAsyncResult *result,
                              GError **error)
{
	GVariant *ret;
	guint code = 0;

	ret = g_dbus_connection_call_finish (connection, result, error);
	if (ret) {
		g_variant_get (ret, "(u)", &code);
		g_variant_unref (ret);
	}

	return code;
}

gboolean
_nm_dbus_request_name_sync (GDBusConnection *connection,
                            const gchar *name,
                            guint flags,
                            GCancellable *cancellable,
                            GError **error)
{
	GVariant *ret;
	guint code = 0;

	ret = g_dbus_connection_call_sync (connection,
	                                   "org.freedesktop.DBus",
	                                   "/org/freedesktop/DBus",
	                                   "org.freedesktop.DBus",
	                                   "RequestName",
	                                   g_variant_new ("(su)", name, flags),
	                                   G_VARIANT_TYPE ("(u)"),
	                                   G_DBUS_CALL_FLAGS_NONE, -1,
	                                   cancellable, error);
	if (ret) {
		g_variant_get (ret, "(u)", &code);
		g_variant_unref (ret);
	}

	return code;
}

void
_nm_dbus_register_error_domain (GQuark domain,
                                const char *interface,
                                GType enum_type)
{
	GEnumClass *enum_class;
	GEnumValue *e;
	char *error_name;
	int i;

	enum_class = g_type_class_ref (enum_type);
	for (i = 0; i < enum_class->n_values; i++) {
		e = &enum_class->values[i];
		error_name = g_strdup_printf ("%s.%s", interface, e->value_nick);
		g_dbus_error_register_error (domain, e->value, error_name);
		g_free (error_name);
	}

	g_type_class_unref (enum_class);
}


void
_nm_dbus_bind_properties (gpointer object, gpointer skeleton)
{
	GParamSpec **properties;
	guint n_properties;
	int i;

	properties = g_object_class_list_properties (G_OBJECT_GET_CLASS (skeleton), &n_properties);
	for (i = 0; i < n_properties; i++) {
		g_object_bind_property (object, properties[i]->name,
		                        skeleton, properties[i]->name,
		                        G_BINDING_BIDIRECTIONAL | G_BINDING_SYNC_CREATE);
	}
}
