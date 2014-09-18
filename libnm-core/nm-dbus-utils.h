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

#ifndef NM_DBUS_UTILS_H
#define NM_DBUS_UTILS_H

#include <gio/gio.h>

void     _nm_dbus_check_name_has_owner        (GDBusConnection *connection,
                                               const gchar *name,
                                               GCancellable *cancellable,
                                               GAsyncReadyCallback callback,
                                               gpointer user_data);
gboolean _nm_dbus_check_name_has_owner_finish (GDBusConnection *connection,
                                               GAsyncResult *result,
                                               gboolean *has_owner,
                                               GError **error);

gboolean _nm_dbus_check_name_has_owner_sync   (GDBusConnection *connection,
                                               const gchar *name,
                                               gboolean *has_owner,
                                               GCancellable *cancellable,
                                               GError **error);

#define DBUS_NAME_FLAG_ALLOW_REPLACEMENT 0x1
#define DBUS_NAME_FLAG_REPLACE_EXISTING  0x2
#define DBUS_NAME_FLAG_DO_NOT_QUEUE      0x4

#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER  1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE       2
#define DBUS_REQUEST_NAME_REPLY_EXISTS         3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER  4

void     _nm_dbus_request_name                (GDBusConnection *connection,
                                               const gchar *name,
                                               guint flags,
                                               GCancellable *cancellable,
                                               GAsyncReadyCallback callback,
                                               gpointer user_data);
int      _nm_dbus_request_name_finish         (GDBusConnection *connection,
                                               GAsyncResult *result,
                                               GError **error);

int      _nm_dbus_request_name_sync           (GDBusConnection *connection,
                                               const gchar *name,
                                               guint flags,
                                               GCancellable *cancellable,
                                               GError **error);

void _nm_dbus_register_error_domain (GQuark domain,
                                     const char *interface,
                                     GType enum_type);

void _nm_dbus_bind_properties (gpointer object,
                               gpointer skeleton);

#endif /* NM_DBUS_UTILS_H */
