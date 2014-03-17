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
 * (C) Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_UTIL_PRIVATE_H__
#define __NM_UTIL_PRIVATE_H__

#include <glib.h>

#include "nm-string-table.h"

G_BEGIN_DECLS

typedef struct NMUtilPrivateData {
	NMStringTable *(*f_nm_string_table_new) (NMStringTableCompareFunc compare, int argc, const NMStringTableTuple *args);
	guint (*f_nm_string_table_size) (NMStringTable *table);
	const char *const*(*f_nm_string_table_get_keys) (NMStringTable *table);
	NMStringTableCompareFunc (*f_nm_string_table_get_compare_func) (NMStringTable *table);
	gboolean (*f_nm_string_table_lookup_by_key) (NMStringTable *table, const char *key, int *out_idx, const char **out_key, gpointer **out_data);
	gboolean (*f_nm_string_table_lookup_by_index) (NMStringTable *table, int idx, const char **out_key, gpointer **out_data);
	gpointer (*f_nm_string_table_get_data_by_key) (NMStringTable *table, const char *key);
	gpointer *(*f_nm_string_table_get_data) (NMStringTable *table);
} NMUtilPrivateData;

const NMUtilPrivateData *nm_util_get_private (void);

#define NM_UTIL_PRIVATE_CALL(call) (nm_util_get_private ()->f_##call)

G_END_DECLS

#endif
