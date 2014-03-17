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

#ifndef __NM_STRING_TABLE_H__
#define __NM_STRING_TABLE_H__

#include <glib.h>

G_BEGIN_DECLS

typedef struct NMStringTable NMStringTable;

typedef int (*NMStringTableCompareFunc) (const char *s1, const char *s2);
typedef gboolean (*NMStringTableForeachFunc) (const char *key, gpointer *pdata, int idx, void *user_data);

typedef struct {
	const char *key;
	void *data;
} NMStringTableTuple;

NMStringTable *nm_string_table_new (NMStringTableCompareFunc compare, int argc, const NMStringTableTuple *args);
NMStringTable *nm_string_table_new_keys_only (NMStringTableCompareFunc compare, int argc, const char **args);

guint nm_string_table_size (NMStringTable *table);
NMStringTableCompareFunc nm_string_table_get_compare_func (NMStringTable *table);
gboolean nm_string_table_lookup_by_key (NMStringTable *table, const char *key, int *out_idx, const char **out_key, gpointer **out_data);
gboolean nm_string_table_lookup_by_index (NMStringTable *table, int idx, const char **out_key, gpointer **out_data);

gpointer nm_string_table_get_data_by_key (NMStringTable *table, const char *key);

const char *const*nm_string_table_get_keys (NMStringTable *table);
gpointer *nm_string_table_get_data (NMStringTable *table);

void nm_string_table_foreach (NMStringTable *table, NMStringTableForeachFunc func, void *user_data);

G_END_DECLS

#endif /* __NM_STRING_TABLE_H__ */
