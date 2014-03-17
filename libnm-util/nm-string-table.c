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

#include "nm-string-table.h"

#include <string.h>

const NMStringTableCompareFunc COMPARE_DEFAULT = &strcmp;

typedef struct NMStringTable {
	guint size;
	NMStringTableCompareFunc compare;

	void *_offset;
} NMStringTable;

#define OFFSET_STRING(table)     ((const char **) ((&((table)->_offset))))
#define OFFSET_DATA(table)       ((void **) &(OFFSET_STRING (table)[(table)->size + 1]))
#define OFFSET_STATICSTR(table)  ((const char *) &(OFFSET_DATA (table)[(table)->size + 1]))

#ifndef G_DISABLE_ASSERT
struct prepare_sort_data
{
	NMStringTableCompareFunc compare;
	gboolean duplicate;
};

static gint
prepare_sort_check (gconstpointer a, gconstpointer b, gpointer user_data)
{
	const NMStringTableTuple *a1 = a;
	const NMStringTableTuple *a2 = b;
	struct prepare_sort_data *data = user_data;
	int c;

	c = (data->compare) (a1->key, a2->key);
	if (c == 0)
		data->duplicate = TRUE;
	return c;
}
#else
static gint
prepare_sort_direct (gconstpointer a, gconstpointer b, gpointer user_data)
{
	const NMStringTableTuple *a1 = a;
	const NMStringTableTuple *a2 = b;

	return ((NMStringTableCompareFunc) user_data) (a1->key, a2->key);
}
#endif

static NMStringTable *
_new (NMStringTableCompareFunc compare, GArray *prepare)
{
	NMStringTable *self;
	guint i;
	const char **tab_str;
	const char *tab_static;
	void **tab_dat;
	size_t len;
	GString *static_strings;
	guint argc = prepare ? prepare->len : 0;

	if (!compare)
		compare = COMPARE_DEFAULT;

	if (argc > G_MAXINT) {
		g_array_free (prepare, TRUE);
		g_return_val_if_reached (NULL);
		return NULL;
	}

	static_strings = g_string_new ("");

	if (prepare) {
#ifndef G_DISABLE_ASSERT
		struct prepare_sort_data sort_data = { .compare = compare };

		g_array_sort_with_data (prepare, prepare_sort_check, &sort_data);
		if (sort_data.duplicate) {
			g_string_free (static_strings, TRUE);
			g_array_free (prepare, TRUE);
			g_return_val_if_reached (NULL);
		}
#else
		g_array_sort_with_data (prepare, prepare_sort_direct, compare);
#endif

		for (i = 0; i < argc; i++) {
			NMStringTableTuple *data = &g_array_index (prepare, NMStringTableTuple, i);
			char *new_key = &static_strings->str[static_strings->len];

			g_string_append (static_strings, data->key);
			g_string_append_c (static_strings, '\0');
			data->key = new_key;
		}
	} else
		g_string_append_c (static_strings, '\0');

	len = offsetof (NMStringTable, _offset) +
	      (argc + 1) * (sizeof (const char *) + sizeof (void *)) +
	      static_strings->len;

	self = g_malloc (len);
	self->size = argc;
	self->compare = compare;

	tab_str = OFFSET_STRING (self);
	tab_dat = OFFSET_DATA (self);
	tab_static = OFFSET_STATICSTR (self);
	memcpy ((char *) tab_static, static_strings->str, static_strings->len);
	for (i = 0; i < argc; i++) {
		NMStringTableTuple *data = &g_array_index (prepare, NMStringTableTuple, i);

		(*tab_str++) = &tab_static[data->key - static_strings->str];
		(*tab_dat++) = data->data;
	}
	*tab_str = NULL;
	*tab_dat = NULL;

	g_string_free (static_strings, TRUE);

	if (prepare)
		g_array_free (prepare, TRUE);

	return self;
}

#ifndef G_DISABLE_ASSERT
static gboolean
_assert_args (GArray *prepare, int argc)
{
	guint i;

	g_return_val_if_fail (prepare, FALSE);
	g_return_val_if_fail (prepare->len == argc, FALSE);

	for (i = 0; i < prepare->len; i++ )
		g_return_val_if_fail (g_array_index (prepare, NMStringTableTuple, i).key, FALSE);
	return TRUE;
}
#define ASSERT_ARGS(prepare, argc) \
	G_STMT_START { \
		if (!_assert_args (prepare, argc)) { \
			g_array_free (prepare, TRUE); \
			return NULL; \
		} \
	} G_STMT_END
#else
#define ASSERT_ARGS(prepare, argc) G_STMT_START { ; } G_STMT_END
#endif

NMStringTable *
nm_string_table_new_keys_only (NMStringTableCompareFunc compare, int argc, const char **args)
{
	guint i;
	GArray *prepare = NULL;

	g_return_val_if_fail ((argc > 0 && args) || argc <= 0, NULL);

	if (argc > 0 || args) {
		NMStringTableTuple data = { 0 };

		prepare = g_array_sized_new (FALSE, FALSE, sizeof (NMStringTableTuple), argc > 0 ? argc : 0);
		if (argc > 0) {
			for (i = 0; i < argc; i++) {
				data.key = args[i];
				g_array_append_val (prepare, data);
			}
			ASSERT_ARGS (prepare, argc);
		} else if (argc < 0) {
			/* argc is negative, that means that args is NULL terminated. */
			for (; *args; args++) {
				data.key = *args;
				g_array_append_val (prepare, data);
			}
		}
	}
	return _new (compare, prepare);
}

NMStringTable *
nm_string_table_new (NMStringTableCompareFunc compare, int argc, const NMStringTableTuple *args)
{
	GArray *prepare = NULL;

	g_return_val_if_fail (!argc || args, NULL);

	if (argc > 0 || args) {
		prepare = g_array_sized_new (FALSE, FALSE, sizeof (NMStringTableTuple), 0);
		if (argc > 0) {
			g_array_append_vals (prepare, args, argc);
			ASSERT_ARGS (prepare, argc);
		} else if (argc < 0) {
			/* argc is negative, that means that args is NULL terminated. */
			for (; args->key; args++)
				g_array_append_val (prepare, *args);
		}
	}
	return _new (compare, prepare);
}


guint
nm_string_table_size (NMStringTable *self)
{
	g_return_val_if_fail (self, 0);

	return self->size;
}

static int
_lookup_by_key (NMStringTable *self, const char *key)
{
	const char *const*t_str;
	guint imin, imax, imid;

	g_return_val_if_fail (self, -1);
	g_return_val_if_fail (key, -1);

	if (self->size == 0)
		return -1;

	t_str = OFFSET_STRING (self);
	imin = 0;
	imax = self->size - 1;

	if (key >= t_str[0] && key <= t_str[imax]) {
		/* Try binary search using the pointer value. We try this
		 * optimization, because the user might lookup using one of the
		 * key values themselves.
		 */
		while (imax >= imin) {
			/* save against overflow, because size is <= INT_MAX */
			imid = (imax + imin) / 2;
			if (t_str[imid] == key)
				return imid;
			if (t_str[imid] < key)
				imin = imid + 1;
			else
				imax = imid - 1;
		}

		/* if we did not find by pointer comparison, try again using
		 * strcmp. The user has provided a substring to one of the keys...
		 */
		imin = 0;
		imax = self->size - 1;
	}
	/* binary search using the compare function. */
	while (imax >= imin) {
		int c;

		/* save against overflow, because size is <= INT_MAX */
		imid = (imax + imin) / 2;
		c = self->compare (key, t_str[imid]);

		if (!c)
			return imid;
		if (c > 0)
			imin = imid + 1;
		else
			imax = imid - 1;
	}

	return -1;
}

static gboolean
_access_at_index (NMStringTable *self, int idx, const char **out_key, gpointer **out_data)
{
	if (idx < 0) {
		if (out_key)
			*out_key = NULL;
		if (out_data)
			out_data = NULL;
		return FALSE;
	}
	if (out_key)
		*out_key = OFFSET_STRING (self)[idx];
	if (out_data)
		*out_data = &OFFSET_DATA (self)[idx];
	return TRUE;
}

gboolean
nm_string_table_lookup_by_key (NMStringTable *self, const char *key, int *out_idx, const char **out_key, gpointer **out_data)
{
	int idx = _lookup_by_key (self, key);

	if (out_idx)
		*out_idx = idx;
	return _access_at_index (self, idx, out_key, out_data);
}

gboolean
nm_string_table_lookup_by_index (NMStringTable *self, int idx, const char **out_key, gpointer **out_data)
{
	g_return_val_if_fail (self, FALSE);

	if (idx >= self->size) {
		/* don't check for idx<0, _access_at_index will handle that. */
		idx = -1;
	}
	return _access_at_index (self, idx, out_key, out_data);
}

gpointer
nm_string_table_get_data_by_key (NMStringTable *self, const char *key)
{
	int idx = _lookup_by_key (self, key);

	return idx >= 0 ? OFFSET_DATA (self)[idx] : NULL;
}

const char *const*
nm_string_table_get_keys (NMStringTable *self)
{
	g_return_val_if_fail (self, NULL);

	return OFFSET_STRING (self);
}

gpointer *
nm_string_table_get_data (NMStringTable *self)
{
	g_return_val_if_fail (self, NULL);

	return OFFSET_DATA (self);
}

NMStringTableCompareFunc
nm_string_table_get_compare_func (NMStringTable *self)
{
	g_return_val_if_fail (self, NULL);

	return self->compare;
}

void
nm_string_table_foreach (NMStringTable *self, NMStringTableForeachFunc func, void *user_data)
{
	const char **tab_str;
	void **tab_dat;
	guint i, size;

	g_return_if_fail (self);
	g_return_if_fail (func);

	tab_str = OFFSET_STRING (self);
	tab_dat = OFFSET_DATA (self);
	for (i = 0, size = self->size; i < size; i++) {
		if (!func (tab_str[i], &tab_dat[i], i, user_data))
			return;
	}
}

