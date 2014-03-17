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

#include "nm-util-private.h"

static const NMUtilPrivateData data = {
	.f_nm_string_table_new = &nm_string_table_new,
	.f_nm_string_table_size = &nm_string_table_size,
	.f_nm_string_table_get_keys = &nm_string_table_get_keys,
	.f_nm_string_table_get_compare_func = &nm_string_table_get_compare_func,
	.f_nm_string_table_lookup_by_key = &nm_string_table_lookup_by_key,
	.f_nm_string_table_lookup_by_index= &nm_string_table_lookup_by_index,
	.f_nm_string_table_get_data_by_key= &nm_string_table_get_data_by_key,
	.f_nm_string_table_get_data = &nm_string_table_get_data,
};

const NMUtilPrivateData *
nm_util_get_private (void)
{
	return &data;
}

