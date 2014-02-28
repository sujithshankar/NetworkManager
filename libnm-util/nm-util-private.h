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

G_BEGIN_DECLS

typedef struct NMUtilPrivateData {
} NMUtilPrivateData;

const NMUtilPrivateData *nm_util_get_private (void);

#define NM_UTIL_PRIVATE_CALL(call) (nm_util_get_private ()->f_##call)

G_END_DECLS

#endif
