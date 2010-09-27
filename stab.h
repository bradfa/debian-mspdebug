/* MSPDebug - debugging tool for the eZ430
 * Copyright (C) 2009, 2010 Daniel Beer
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef STAB_H_
#define STAB_H_

#include <sys/types.h>

/* Initialise/destroy the symbol table manager. If successful, init returns
 * 0, or -1 on error.
 */
int stab_init(void);
void stab_exit(void);

/* Reset the symbol table (delete all symbols) */
void stab_clear(void);

/* Set a symbol in the table. Returns 0 on success, or -1 on error. */
int stab_set(const char *name, int value);

/* Take an address and find the nearest symbol and offset (always
 * non-negative).
 *
 * Returns 0 if found, 1 otherwise.
 */
int stab_nearest(u_int16_t addr, char *ret_name, int max_len,
		 u_int16_t *ret_offset);

/* Retrieve the value of a symbol. Returns 0 on success or -1 if the symbol
 * doesn't exist.
 */
int stab_get(const char *name, int *value);

/* Delete a symbol table entry. Returns 0 on success or -1 if the symbol
 * doesn't exist.
 */
int stab_del(const char *name);

/* Enumerate all symbols in the table */
typedef int (*stab_callback_t)(const char *name, u_int16_t value);

int stab_enum(stab_callback_t cb);

/* Parse an address expression, storing the result in the integer
 * pointed to. Returns 0 if parsed successfully, -1 if not.
 */
int stab_exp(const char *text, int *value);

#endif
