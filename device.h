/* MSPDebug - debugging tool for MSP430 MCUs
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

#ifndef DEVICE_H_
#define DEVICE_H_

#include <stdint.h>
#include "util.h"

struct device;
typedef struct device *device_t;

extern device_t device_default;

typedef enum {
	DEVICE_CTL_RESET,
	DEVICE_CTL_RUN,
	DEVICE_CTL_HALT,
	DEVICE_CTL_STEP
} device_ctl_t;

typedef enum {
	DEVICE_STATUS_HALTED,
	DEVICE_STATUS_RUNNING,
	DEVICE_STATUS_INTR,
	DEVICE_STATUS_ERROR
} device_status_t;

typedef enum {
	DEVICE_ERASE_ALL,
	DEVICE_ERASE_MAIN,
	DEVICE_ERASE_SEGMENT
} device_erase_type_t;

#define DEVICE_NUM_REGS		16
#define DEVICE_MAX_BREAKPOINTS  32

#define DEVICE_BP_ENABLED       0x01
#define DEVICE_BP_DIRTY         0x02

struct device_breakpoint {
	address_t      addr;
	int            flags;
};

struct device {
	/* Breakpoint table. This should not be modified directly.
	 * Instead, you should use the device_setbrk() helper function. This
	 * will set the appropriate flags and ensure that the breakpoint is
	 * reloaded before the next run.
	 */
	int max_breakpoints;
	struct device_breakpoint breakpoints[DEVICE_MAX_BREAKPOINTS];

	/* Close the connection to the device and destroy the driver object */
	void (*destroy)(device_t dev);

	/* Read/write memory */
	int (*readmem)(device_t dev, address_t addr,
		       uint8_t *mem, address_t len);
	int (*writemem)(device_t dev, address_t addr,
			const uint8_t *mem, address_t len);

	/* Erase memory */
	int (*erase)(device_t dev, device_erase_type_t type,
		     address_t address);

	/* Read/write registers */
	int (*getregs)(device_t dev, address_t *regs);
	int (*setregs)(device_t dev, const address_t *regs);

	/* CPU control */
	int (*ctl)(device_t dev, device_ctl_t op);

	/* Wait a little while for the CPU to change state */
	device_status_t (*poll)(device_t dev);
};

/* Set or clear a breakpoint. The index of the modified entry is
 * returned, or -1 if no free entries were available. The modified
 * entry is flagged so that it will be reloaded on the next run.
 *
 * If which is specified, a particular breakpoint slot is
 * modified. Otherwise, if which < 0, breakpoint slots are selected
 * automatically.
 */
int device_setbrk(device_t dev, int which, int enabled, address_t address);

#endif
