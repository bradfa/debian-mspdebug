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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "device.h"
#include "dis.h"
#include "util.h"
#include "stab.h"

#define MEM_SIZE	65536

static u_int8_t *memory;
static u_int16_t sim_regs[DEVICE_NUM_REGS];

#define MEM_GETB(offset) (memory[offset])
#define MEM_SETB(offset, value) (memory[offset] = (value))
#define MEM_GETW(offset) \
	(memory[offset] | (memory[(offset + 1) & 0xffff] << 8))
#define MEM_SETW(offset, value) \
	do {							\
		memory[offset] = (value) & 0xff;		\
		memory[(offset + 1) & 0xffff] = (value) >> 8;	\
	} while (0);

#define MEM_IO_END 0x200

/* PC at the start of the current instruction */
static u_int16_t current_insn;

static void io_prefix(const char *prefix, u_int16_t addr, int is_byte)
{
	const char *name;
	u_int16_t pc = current_insn;

	if (!stab_find(&pc, &name)) {
		printf("%s", name);
		if (pc)
			printf("+0x%x", addr);
	} else {
		printf("0x%04x", addr);
	}

	printf(": IO %s.%c: 0x%04x", prefix, is_byte ? 'B' : 'W', addr);
	if (!stab_find(&addr, &name)) {
		printf(" (%s", name);
		if (addr)
			printf("+0x%x", addr);
		printf(")");
	}
}

static u_int16_t fetch_io(u_int16_t addr, int is_byte)
{
	io_prefix("READ", addr, is_byte);

	for (;;) {
		char text[128];
		int len;
		int data;

		printf("? ");
		fflush(stdout);
		if (!fgets(text, sizeof(text), stdin))
			return 0;

		len = strlen(text);
		while (len && isspace(text[len - 1]))
			len--;
		text[len] = 0;

		if (!stab_parse(text, &data))
			return data;
	}

	return 0;
}

static void store_io(u_int16_t addr, int is_byte, u_int16_t data)
{
	io_prefix("WRITE", addr, is_byte);

	if (is_byte)
		printf(" => 0x%02x\n", data & 0xff);
	else
		printf(" => 0x%04x\n", data);
}

static void fetch_operand(int amode, int reg, int is_byte,
			  u_int16_t *addr_ret, u_int32_t *data_ret)
{
	u_int16_t addr = 0;
	u_int32_t mask = is_byte ? 0xff : 0xffff;

	switch (amode) {
	case MSP430_AMODE_REGISTER:
		if (reg == MSP430_REG_R3) {
			if (data_ret)
				*data_ret = 0;
			return;
		}
		if (data_ret)
			*data_ret = sim_regs[reg] & mask;
		return;

	case MSP430_AMODE_INDEXED:
		if (reg == MSP430_REG_R3) {
			if (data_ret)
				*data_ret = 1;
			return;
		}

		addr = MEM_GETW(sim_regs[MSP430_REG_PC]);
		sim_regs[MSP430_REG_PC] += 2;

		if (reg != MSP430_REG_SR)
			addr += sim_regs[reg];
		break;

	case MSP430_AMODE_INDIRECT:
		if (reg == MSP430_REG_SR) {
			if (data_ret)
				*data_ret = 4;
			return;
		}

		if (reg == MSP430_REG_R3) {
			if (data_ret)
				*data_ret = 2;
			return;
		}
		addr = sim_regs[reg];
		break;

	case MSP430_AMODE_INDIRECT_INC:
		if (reg == MSP430_REG_SR) {
			if (data_ret)
				*data_ret = 8;
			return;
		}
		if (reg == MSP430_REG_R3) {
			if (data_ret)
				*data_ret = mask;
			return;
		}
		addr = sim_regs[reg];
		sim_regs[reg] += 2;
		break;
	}

	if (addr_ret)
		*addr_ret = addr;

	if (data_ret) {
		if (addr < MEM_IO_END)
			*data_ret = fetch_io(addr, is_byte);
		else
			*data_ret = MEM_GETW(addr) & mask;
	}
}

static void store_operand(int amode, int reg, int is_byte,
			  u_int16_t addr, u_int16_t data)
{
	if (amode == MSP430_AMODE_REGISTER)
		sim_regs[reg] = data;
	else if (addr < MEM_IO_END)
		store_io(addr, is_byte, data);
	else if (is_byte)
		MEM_SETB(addr, data);
	else
		MEM_SETW(addr, data);
}

#define ARITH_BITS (MSP430_SR_V | MSP430_SR_N | MSP430_SR_Z | MSP430_SR_C)

static int step_double(u_int16_t ins)
{
	u_int16_t opcode = ins & 0xf000;
	int sreg = (ins >> 8) & 0xf;
	int amode_dst = (ins >> 7) & 1;
	int is_byte = ins & 0x0040;
	int amode_src = (ins >> 4) & 0x3;
	int dreg = ins & 0x000f;
	u_int32_t src_data;
	u_int16_t dst_addr = 0;
	u_int32_t dst_data;
	u_int32_t res_data;
	u_int32_t msb = is_byte ? 0x80 : 0x8000;

	fetch_operand(amode_src, sreg, is_byte, NULL, &src_data);
	fetch_operand(amode_dst, dreg, is_byte, &dst_addr,
		      opcode == MSP430_OP_MOV ? NULL : &dst_data);

	switch (opcode) {
	case MSP430_OP_MOV:
		res_data = src_data;
		break;

	case MSP430_OP_SUB:
	case MSP430_OP_SUBC:
	case MSP430_OP_CMP:
		src_data = ~src_data;
	case MSP430_OP_ADD:
	case MSP430_OP_ADDC:
		if (opcode == MSP430_OP_ADDC || opcode == MSP430_OP_SUBC)
			res_data = (sim_regs[MSP430_REG_SR] &
				    MSP430_SR_C) ? 1 : 0;
		else if (opcode == MSP430_OP_SUB)
			res_data = 1;
		else
			res_data = 0;

		res_data += src_data;
		res_data += dst_data;

		sim_regs[MSP430_REG_SR] &= ~ARITH_BITS;
		if (!res_data)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_Z;
		if (res_data & msb)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_N;
		if (res_data & (msb << 1))
			sim_regs[MSP430_REG_SR] |= MSP430_SR_C;
		if (!((src_data ^ dst_data) & msb) &&
		    (src_data ^ dst_data) & msb)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_V;
		break;

	case MSP430_OP_DADD:
		res_data = src_data + dst_data;
		if (sim_regs[MSP430_REG_SR] & MSP430_SR_C)
			res_data++;

		sim_regs[MSP430_REG_SR] &= ~ARITH_BITS;
		if (!res_data)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_Z;
		if (res_data == 1)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_N;
		if ((is_byte && res_data > 99) ||
		    (!is_byte && res_data > 9999))
			sim_regs[MSP430_REG_SR] |= MSP430_SR_C;
		break;

	case MSP430_OP_BIT:
	case MSP430_OP_AND:
		res_data = src_data & dst_data;

		sim_regs[MSP430_REG_SR] &= ~ARITH_BITS;
		sim_regs[MSP430_REG_SR] |=
			res_data ? MSP430_SR_C : MSP430_SR_Z;
		if (res_data & msb)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_N;
		break;

	case MSP430_OP_BIC:
		res_data = dst_data & ~src_data;
		break;

	case MSP430_OP_BIS:
		res_data = dst_data | src_data;
		break;

	case MSP430_OP_XOR:
		res_data = dst_data ^ src_data;
		sim_regs[MSP430_REG_SR] &= ~ARITH_BITS;
		sim_regs[MSP430_REG_SR] |=
			res_data ? MSP430_SR_C : MSP430_SR_Z;
		if (res_data & msb)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_N;
		if (src_data & dst_data & msb)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_V;
		break;

	default:
		fprintf(stderr, "sim: invalid double-operand opcode: "
			"0x%04x (PC = 0x%04x)\n",
			opcode, current_insn);
		return -1;
	}

	if (opcode != MSP430_OP_CMP && opcode != MSP430_OP_BIT)
		store_operand(amode_dst, dreg, is_byte, dst_addr, res_data);

	return 0;
}

static int step_single(u_int16_t ins)
{
	u_int16_t opcode = ins & 0xff80;
	int is_byte = ins & 0x0040;
	int amode = (ins >> 4) & 0x3;
	int reg = ins & 0x000f;
	u_int16_t msb = is_byte ? 0x80 : 0x8000;
	u_int16_t src_addr = 0;
	u_int32_t src_data;
	u_int32_t res_data;

	fetch_operand(amode, reg, is_byte, &src_addr, &src_data);

	switch (opcode) {
	case MSP430_OP_RRC:
	case MSP430_OP_RRA:
		res_data = (src_data >> 1) & ~msb;
		if (opcode == MSP430_OP_RRC) {
			if (sim_regs[MSP430_REG_SR] & MSP430_SR_C)
				res_data |= msb;
		} else {
			res_data |= src_data & msb;
		}

		sim_regs[MSP430_REG_SR] &= ~ARITH_BITS;
		if (!res_data)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_Z;
		if (res_data & msb)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_N;
		if (src_data & 1)
			sim_regs[MSP430_REG_SR] |= MSP430_SR_C;
		break;

	case MSP430_OP_SWPB:
		res_data = ((src_data & 0xff) << 8) | ((src_data >> 8) & 0xff);
		break;

	case MSP430_OP_SXT:
		res_data = src_data & 0xff;
		sim_regs[MSP430_REG_SR] &= ~ARITH_BITS;

		if (src_data & 0x80) {
			res_data |= 0xff00;
			sim_regs[MSP430_REG_SR] |= MSP430_SR_N;
		}

		sim_regs[MSP430_REG_SR] |= res_data ? MSP430_SR_C : MSP430_SR_Z;
		break;

	case MSP430_OP_PUSH:
		sim_regs[MSP430_REG_SP] -= 2;
		MEM_SETW(sim_regs[MSP430_REG_SP], src_data);
		break;

	case MSP430_OP_CALL:
		sim_regs[MSP430_REG_SP] -= 2;
		MEM_SETW(sim_regs[MSP430_REG_SP], sim_regs[MSP430_REG_PC]);
		sim_regs[MSP430_REG_PC] = src_data;
		break;

	case MSP430_OP_RETI:
		sim_regs[MSP430_REG_SR] = MEM_GETW(sim_regs[MSP430_REG_SP]);
		sim_regs[MSP430_REG_SP] += 2;
		sim_regs[MSP430_REG_PC] = MEM_GETW(sim_regs[MSP430_REG_SP]);
		sim_regs[MSP430_REG_SP] += 2;
		break;

	default:
		fprintf(stderr, "sim: unknown single-operand opcode: 0x%04x "
			"(PC = 0x%04x)\n", opcode, current_insn);
		return -1;
	}

	if (opcode != MSP430_OP_PUSH && opcode != MSP430_OP_CALL &&
	    opcode != MSP430_OP_RETI)
		store_operand(amode, reg, is_byte, src_addr, res_data);

	return 0;
}

static int step_jump(u_int16_t ins)
{
	u_int16_t opcode = ins & 0xfc00;
	u_int16_t pc_offset = (ins & 0x03ff) << 1;
	u_int16_t sr = sim_regs[MSP430_REG_SR];

	if (pc_offset & 0x0400)
		pc_offset |= 0xff800;

	switch (opcode) {
	case MSP430_OP_JNZ:
		sr = !(sr & MSP430_SR_Z);
		break;

	case MSP430_OP_JZ:
		sr &= MSP430_SR_Z;
		break;

	case MSP430_OP_JNC:
		sr = !(sr & MSP430_SR_C);
		break;

	case MSP430_OP_JC:
		sr &= MSP430_SR_C;
		break;

	case MSP430_OP_JN:
		sr &= MSP430_SR_N;
		break;

	case MSP430_OP_JGE:
		sr = ((sr & MSP430_SR_N) ? 1 : 0) !=
			((sr & MSP430_SR_V) ? 1 : 0);
		break;

	case MSP430_OP_JL:
		sr = ((sr & MSP430_SR_N) ? 1 : 0) ==
			((sr & MSP430_SR_V) ? 1 : 0);
		break;

	case MSP430_OP_JMP:
		sr = 1;
		break;
	}

	if (sr)
		sim_regs[MSP430_REG_PC] += pc_offset;

	return 0;
}

static int step_cpu(void)
{
	u_int16_t ins;

	/* Fetch the instruction */
	current_insn = sim_regs[MSP430_REG_PC];
	ins = MEM_GETW(current_insn);
	sim_regs[MSP430_REG_PC] += 2;

	/* Handle different instruction types */
	if ((ins & 0xf000) >= 0x4000)
		return step_double(ins);
	else if ((ins & 0xf000) >= 0x2000)
		return step_jump(ins);
	else
		return step_single(ins);
}

/************************************************************************
 * Device interface
 */

static enum {
	RUN_HALTED = 0,
	RUN_FREE,
	RUN_TO_BREAKPOINT
} run_mode;

static u_int16_t run_breakpoint;

static void sim_close(void)
{
	if (memory) {
		free(memory);
		memory = NULL;
	}
}

static int sim_control(device_ctl_t action)
{
	switch (action) {
	case DEVICE_CTL_RESET:
		memset(sim_regs, 0, sizeof(sim_regs));
		sim_regs[MSP430_REG_PC] = MEM_GETW(0xfffe);
		break;

	case DEVICE_CTL_ERASE:
		memset(memory, 0xff, MEM_SIZE);
		return 0;

	case DEVICE_CTL_HALT:
		return 0;

	case DEVICE_CTL_STEP:
		return step_cpu();

	case DEVICE_CTL_RUN_BP:
		run_mode = RUN_TO_BREAKPOINT;
		return 0;

	case DEVICE_CTL_RUN:
		run_mode = RUN_FREE;
		return 0;
	}

	return -1;
}

static int sim_wait(void)
{
	if (run_mode != RUN_HALTED) {
		printf("\n");
		ctrlc_reset();

		for (;;) {
			if (run_mode == RUN_TO_BREAKPOINT &&
			    sim_regs[MSP430_REG_PC] == run_breakpoint)
				break;

			if (ctrlc_check()) {
				run_mode = RUN_HALTED;
				return 1;
			}

			if (step_cpu() < 0) {
				run_mode = RUN_HALTED;
				return -1;
			}
		}

		run_mode = RUN_HALTED;
	}

	return 0;
}

static int sim_breakpoint(u_int16_t addr)
{
	run_breakpoint = addr;
	return 0;
}

static int sim_getregs(u_int16_t *regs)
{
	memcpy(regs, sim_regs, sizeof(sim_regs));
	return 0;
}

static int sim_setregs(const u_int16_t *regs)
{
	memcpy(sim_regs, regs, sizeof(sim_regs));
	return -1;
}

static int sim_readmem(u_int16_t addr, u_int8_t *mem, int len)
{
	if (addr + len > MEM_SIZE)
		len = MEM_SIZE - addr;

	memcpy(mem, memory + addr, len);
	return 0;
}

static int sim_writemem(u_int16_t addr, const u_int8_t *mem, int len)
{
	if (addr + len > MEM_SIZE)
		len = MEM_SIZE - addr;

	memcpy(memory + addr, mem, len);
	return 0;
}

static const struct device sim_device = {
	.close		= sim_close,
	.control	= sim_control,
	.wait		= sim_wait,
	.breakpoint	= sim_breakpoint,
	.getregs	= sim_getregs,
	.setregs	= sim_setregs,
	.readmem	= sim_readmem,
	.writemem	= sim_writemem
};

const struct device *sim_open(void)
{
	memory = malloc(MEM_SIZE);
	if (!memory) {
		perror("sim: can't allocate memory");
		return NULL;
	}

	memset(memory, 0xff, MEM_SIZE);
	printf("Simulation started, 0x%x bytes of RAM\n", MEM_SIZE);
	return &sim_device;
}
