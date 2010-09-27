/* MSPDebug - debugging tool for the eZ430-RF2500
 * Copyright (C) 2009 Daniel Beer
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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <usb.h>

#define MSP_NUM_REGS		16

static void hexdump(int addr, const char *data, int len)
{
	int offset = 0;

	while (offset < len) {
		int i, j;

		/* Address label */
		printf("    %04x:", offset + addr);

		/* Hex portion */
		for (i = 0; i < 16 && offset + i < len; i++)
			printf(" %02x",
				((const unsigned char *)data)[offset + i]);
		for (j = i; j < 16; j++)
			printf("   ");

		/* Printable characters */
		printf(" |");
		for (j = 0; j < i; j++) {
			int c = ((const unsigned char *)data)[offset + j];

			printf("%c", (c >= 32 && c <= 126) ? c : '.');
		}
		for (; j < 16; j++)
			printf(" ");
		printf("|\n");

		offset += i;
	}
}

/**********************************************************************/
/* Disassembler
 */

/* Addressing modes.
 *
 * Addressing modes are not determined solely by the address mode bits
 * in an instruction. Rather, those bits specify one of four possible
 * modes (REGISTER, INDEXED, INDIRECT and INDIRECT_INC). Using some of
 * these modes in conjunction with special registers like PC or the
 * constant generator registers results in extra modes. For example, the
 * following code, written using INDIRECT_INC on PC:
 *
 *     MOV      @PC+, R5
 *     .word    0x5729
 *
 * can also be written as an instruction using IMMEDIATE addressing:
 *
 *     MOV      #0x5729, R5
 */
typedef enum {
	MSP430_AMODE_REGISTER           = 0x0,
	MSP430_AMODE_INDEXED            = 0x1,
	MSP430_AMODE_SYMBOLIC           = 0x81,
	MSP430_AMODE_ABSOLUTE           = 0x82,
	MSP430_AMODE_INDIRECT           = 0x2,
	MSP430_AMODE_INDIRECT_INC       = 0x3,
	MSP430_AMODE_IMMEDIATE          = 0x83
} msp430_amode_t;

/* MSP430 registers.
 *
 * These are divided into:
 *
 *     PC/R0:    program counter
 *     SP/R1:    stack pointer
 *     SR/R2:    status register/constant generator 1
 *     R3:       constant generator 2
 *     R4-R15:   general purpose registers
 */
typedef enum {
	MSP430_REG_PC           = 0,
	MSP430_REG_SP           = 1,
	MSP430_REG_SR           = 2,
	MSP430_REG_R3           = 3,
	MSP430_REG_R4           = 4,
	MSP430_REG_R5           = 5,
	MSP430_REG_R6           = 6,
	MSP430_REG_R7           = 7,
	MSP430_REG_R8           = 8,
	MSP430_REG_R9           = 9,
	MSP430_REG_R10          = 10,
	MSP430_REG_R11          = 11,
	MSP430_REG_R12          = 12,
	MSP430_REG_R13          = 13,
	MSP430_REG_R14          = 14,
	MSP430_REG_R15          = 15,
} msp430_reg_t;

/* Status register bits. */
#define MSP430_SR_V             0x0100
#define MSP430_SR_SCG1          0x0080
#define MSP430_SR_SCG0          0x0040
#define MSP430_SR_OSCOFF        0x0020
#define MSP430_SR_CPUOFF        0x0010
#define MSP430_SR_GIE           0x0008
#define MSP430_SR_N             0x0004
#define MSP430_SR_Z             0x0002
#define MSP430_SR_C             0x0001

/* MSP430 instruction formats.
 *
 * NOARG is not an actual instruction format recognised by the CPU.
 * It is used only for emulated instructions.
 */
typedef enum {
	MSP430_ITYPE_NOARG,
	MSP430_ITYPE_JUMP,
	MSP430_ITYPE_DOUBLE,
	MSP430_ITYPE_SINGLE
} msp430_itype_t;

/* MSP430 operations.
 *
 * Some of these are emulated instructions. Emulated instructions are
 * alternate mnemonics for combinations of some real opcodes with
 * common operand values. For example, the following real instruction:
 *
 *    MOV   #0, R8
 *
 * can be written as the following emulated instruction:
 *
 *    CLR   R8
 */
typedef enum {
	/* Single operand */
	MSP430_OP_RRC           = 0x1000,
	MSP430_OP_SWPB          = 0x1080,
	MSP430_OP_RRA           = 0x1100,
	MSP430_OP_SXT           = 0x1180,
	MSP430_OP_PUSH          = 0x1200,
	MSP430_OP_CALL          = 0x1280,
	MSP430_OP_RETI          = 0x1300,

	/* Jump */
	MSP430_OP_JNZ           = 0x2000,
	MSP430_OP_JZ            = 0x2400,
	MSP430_OP_JNC           = 0x2800,
	MSP430_OP_JC            = 0x2C00,
	MSP430_OP_JN            = 0x3000,
	MSP430_OP_JGE           = 0x3400,
	MSP430_OP_JL            = 0x3800,
	MSP430_OP_JMP           = 0x3C00,

	/* Double operand */
	MSP430_OP_MOV           = 0x4000,
	MSP430_OP_ADD           = 0x5000,
	MSP430_OP_ADDC          = 0x6000,
	MSP430_OP_SUBC          = 0x7000,
	MSP430_OP_SUB           = 0x8000,
	MSP430_OP_CMP           = 0x9000,
	MSP430_OP_DADD          = 0xA000,
	MSP430_OP_BIT           = 0xB000,
	MSP430_OP_BIC           = 0xC000,
	MSP430_OP_BIS           = 0xD000,
	MSP430_OP_XOR           = 0xE000,
	MSP430_OP_AND           = 0xF000,

	/* Emulated instructions */
	MSP430_OP_ADC           = 0x10000,
	MSP430_OP_BR            = 0x10001,
	MSP430_OP_CLR           = 0x10002,
	MSP430_OP_CLRC          = 0x10003,
	MSP430_OP_CLRN          = 0x10004,
	MSP430_OP_CLRZ          = 0x10005,
	MSP430_OP_DADC          = 0x10006,
	MSP430_OP_DEC           = 0x10007,
	MSP430_OP_DECD          = 0x10008,
	MSP430_OP_DINT          = 0x10009,
	MSP430_OP_EINT          = 0x1000A,
	MSP430_OP_INC           = 0x1000B,
	MSP430_OP_INCD          = 0x1000C,
	MSP430_OP_INV           = 0x1000D,
	MSP430_OP_NOP           = 0x1000E,
	MSP430_OP_POP           = 0x1000F,
	MSP430_OP_RET           = 0x10010,
	MSP430_OP_RLA           = 0x10011,
	MSP430_OP_RLC           = 0x10012,
	MSP430_OP_SBC           = 0x10013,
	MSP430_OP_SETC          = 0x10014,
	MSP430_OP_SETN          = 0x10015,
	MSP430_OP_SETZ          = 0x10016,
	MSP430_OP_TST           = 0x10017
} msp430_op_t;

#define MSP430_OP_IS_JUMP(o) ((o) >= MSP430_OP_JNZ && (o) <= MSP430_OP_JMP)

/* This represents a decoded instruction. All decoded addresses are
 * absolute or register-indexed, depending on the addressing mode.
 *
 * For jump instructions, the target address is stored in dst_operand.
 */
struct msp430_instruction {
	u_int16_t               offset;
	int                     len;

	msp430_op_t             op;
	msp430_itype_t          itype;
	int                     is_byte_op;

	msp430_amode_t          src_mode;
	u_int16_t               src_addr;
	msp430_reg_t            src_reg;

	msp430_amode_t          dst_mode;
	u_int16_t               dst_addr;
	msp430_reg_t            dst_reg;
};

/* Decode a single-operand instruction.
 *
 * Returns the number of bytes consumed in decoding, or -1 if the a
 * valid single-operand instruction could not be found.
 */
static int decode_single(u_int8_t *code, u_int16_t offset, u_int16_t size,
			 struct msp430_instruction *insn)
{
	u_int16_t op = (code[1] << 8) | code[0];
	int need_arg = 0;

	insn->op = op & 0xff80;
	insn->is_byte_op = op & 0x0400;

	insn->dst_mode = (op >> 4) & 0x3;
	insn->dst_reg = op & 0xf;

	switch (insn->dst_mode) {
	case MSP430_AMODE_REGISTER: break;

	case MSP430_AMODE_INDEXED:
		need_arg = 1;
		if (insn->dst_reg == MSP430_REG_PC) {
			insn->dst_addr = offset + 2;
			insn->dst_mode = MSP430_AMODE_SYMBOLIC;
		} else if (insn->dst_reg == MSP430_REG_SR)
			insn->dst_mode = MSP430_AMODE_ABSOLUTE;
		break;

	case MSP430_AMODE_INDIRECT: break;

	case MSP430_AMODE_INDIRECT_INC:
		if (insn->dst_reg == MSP430_REG_PC) {
			insn->dst_mode = MSP430_AMODE_IMMEDIATE;
			need_arg = 1;
		}
		break;

	default: break;
	}

	if (need_arg) {
		if (size < 4)
			return -1;

		insn->dst_addr += (code[3] << 8) | code[2];
		return 4;
	}

	return 2;
}

/* Decode a double-operand instruction.
 *
 * Returns the number of bytes consumed or -1 if a valid instruction
 * could not be found.
 */
static int decode_double(u_int8_t *code, u_int16_t offset, u_int16_t size,
			 struct msp430_instruction *insn)
{
	u_int16_t op = (code[1] << 8) | code[0];
	int need_src = 0;
	int need_dst = 0;
	int ret = 2;

	insn->op = op & 0xf000;
	insn->is_byte_op = op & 0x0040;

	insn->src_mode = (op >> 4) & 0x3;
	insn->src_reg = (op >> 8) & 0xf;

	insn->dst_mode = (op >> 7) & 0x1;
	insn->dst_reg = op & 0xf;

	switch (insn->dst_mode) {
	case MSP430_AMODE_REGISTER: break;
	case MSP430_AMODE_INDEXED:
		need_dst = 1;

		if (insn->dst_reg == MSP430_REG_PC) {
			insn->dst_mode = MSP430_AMODE_SYMBOLIC;
			insn->dst_addr = offset + 2;
		} else if (insn->dst_reg == MSP430_REG_SR)
			insn->dst_mode = MSP430_AMODE_ABSOLUTE;
		break;

	default: break;
	}

	switch (insn->src_mode) {
	case MSP430_AMODE_REGISTER: break;
	case MSP430_AMODE_INDEXED:
		need_src = 1;

		if (insn->src_reg == MSP430_REG_PC) {
			insn->src_mode = MSP430_AMODE_SYMBOLIC;
			insn->dst_addr = offset + 2;
		} else if (insn->src_reg == MSP430_REG_SR)
			insn->src_mode = MSP430_AMODE_ABSOLUTE;
		else if (insn->src_reg == MSP430_REG_R3)
			need_src = 0;
		break;

	case MSP430_AMODE_INDIRECT: break;

	case MSP430_AMODE_INDIRECT_INC:
		if (insn->src_reg == MSP430_REG_PC) {
			insn->src_mode = MSP430_AMODE_IMMEDIATE;
			need_src = 1;
		}
		break;

	default: break;
	}

	offset += 2;
	code += 2;
	size -= 2;

	if (need_src) {
		if (size < 2)
			return -1;

		insn->src_addr += (code[1] << 8) | code[0];
		offset += 2;
		code += 2;
		size -= 2;
		ret += 2;
	}

	if (need_dst) {
		if (size < 2)
			return -1;

		insn->dst_addr += (code[1] << 8) | code[0];
		ret += 2;
	}

	return ret;
}

/* Decode a jump instruction.
 *
 * All jump instructions are one word in length, so this function
 * always returns 2 (to indicate the consumption of 2 bytes).
 */
static int decode_jump(u_int8_t *code, u_int16_t offset, u_int16_t len,
		       struct msp430_instruction *insn)
{
	u_int16_t op = (code[1] << 8) | code[0];
	int tgtrel = op & 0x3ff;

	if (tgtrel & 0x200)
		tgtrel -= 0x400;

	insn->op = op & 0xfc00;
	insn->dst_addr = offset + 2 + tgtrel * 2;
	insn->dst_mode = MSP430_AMODE_SYMBOLIC;
	insn->dst_reg = MSP430_REG_PC;

	return 2;
}

/* Take a decoded instruction and replace certain addressing modes of
 * the constant generator registers with their corresponding immediate
 * values.
 */
static void find_cgens(struct msp430_instruction *insn)
{
	if (insn->src_reg == MSP430_REG_SR) {
		if (insn->src_mode == MSP430_AMODE_INDIRECT) {
			insn->src_mode = MSP430_AMODE_IMMEDIATE;
			insn->src_addr = 4;
		} else if (insn->src_mode == MSP430_AMODE_INDIRECT_INC) {
			insn->src_mode = MSP430_AMODE_IMMEDIATE;
			insn->src_addr = 8;
		}
	} else if (insn->src_reg == MSP430_REG_R3) {
		if (insn->src_mode == MSP430_AMODE_REGISTER)
			insn->src_addr = 0;
		else if (insn->src_mode == MSP430_AMODE_INDEXED)
			insn->src_addr = 1;
		else if (insn->src_mode == MSP430_AMODE_INDIRECT)
			insn->src_addr = 2;
		else if (insn->src_mode == MSP430_AMODE_INDIRECT_INC)
			insn->src_addr = 0xffff;

		insn->src_mode = MSP430_AMODE_IMMEDIATE;
	}
}

/* Recognise special cases of real instructions and translate them to
 * emulated instructions.
 */
static void find_emulated_ops(struct msp430_instruction *insn)
{
	switch (insn->op) {
	case MSP430_OP_ADD:
		if (insn->src_mode == MSP430_AMODE_IMMEDIATE) {
			if (insn->src_addr == 1) {
				insn->op = MSP430_OP_INC;
				insn->itype = MSP430_ITYPE_SINGLE;
			} else if (insn->src_addr == 2) {
				insn->op = MSP430_OP_INCD;
				insn->itype = MSP430_ITYPE_SINGLE;
			}
		} else if (insn->dst_mode == insn->src_mode &&
			   insn->dst_reg == insn->src_reg &&
			   insn->dst_addr == insn->src_addr) {
			insn->op = MSP430_OP_RLA;
			insn->itype = MSP430_ITYPE_SINGLE;
		}
		break;

	case MSP430_OP_ADDC:
		if (insn->src_mode == MSP430_AMODE_IMMEDIATE &&
		    !insn->src_addr) {
			insn->op = MSP430_OP_ADC;
			insn->itype = MSP430_ITYPE_SINGLE;
		} else if (insn->dst_mode == insn->src_mode &&
			   insn->dst_reg == insn->src_reg &&
			   insn->dst_addr == insn->src_addr) {
			insn->op = MSP430_OP_RLC;
			insn->itype = MSP430_ITYPE_SINGLE;
		}
		break;

	case MSP430_OP_BIC:
		if (insn->dst_mode == MSP430_AMODE_REGISTER &&
		    insn->dst_reg == MSP430_REG_SR &&
		    insn->src_mode == MSP430_AMODE_IMMEDIATE) {
			if (insn->src_addr == 1) {
				insn->op = MSP430_OP_CLRC;
				insn->itype = MSP430_ITYPE_NOARG;
			} else if (insn->src_addr == 4) {
				insn->op = MSP430_OP_CLRN;
				insn->itype = MSP430_ITYPE_NOARG;
			} else if (insn->src_addr == 2) {
				insn->op = MSP430_OP_CLRZ;
				insn->itype = MSP430_ITYPE_NOARG;
			} else if (insn->src_addr == 8) {
				insn->op = MSP430_OP_DINT;
				insn->itype = MSP430_ITYPE_NOARG;
			}
		}
		break;

	case MSP430_OP_BIS:
		if (insn->dst_mode == MSP430_AMODE_REGISTER &&
		    insn->dst_reg == MSP430_REG_SR &&
		    insn->src_mode == MSP430_AMODE_IMMEDIATE) {
			if (insn->src_addr == 1) {
				insn->op = MSP430_OP_SETC;
				insn->itype = MSP430_ITYPE_NOARG;
			} else if (insn->src_addr == 4) {
				insn->op = MSP430_OP_SETN;
				insn->itype = MSP430_ITYPE_NOARG;
			} else if (insn->src_addr == 2) {
				insn->op = MSP430_OP_SETZ;
				insn->itype = MSP430_ITYPE_NOARG;
			} else if (insn->src_addr == 8) {
				insn->op = MSP430_OP_EINT;
				insn->itype = MSP430_ITYPE_NOARG;
			}
		}
		break;

	case MSP430_OP_CMP:
		if (insn->src_mode == MSP430_AMODE_IMMEDIATE &&
		    !insn->src_addr) {
			insn->op = MSP430_OP_TST;
			insn->itype = MSP430_ITYPE_SINGLE;
		}
		break;

	case MSP430_OP_DADD:
		if (insn->src_mode == MSP430_AMODE_IMMEDIATE &&
		    !insn->src_addr) {
			insn->op = MSP430_OP_DADC;
			insn->itype = MSP430_ITYPE_SINGLE;
		}
		break;

	case MSP430_OP_MOV:
		if (insn->src_mode == MSP430_AMODE_INDIRECT_INC &&
		    insn->src_reg == MSP430_REG_SP) {
			if (insn->dst_mode == MSP430_AMODE_REGISTER &&
			    insn->dst_reg == MSP430_REG_PC) {
				insn->op = MSP430_OP_RET;
				insn->itype = MSP430_ITYPE_NOARG;
			} else {
				insn->op = MSP430_OP_POP;
				insn->itype = MSP430_ITYPE_SINGLE;
			}
		} else if (insn->dst_mode == MSP430_AMODE_REGISTER &&
			   insn->dst_reg == MSP430_REG_PC) {
			insn->op = MSP430_OP_BR;
			insn->itype = MSP430_ITYPE_SINGLE;
			insn->dst_mode = insn->src_mode;
			insn->dst_reg = insn->src_reg;
			insn->dst_addr = insn->src_addr;
		} else if (insn->src_mode == MSP430_AMODE_IMMEDIATE &&
			   !insn->src_addr) {
			if (insn->dst_mode == MSP430_AMODE_REGISTER &&
			    insn->dst_reg == MSP430_REG_R3) {
				insn->op = MSP430_OP_NOP;
				insn->itype = MSP430_ITYPE_NOARG;
			} else {
				insn->op = MSP430_OP_CLR;
				insn->itype = MSP430_ITYPE_SINGLE;
			}
		}
		break;

	case MSP430_OP_SUB:
		if (insn->dst_mode == MSP430_AMODE_IMMEDIATE) {
			if (insn->dst_addr == 1) {
				insn->op = MSP430_OP_DEC;
				insn->itype = MSP430_ITYPE_SINGLE;
			} else if (insn->dst_addr == 2) {
				insn->op = MSP430_OP_DECD;
				insn->itype = MSP430_ITYPE_SINGLE;
			}
		}
		break;

	case MSP430_OP_SUBC:
		if (insn->src_mode == MSP430_AMODE_IMMEDIATE &&
		    !insn->src_addr) {
			insn->op = MSP430_OP_SBC;
			insn->itype = MSP430_ITYPE_SINGLE;
		}
		break;

	case MSP430_OP_XOR:
		if (insn->src_mode == MSP430_AMODE_IMMEDIATE &&
		    insn->src_addr == 0xffff) {
			insn->op = MSP430_OP_INV;
			insn->itype = MSP430_ITYPE_SINGLE;
		}
		break;

	default: break;
	}
}

/* Decode a single instruction.
 *
 * Returns the number of bytes consumed, or -1 if an error occured.
 *
 * The caller needs to pass a pointer to the bytes to be decoded, the
 * virtual offset of those bytes, and the maximum number available. If
 * successful, the decoded instruction is written into the structure
 * pointed to by insn.
 */
static int decode(u_int8_t *code, u_int16_t offset, u_int16_t len,
		  struct msp430_instruction *insn)
{
	u_int16_t op;
	int ret;

	memset(insn, 0, sizeof(*insn));

	if (len < 2)
		return -1;

	insn->offset = offset;
	op = (code[1] << 8) | code[0];

	if ((op & 0xf000) == 0x1000)
		insn->itype = MSP430_ITYPE_SINGLE;
	else if ((op & 0xff00) >= 0x2000 &&
		 (op & 0xff00) < 0x4000)
		insn->itype = MSP430_ITYPE_JUMP;
	else if ((op & 0xf000) >= 0x4000)
		insn->itype = MSP430_ITYPE_DOUBLE;
	else
		return -1;

	switch (insn->itype) {
	case MSP430_ITYPE_SINGLE:
		ret = decode_single(code, offset, len, insn);
		break;

	case MSP430_ITYPE_DOUBLE:
		ret = decode_double(code, offset, len, insn);
		break;

	case MSP430_ITYPE_JUMP:
		ret = decode_jump(code, offset, len, insn);
		break;

	default: break;
	}

	find_cgens(insn);
	find_emulated_ops(insn);

	insn->len = ret;
	return ret;
}

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* Return the mnemonic for an operation, if possible.
 *
 * If the argument is not a valid operation, this function returns the
 * string "???".
 */
static const char *msp_op_name(msp430_op_t op)
{
	static const struct {
		msp430_op_t     op;
		const char      *mnemonic;
	} ops[] = {
		/* Single operand */
		{MSP430_OP_RRC,         "RRC"},
		{MSP430_OP_RRC,         "SWPB"},
		{MSP430_OP_RRA,         "RRA"},
		{MSP430_OP_SXT,         "SXT"},
		{MSP430_OP_PUSH,        "PUSH"},
		{MSP430_OP_CALL,        "CALL"},
		{MSP430_OP_RETI,        "RETI"},

		/* Jump */
		{MSP430_OP_JNZ,         "JNZ"},
		{MSP430_OP_JZ,          "JZ"},
		{MSP430_OP_JNC,         "JNC"},
		{MSP430_OP_JC,          "JC"},
		{MSP430_OP_JN,          "JN"},
		{MSP430_OP_JL,          "JL"},
		{MSP430_OP_JGE,         "JGE"},
		{MSP430_OP_JMP,         "JMP"},

		/* Double operand */
		{MSP430_OP_MOV,         "MOV"},
		{MSP430_OP_ADD,         "ADD"},
		{MSP430_OP_ADDC,        "ADDC"},
		{MSP430_OP_SUBC,        "SUBC"},
		{MSP430_OP_SUB,         "SUB"},
		{MSP430_OP_CMP,         "CMP"},
		{MSP430_OP_DADD,        "DADD"},
		{MSP430_OP_BIT,         "BIT"},
		{MSP430_OP_BIC,         "BIC"},
		{MSP430_OP_BIS,         "BIS"},
		{MSP430_OP_XOR,         "XOR"},
		{MSP430_OP_AND,         "AND"},

		/* Emulated instructions */
		{MSP430_OP_ADC,         "ADC"},
		{MSP430_OP_BR,          "BR"},
		{MSP430_OP_CLR,         "CLR"},
		{MSP430_OP_CLRC,        "CLRC"},
		{MSP430_OP_CLRN,        "CLRN"},
		{MSP430_OP_CLRZ,        "CLRZ"},
		{MSP430_OP_DADC,        "DADC"},
		{MSP430_OP_DEC,         "DEC"},
		{MSP430_OP_DECD,        "DECD"},
		{MSP430_OP_DINT,        "DINT"},
		{MSP430_OP_EINT,        "EINT"},
		{MSP430_OP_INC,         "INC"},
		{MSP430_OP_INCD,        "INCD"},
		{MSP430_OP_INV,         "INV"},
		{MSP430_OP_NOP,         "NOP"},
		{MSP430_OP_POP,         "POP"},
		{MSP430_OP_RET,         "RET"},
		{MSP430_OP_RLA,         "RLA"},
		{MSP430_OP_RLC,         "RLC"},
		{MSP430_OP_SBC,         "SBC"},
		{MSP430_OP_SETC,        "SETC"},
		{MSP430_OP_SETN,        "SETN"},
		{MSP430_OP_SETZ,        "SETZ"},
		{MSP430_OP_TST,         "TST"}
	};
	int i;

	for (i = 0; i < ARRAY_LEN(ops); i++)
		if (op == ops[i].op)
			return ops[i].mnemonic;

	return "???";
}

static const char *const msp430_reg_names[] = {
	"PC",  "SP",  "SR",  "R3",
	"R4",  "R5",  "R6",  "R7",
	"R8",  "R9",  "R10", "R11",
	"R12", "R13", "R14", "R15"
};

/* Given an operands addressing mode, value and associated register,
 * print the canonical representation of it to stdout.
 *
 * Returns the number of characters printed.
 */
static int format_operand(char *buf, int max_len,
			  msp430_amode_t amode, u_int16_t addr,
			  msp430_reg_t reg)
{
	assert (reg >= 0 && reg < ARRAY_LEN(msp430_reg_names));

	switch (amode) {
	case MSP430_AMODE_REGISTER:
		return snprintf(buf, max_len, "%s", msp430_reg_names[reg]);

	case MSP430_AMODE_INDEXED:
		return snprintf(buf, max_len, "%d(%s)", (int16_t)addr,
				msp430_reg_names[reg]);

	case MSP430_AMODE_SYMBOLIC:
		return snprintf(buf, max_len, "0x%04x", addr);

	case MSP430_AMODE_ABSOLUTE:
		return snprintf(buf, max_len, "&0x%04x", addr);

	case MSP430_AMODE_INDIRECT:
		return snprintf(buf, max_len, "@%s", msp430_reg_names[reg]);

	case MSP430_AMODE_INDIRECT_INC:
		return snprintf(buf, max_len, "@%s+", msp430_reg_names[reg]);

	case MSP430_AMODE_IMMEDIATE:
		return snprintf(buf, max_len, "#%d", (int16_t)addr);
	}

	return snprintf(buf, max_len, "???");
}

/* Write assembly language for the instruction to this buffer */
static int format_instruction(char *buf, int max_len,
			      const struct msp430_instruction *insn)
{
	int count = 0;

	/* Opcode mnemonic */
	count = snprintf(buf, max_len, "%s", msp_op_name(insn->op));
	if (insn->is_byte_op)
		count += snprintf(buf + count, max_len - count, ".B");
	while (count < 8 && count + 1 < max_len)
		buf[count++] = ' ';

	/* Source operand */
	if (insn->itype == MSP430_ITYPE_DOUBLE) {
		count += format_operand(buf + count,
					max_len - count,
					insn->src_mode,
					insn->src_addr,
					insn->src_reg);

		if (count + 1 < max_len)
			buf[count++] = ',';
		while (count < 20 && count + 1 < max_len)
			buf[count++] = ' ';
	}

	/* Destination operand */
	if (insn->itype != MSP430_ITYPE_NOARG) {
		if ((insn->op == MSP430_OP_CALL ||
		     insn->op == MSP430_OP_BR) &&
		    insn->dst_mode == MSP430_AMODE_IMMEDIATE)
			count += snprintf(buf + count, max_len - count,
					  "#0x%04x", insn->dst_addr);
		else
			count += format_operand(buf + count,
						max_len - count,
						insn->dst_mode,
						insn->dst_addr,
						insn->dst_reg);
	}

	buf[count] = 0;
	return count;
}

/*********************************************************************
 * Checksum calculation
 */

static u_int16_t code_left[65536];

/* Initialise the code table. The code table is a function which takes
 * us from one checksum position code to the next.
 */

static void init_codes(void)
{
	int i;

	for (i = 0; i < 65536; i++) {
		u_int16_t right = i << 1;

		if (i & 0x8000)
			right ^= 0x0811;

		code_left[right] = i;
	}
}

/* Calculate the checksum over the given payload and return it. This checksum
 * needs to be stored in little-endian format at the end of the payload.
 */

static u_int16_t calc_checksum(const char *data, int len)
{
	int i;
	u_int16_t cksum = 0xffff;
	u_int16_t code = 0x8408;

	for (i = len * 8; i; i--)
		cksum = code_left[cksum];

	for (i = len - 1; i >= 0; i--) {
		int j;
		u_int8_t c = data[i];

		for (j = 0; j < 8; j++) {
			if (c & 0x80)
				cksum ^= code;
			code = code_left[code];
			c <<= 1;
		}
	}

	return cksum ^ 0xffff;
}

/*********************************************************************
 * USB transport
 *
 * These functions handle the details of slicing data over USB
 * transfers. The interface presented is a continuous byte stream with
 * no slicing codes.
 *
 * Writes are unbuffered -- a single write translates to at least
 * one transfer.
 */

#define USB_FET_VENDOR			0x0451
#define USB_FET_PRODUCT			0xf432
#define USB_FET_INTERFACE_CLASS		3

#define USB_FET_IN_EP			0x81
#define USB_FET_OUT_EP			0x01

static int usbtr_int_number;
static struct usb_dev_handle *usbtr_handle;

static int usbtr_open_interface(struct usb_device *dev, int ino)
{
	printf("Trying to open interface %d on %s\n", ino, dev->filename);

	usbtr_int_number = ino;

	usbtr_handle = usb_open(dev);
	if (!usbtr_handle) {
		perror("usbtr_open_interface: can't open device");
		return -1;
	}

	if (usb_detach_kernel_driver_np(usbtr_handle, usbtr_int_number) < 0)
		perror("usbtr_open_interface: warning: can't "
			"detach kernel driver");

	if (usb_claim_interface(usbtr_handle, usbtr_int_number) < 0) {
		perror("usbtr_open_interface: can't claim interface");
		usb_close(usbtr_handle);
		return -1;
	}

	return 0;
}

static int usbtr_open_device(struct usb_device *dev)
{
	struct usb_config_descriptor *c = &dev->config[0];
	int i;

	for (i = 0; i < c->bNumInterfaces; i++) {
		struct usb_interface *intf = &c->interface[i];
		struct usb_interface_descriptor *desc = &intf->altsetting[0];

		if (desc->bInterfaceClass == USB_FET_INTERFACE_CLASS &&
		    !usbtr_open_interface(dev, desc->bInterfaceNumber))
			return 0;
	}

	return -1;
}

static int usbtr_open(void)
{
	struct usb_bus *bus;

	usb_init();
	usb_find_busses();
	usb_find_devices();

	for (bus = usb_get_busses(); bus; bus = bus->next) {
		struct usb_device *dev;

		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->descriptor.idVendor == USB_FET_VENDOR &&
			    dev->descriptor.idProduct == USB_FET_PRODUCT &&
			    !usbtr_open_device(dev))
				return 0;
		}
	}

	fprintf(stderr, "usbtr_open: no devices could be found\n");
	return -1;
}

static int usbtr_send(const char *data, int len)
{
	while (len) {
		char pbuf[256];
		int plen = len > 255 ? 255 : len;
		int txlen = plen + 1;

		memcpy(pbuf + 1, data, plen);

		/* This padding is needed to work around an apparent bug in
		 * the RF2500 FET. Without this, the device hangs.
		 */
		if (txlen > 32 && (txlen & 0x3f))
			while (txlen < 255 && (txlen & 0x3f))
				pbuf[txlen++] = 0xff;
		else if (txlen > 16 && (txlen & 0xf))
			while (txlen < 255 && (txlen & 0xf) != 1)
				pbuf[txlen++] = 0xff;
		pbuf[0] = txlen - 1;

#ifdef DEBUG_USBTR
		puts("USB transfer out:");
		hexdump(0, pbuf, txlen);
#endif
		if (usb_bulk_write(usbtr_handle, USB_FET_OUT_EP,
			pbuf, txlen, 10000) < 0) {
			perror("usbtr_send");
			return -1;
		}

		data += plen;
		len -= plen;
	}

	return 0;
}

static char usbtr_buf[64];
static int usbtr_len;
static int usbtr_offset;

static void usbtr_flush(void)
{
	char buf[64];

	while (usb_bulk_read(usbtr_handle, USB_FET_IN_EP,
			buf, sizeof(buf), 100) >= 0);
}

static int usbtr_recv(char *databuf, int max_len)
{
	int rlen;

	if (usbtr_offset >= usbtr_len) {
		if (usb_bulk_read(usbtr_handle, USB_FET_IN_EP,
				usbtr_buf, sizeof(usbtr_buf), 10000) < 0) {
			perror("usbtr_recv");
			return -1;
		}

#ifdef DEBUG_USBTR
		puts("USB transfer in:");
		hexdump(0, usbtr_buf, 64);
#endif

		usbtr_len = usbtr_buf[1] + 2;
		if (usbtr_len > sizeof(usbtr_buf))
			usbtr_len = sizeof(usbtr_buf);
		usbtr_offset = 2;
	}

	rlen = usbtr_len - usbtr_offset;
	if (rlen > max_len)
		rlen = max_len;
	memcpy(databuf, usbtr_buf + usbtr_offset, rlen);
	usbtr_offset += rlen;

	return rlen;
}

static void usbtr_close(void)
{
	usb_release_interface(usbtr_handle, usbtr_int_number);
	usb_close(usbtr_handle);
}

/*********************************************************************
 * FET packet transfer. This level of the interface deals in packets
 * send to/from the device.
 */

/* This is a type of data transfer which appears to be unique to
 * the RF2500. Blocks of data are sent to an internal buffer. Each
 * block is prefixed with a buffer offset and a payload length.
 *
 * No checksums are included.
 */
static int fet_send_data(const char *data, int len)
{
	int offset = 0;

	while (len) {
		char pbuf[63];
		int plen = len > 59 ? 59 : len;

		pbuf[0] = 0x83;
		pbuf[1] = offset & 0xff;
		pbuf[2] = offset >> 8;
		pbuf[3] = plen;
		memcpy(pbuf + 4, data, plen);
		if (usbtr_send(pbuf, plen + 4) < 0)
			return -1;

		data += plen;
		len -= plen;
		offset += plen;
	}

	return 0;
}

static char fet_buf[65538];
static int fet_len;

#define BUFFER_BYTE(b, x) ((int)((u_int8_t *)(b))[x])
#define BUFFER_WORD(b, x) ((BUFFER_BYTE(b, x + 1) << 8) | BUFFER_BYTE(b, x))

static const char *fet_recv_packet(int *pktlen)
{
	int plen = BUFFER_WORD(fet_buf, 0);

	/* If there's a packet still here from last time, get rid of it */
	if (fet_len >= plen + 2) {
		memmove(fet_buf, fet_buf + plen + 2, fet_len - plen - 2);
		fet_len -= plen + 2;
	}

	/* Keep adding data to the buffer until we have a complete packet */
	for (;;) {
		int len;

		plen = BUFFER_WORD(fet_buf, 0);
		if (fet_len >= plen + 2) {
			u_int16_t c = calc_checksum(fet_buf + 2, plen - 2);
			u_int16_t r = BUFFER_WORD(fet_buf, plen);

			if (pktlen)
				*pktlen = plen - 2;

			if (c != r) {
				fprintf(stderr, "fet_fecv_packet: checksum "
					"error (calc %04x, recv %04x)\n",
					c, r);
				return NULL;
			}

			return fet_buf + 2;
		}

		len = usbtr_recv(fet_buf + fet_len, sizeof(fet_buf) - fet_len);
		if (len < 0)
			return NULL;
		fet_len += len;
	}

	return NULL;
}

static int fet_send_command(const char *data, int len)
{
	char datapkt[256];
	char buf[256];
	u_int16_t cksum = calc_checksum(data, len);
	int i = 0;
	int j;

	assert (len + 4 <= sizeof(buf));
	assert (len + 2 <= sizeof(datapkt));

	memcpy(datapkt, data, len);
	datapkt[len++] = cksum & 0xff;
	datapkt[len++] = cksum >> 8;

	buf[i++] = 0x7e;
	for (j = 0; j < len; j++) {
		char c = datapkt[j];

		if (c == 0x7e || c == 0x7d) {
			buf[i++] = 0x7d;
			c ^= 0x20;
		}

		buf[i++] = c;
	}
	buf[i++] = 0x7e;

	assert (i < sizeof(buf));

	return usbtr_send(buf, i);
}

static const char *fet_send_recv(const char *data, int len, int *recvlen)
{
	const char *buf;

	if (fet_send_command(data, len) < 0)
		return NULL;

	buf = fet_recv_packet(recvlen);
	if (!buf)
		return NULL;

	if (data[0] != buf[0]) {
		fprintf(stderr, "fet_send_recv: reply type mismatch\n");
		return NULL;
	}

	return buf;
}

/**********************************************************************
 * MSP430 high-level control functions
 */

static int msp_startup(int sbw, int vcc_mv)
{
        static char config[12] = {
		0x05, 0x02, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

        static char vcc[8] = {
		0x06, 0x02, 0x01, 0x00, 0xff, 0xff, 0x00, 0x00
	};

	/* open */
	if (!fet_send_recv("\x01\x01", 2, NULL)) {
		fprintf(stderr, "msp_startup: open failed\n");
		return -1;
	}

	/* init */
	if (!fet_send_recv("\x27\x02\x01\x00\x04\x00\x00\x00\x00", 8, NULL)) {
		fprintf(stderr, "msp_startup: init failed\n");
		return -1;
	}

	/* configure: Spy-Bi-Wire or JTAG */
	config[8] = sbw ? 1 : 0;
	if (!fet_send_recv(config, 12, NULL)) {
		fprintf(stderr, "msp_startup: configure failed\n");
		return -1;
	}

	/* I don't know what this is. It's RF2500-specific. It may have
	 * something to do with flash -- 0x1d is sent before an erase.
	 */
	if (!fet_send_recv("\x1e\x01", 2, NULL)) {
		fprintf(stderr, "msp_startup: command 0x1e failed\n");
		return -1;
	}

	/* set VCC */
	vcc[4] = vcc_mv & 0xff;
	vcc[5] = vcc_mv >> 8;
	if (!fet_send_recv(vcc, 8, NULL)) {
		fprintf(stderr, "msp_startup: set VCC failed\n");
		return -1;
	}

	/* I don't know what this is, but it appears to halt the MSP. Without
	 * it, memory reads return garbage. This is RF2500-specific.
	 */
	if (!fet_send_recv("\x28\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			   12, NULL)) {
		fprintf(stderr, "msp_startup: command 0x28 failed\n");
		return -1;
	}

	/* Who knows what this is. Without it, register reads don't work.
	 * This is RF2500-specific.
	 */
	{
		static char data[] = {
			0x00, 0x80, 0xff, 0xff, 0x00, 0x00, 0x00, 0x10,
			0xff, 0x10, 0x40, 0x00, 0x00, 0x02, 0xff, 0x05,
			0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
			0x01, 0x00, 0xd7, 0x60, 0x00, 0x00, 0x00, 0x00,
			0x08, 0x07, 0x10, 0x0e, 0xc4, 0x09, 0x70, 0x17,
			0x58, 0x1b, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x33, 0x0f, 0x1f, 0x0f,
			0xff, 0xff,
		};

		if (fet_send_data(data, sizeof(data)) < 0 ||
		    !fet_send_recv("\x29\x02\x04\x00\x00\x00\x00\x00"
				   "\x39\x00\x00\x00\x31\x00\x00\x00"
			           "\x4a\x00\x00\x00", 20, NULL)) {
			fprintf(stderr, "msp_startup: command 0x29 failed\n");
			return -1;
		}
	}

	printf("FET initialized: %s (VCC = %d mV)\n",
		sbw ? "Spy-Bi-Wire" : "JTAG", vcc_mv);
	return 0;
}

#define MSP_RESET_PUC	0x01
#define MSP_RESET_RST	0x02
#define MSP_RESET_VCC	0x04
#define MSP_RESET_ALL	0x07

static int msp_reset(int type, int halt)
{
	static char reset[] = {
		0x07, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	reset[4] = type;
	if (halt) {
		reset[8] = 0;
		reset[12] = 0;
	} else {
		reset[8] = 1;
		reset[12] = 1;
	}

	if (!fet_send_recv(reset, 16, NULL)) {
		fprintf(stderr, "msp_reset: reset failed\n");
		return -1;
	}

	return 0;
}

static int msp_shutdown(void)
{
	if (!fet_send_recv("\x02\x02\x01\x00", 4, NULL)) {
		fprintf(stderr, "msp_close: close command failed\n");
		return -1;
	}

	return 0;
}

static int msp_get_context(u_int16_t *regs)
{
	int len;
	int i;
	const char *buf;

	buf = fet_send_recv("\x08\x01", 2, &len);
	if (len < 72) {
		fprintf(stderr, "msp_get_context: short reply (%d bytes)\n",
			len);
		return -1;
	}

	for (i = 0; i < MSP_NUM_REGS; i++)
		regs[i] = BUFFER_WORD(buf, i * 4 + 8);

	return 0;
}

static int msp_set_context(u_int16_t *regs)
{
	char buf[MSP_NUM_REGS * 4];
	int i;

	memset(buf, 0, sizeof(buf));

	for (i = 0; i < MSP_NUM_REGS; i++) {
		buf[i * 4] = regs[i] & 0xff;
		buf[i * 4 + 1] = regs[i] >> 8;
	}

	if (fet_send_data(buf, sizeof(buf)) < 0 ||
	    !fet_send_recv("\x09\x02\x02\x00\xff\xff\x00\x00"
			   "\x40\x00\x00\x00", 12, NULL)) {
		fprintf(stderr, "msp_set_context: context set failed\n");
		return -1;
	}

	return 0;
}

static int msp_read_mem(u_int16_t addr, char *buffer, int count)
{
	while (count) {
		int plen = count > 128 ? 128 : count;
		const char *buf;
		int len;

		static char readmem[] = {
			0x0d, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		};

		readmem[4] = addr & 0xff;
		readmem[5] = addr >> 8;
		readmem[8] = plen;

		buf = fet_send_recv(readmem, 12, &len);
		if (!buf) {
			fprintf(stderr, "msp_read_mem: failed to read "
				"from 0x%04x\n", addr);
			return -1;
		}

		if (len < plen + 8) {
			fprintf(stderr, "msp_read_mem: short read "
				"(%d bytes)\n", len);
			return -1;
		}

		memcpy(buffer, buf + 8, plen);
		buffer += plen;
		count -= plen;
		addr += plen;
	}

	return 0;
}

static int msp_write_mem(u_int16_t addr, char *buffer, int count)
{
	while (count) {
		int plen = count > 128 ? 128 : count;

		static char writemem[] = {
			0x0e, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		};

		writemem[4] = addr & 0xff;
		writemem[5] = addr >> 8;
		writemem[8] = plen;

		if (fet_send_data(buffer, plen) < 0 ||
		    !fet_send_recv(writemem, 12, NULL)) {
			fprintf(stderr, "msp_write_mem: failed to write "
				"to 0x%04x\n", addr);
			return -1;
		}

		buffer += plen;
		count -= plen;
		addr += plen;
	}

	return 0;
}

#define MSP_ERASE_ALL		0x01
#define MSP_ERASE_MAIN		0x02
#define MSP_ERASE_ADDR		0x03
#define MSP_ERASE_INFO		0x04

static int msp_erase(int type, u_int16_t addr)
{
	static char erase[] = {
		0x0c, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	switch (type) {
	case MSP_ERASE_MAIN:
		erase[4] = 1;
		erase[8] = 0xe0;
		erase[9] = 0xff;
		erase[12] = 2;
		break;

	case MSP_ERASE_ADDR:
		erase[8] = addr & 0xff;
		erase[9] = addr >> 8;
		erase[12] = 2;
		break;

	case MSP_ERASE_INFO:
		erase[9] = 0x10;
		erase[13] = 1;
		break;

	case MSP_ERASE_ALL:
	default:
		erase[4] = 2;
		erase[9] = 0x10;
		erase[13] = 0x01;
		break;
	}

	if (!fet_send_recv("\x1d\x01", 2, NULL)) {
		fprintf(stderr, "msp_erase: command 1d failed\n");
		return -1;
	}

	if (!fet_send_recv("\x05\x02\x02\x00\x02\x00\x00\x00\x26\x00\x00\x00",
			   12, NULL)) {
		fprintf(stderr, "msp_erase: config (1) failed\n");
		return -1;
	}

	if (!fet_send_recv("\x05\x02\x02\x00\x05\x00\x00\x00\x00\x00\x00\x00",
			   12, NULL)) {
		fprintf(stderr, "msp_erase: config (2) failed\n");
		return -1;
	}

	if (!fet_send_recv(erase, 16, NULL)) {
		fprintf(stderr, "msp_erase: erase command failed\n");
		return -1;
	}

	return 0;
}

#define MSP_POLL_RUNNING	0x01
#define MSP_POLL_BREAKPOINT	0x02

static int msp_poll(void)
{
	const char *reply;
	int len;

	/* Without this delay, breakpoints can get lost. */
	if (usleep(500000) < 0)
		return -1;

	reply = fet_send_recv("\x12\x02\x01\x00\x00\x00\x00\x00", 8, &len);
	if (!reply) {
		fprintf(stderr, "msp_poll: polling failed\n");
		return -1;
	}

	return reply[6];
}

static int msp_step(void)
{
	if (!fet_send_recv("\x11\x02\x02\x00\x02\x00\x00\x00\x00\x00\x00\x00",
			12, NULL)) {
		fprintf(stderr, "msp_step: failed to single-step\n");
		return -1;
	}

	return 0;
}

static int msp_run(void)
{
	if (!fet_send_recv("\x11\x02\x02\x00\x03\x00\x00\x00\x00\x00\x00\x00",
			   12, NULL)) {
		fprintf(stderr, "msp_run: run failed\n");
		return -1;
	}

	return 0;
}

static int msp_stop(void)
{
	if (!fet_send_recv("\x12\x02\x01\x00\x01\x00\x00\x00", 8, NULL)) {
		fprintf(stderr, "msp_stop: stop failed\n");
		return -1;
	}

	return 0;
}

static int msp_break(int enable, u_int16_t addr)
{
	static char buf[] = {
		0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x00, 0x00, 0x14, 0x80, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0x0e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x80, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
		0x98, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
	};

	if (enable) {
		buf[12] = addr & 0xff;
		buf[13] = addr >> 8;
		buf[30] = 0xff;
		buf[31] = 0xff;
		buf[36] = 2;
		buf[52] = 3;
	} else {
		buf[12] = 0;
		buf[13] = 0;
		buf[30] = 0;
		buf[31] = 0;
		buf[36] = 0;
		buf[52] = 1;
	}

	if (fet_send_data(buf, sizeof(buf)) < 0 ||
	    !fet_send_recv("\x2a\x02\x04\x00\x08\x00\x00\x00\xb0\x00\x00\x00"
			   "\x00\x00\x00\x00\x40\x00\x00\x00", 20, NULL)) {
		fprintf(stderr, "msp_break: set breakpoint failed\n");
		return -1;
	}

	return 0;
}

/**********************************************************************
 * Command-line interface
 */

char *get_arg(char **text)
{
	char *start;
	char *end;

	if (!text)
		return NULL;

	start = *text;
	while (*start && isspace(*start))
		start++;

	if (!*start)
		return NULL;

	end = start;
	while (*end && !isspace(*end))
		end++;

	if (*end)
	    while (*end && isspace(*end))
		    *(end++) = 0;

	*text = end;
	return start;
}

#define REG_COLUMNS	4
#define REG_ROWS	((MSP_NUM_REGS + REG_COLUMNS - 1) / REG_COLUMNS)

static void show_regs(u_int16_t *regs)
{
	int i;

	for (i = 0; i < REG_ROWS; i++) {
		int j;

		printf("    ");
		for (j = 0; j < REG_COLUMNS; j++) {
			int k = j * REG_ROWS + i;

			if (k < MSP_NUM_REGS)
				printf("(r%02d: %04x)  ", k, regs[k]);
		}
		printf("\n");
	}
}

struct command {
	const char	*name;
	int		(*func)(char **arg);
	const char	*help;
};

static const struct command all_commands[];

static int cmd_help(char **arg);

static int cmd_md(char **arg)
{
	char *off_text = get_arg(arg);
	char *len_text = get_arg(arg);
	unsigned int offset = 0;
	unsigned int length = 0;

	if (!off_text) {
		fprintf(stderr, "md: offset must be specified\n");
		return -1;
	}

	sscanf(off_text, "%x", &offset);
	if (len_text)
		sscanf(len_text, "%x", &length);
	else
		length = 0x80;
	if (offset >= 0x10000 || length > 0x10000 ||
	    (offset + length) > 0x10000) {
		fprintf(stderr, "md: memory out of range\n");
		return -1;
	}

	while (length) {
		char buf[128];
		int blen = length > sizeof(buf) ? sizeof(buf) : length;

		if (msp_read_mem(offset, buf, blen) < 0)
			return -1;
		hexdump(offset, buf, blen);

		offset += blen;
		length -= blen;
	}

	return 0;
}

static void disassemble(u_int16_t offset, u_int8_t *data, int length)
{
	while (length) {
		struct msp430_instruction insn;
		int retval;
		int count;
		int i;

		retval = decode(data, offset, length, &insn);
		count = retval > 0 ? retval : 2;
		if (count > length)
			count = length;
		printf("    %04x:", offset);

		for (i = 0; i < count; i++)
			printf(" %02x", data[i]);

		while (i < 8) {
			printf("   ");
			i++;
		}

		if (retval >= 0) {
			char buf[32];

			format_instruction(buf, sizeof(buf), &insn);
			printf("%s", buf);
		}

		printf("\n");

		offset += count;
		length -= count;
		data += count;
	}
}

static int cmd_dis(char **arg)
{
	char *off_text = get_arg(arg);
	char *len_text = get_arg(arg);
	unsigned int offset = 0;
	unsigned int length = 0;
	char buf[128];

	if (!off_text) {
		fprintf(stderr, "md: offset must be specified\n");
		return -1;
	}

	sscanf(off_text, "%x", &offset);
	if (len_text)
		sscanf(len_text, "%x", &length);
	else
		length = 0x40;
	if (offset >= 0x10000 || length > sizeof(buf) ||
	    (offset + length) > 0x10000) {
		fprintf(stderr, "dis: memory out of range\n");
		return -1;
	}

	if (msp_read_mem(offset, buf, length) < 0)
		return -1;

	disassemble(offset, (u_int8_t *)buf, length);
	return 0;
}

static int cmd_reset(char **arg)
{
	return msp_reset(MSP_RESET_ALL, 1);
}

static int cmd_regs(char **arg)
{
	u_int16_t regs[MSP_NUM_REGS];
	char code[16];

	if (msp_get_context(regs) < 0)
		return -1;
	show_regs(regs);

	/* Try to disassemble the instruction at PC */
	if (msp_read_mem(regs[0], code, sizeof(code)) < 0)
		return 0;

	disassemble(regs[0], (u_int8_t *)code, sizeof(code));
	return 0;
}

static int cmd_run(char **arg)
{
	char *bp_text = get_arg(arg);

	if (bp_text) {
		unsigned int addr = 0;

		sscanf(bp_text, "%x", &addr);
		msp_break(1, addr);
	} else {
		msp_break(0, 0);
	}

	if (msp_run() < 0)
		return -1;

	printf("Running. Press Ctrl+C to interrupt...");
	fflush(stdout);

	for (;;) {
		int r = msp_poll();

		if (r < 0 || !(r & MSP_POLL_RUNNING))
			break;
	}

	printf("\n");
	if (msp_stop() < 0)
		return -1;

	return cmd_regs(NULL);
}

static int cmd_set(char **arg)
{
	char *reg_text = get_arg(arg);
	char *val_text = get_arg(arg);
	int reg;
	unsigned int value = 0;
	u_int16_t regs[MSP_NUM_REGS];

	if (!(reg_text && val_text)) {
		fprintf(stderr, "set: must specify a register and a value\n");
		return -1;
	}

	while (*reg_text && !isdigit(*reg_text))
		reg_text++;
	reg = atoi(reg_text);
	sscanf(val_text, "%x", &value);

	if (reg < 0 || reg >= MSP_NUM_REGS) {
		fprintf(stderr, "set: register out of range: %d\n", reg);
		return -1;
	}

	if (msp_get_context(regs) < 0)
		return -1;
	regs[reg] = value;
	if (msp_set_context(regs) < 0)
		return -1;

	show_regs(regs);
	return 0;
}

static int cmd_step(char **arg)
{
	if (msp_step() < 0)
		return -1;
	if (msp_poll() < 0)
		return -1;

	return cmd_regs(NULL);
}

static int hexval(const char *text, int len)
{
	int value = 0;

	while (len && *text) {
		value <<= 4;

		if (*text >= 'A' && *text <= 'F')
			value += *text - 'A' + 10;
		else if (*text >= 'a' && *text <= 'f')
			value += *text - 'a' + 10;
		else if (isdigit(*text))
			value += *text - '0';

		text++;
		len--;
	}

	return value;
}

static char prog_buf[128];
static u_int16_t prog_addr;
static int prog_len;

static int prog_flush(void)
{
	int wlen = prog_len;

	if (!prog_len)
		return 0;

	/* Writing across this address seems to cause a hang */
	if (prog_addr < 0x999a && wlen + prog_addr > 0x999a)
		wlen = 0x999a - prog_addr;

	printf("Writing %3d bytes to %04x...\n", wlen, prog_addr);

	if (msp_write_mem(prog_addr, prog_buf, wlen) < 0)
		return -1;

	memmove(prog_buf, prog_buf + wlen, prog_len - wlen);
	prog_len -= wlen;
	prog_addr += wlen;

	return 0;
}

static int prog_hex(int lno, const char *hex)
{
	int len = strlen(hex);
	int count, address, type, cksum = 0;
	int i;

	if (*hex != ':')
		return 0;

	hex++;
	len--;

	while (len && isspace(hex[len - 1]))
		len--;

	if (len < 10)
		return 0;

	count = hexval(hex, 2);
	address = hexval(hex + 2, 4);
	type = hexval(hex + 6, 2);

	if (type)
		return 0;

	for (i = 0; i + 2 < len; i += 2)
		cksum = (cksum + hexval(hex + i, 2))
			& 0xff;
	cksum = ~(cksum - 1) & 0xff;

	if (count * 2 + 10 != len) {
		fprintf(stderr, "warning: length mismatch at line %d\n", lno);
		count = (len - 10) / 2;
	}

	if (cksum != hexval(hex + len - 2, 2))
		fprintf(stderr, "warning: invalid checksum at line %d\n", lno);

	for (i = 0; i < count; i++) {
		int offset;

		offset = address + i - prog_addr;
		if (offset < 0 || offset >= sizeof(prog_buf))
			if (prog_flush() < 0)
				return -1;

		if (!prog_len)
			prog_addr = address + i;

		offset = address + i - prog_addr;
		prog_buf[offset] = hexval(hex + 8 + i * 2, 2);
		if (offset + 1 > prog_len)
			prog_len = offset + 1;
	}

	return 0;
}

static int cmd_prog(char **arg)
{
	FILE *in = fopen(*arg, "r");
	char text[256];
	int lno = 1;

	if (!in) {
		fprintf(stderr, "prog: %s: %s\n", *arg, strerror(errno));
		return -1;
	}

	printf("Erasing...\n");
	if (msp_erase(MSP_ERASE_ALL, 0) < 0) {
		fclose(in);
		return -1;
	}

	if (msp_reset(MSP_RESET_ALL, 1) < 0)
		return -1;

	prog_len = 0;
	while (fgets(text, sizeof(text), in))
		if (prog_hex(lno++, text) < 0) {
			fclose(in);
			return -1;
		}
	fclose(in);

	if (prog_flush() < 0)
		return -1;

	return msp_reset(MSP_RESET_ALL, 1);
}

static const struct command all_commands[] = {
	{"dis",		cmd_dis,
"dis <address> <range>\n"
"    Disassemble a section of memory.\n"},
	{"help",	cmd_help,
"help [command]\n"
"    Without arguments, displays a list of commands. With a command name as\n"
"    an argument, displays help for that command.\n"},
	{"md",		cmd_md,
"md <address> <length>\n"
"    Read the specified number of bytes from memory at the given address,\n"
"    and display a hexdump.\n"},
	{"prog",	cmd_prog,
"prog <filename.hex>\n"
"    Erase the device and flash the data contained in an Intel HEX file.\n"},
	{"regs",	cmd_regs,
"regs\n"
"    Read and display the current register contents.\n"},
	{"reset",	cmd_reset,
"reset\n"
"    Reset (and halt) the CPU.\n"},
	{"run",		cmd_run,
"run [breakpoint]\n"
"    Run the CPU until either a specified breakpoint occurs or the command\n"
"    is interrupted.\n"},
	{"set",		cmd_set,
"set <register> <value>\n"
"    Change the value of a CPU register.\n"},
	{"step",	cmd_step,
"step\n"
"    Single-step the CPU, and display the register state.\n"},
};

#define NUM_COMMANDS (sizeof(all_commands) / sizeof(all_commands[0]))

const struct command *find_command(const char *name)
{
	int i;

	for (i = 0; i < NUM_COMMANDS; i++)
		if (!strcasecmp(name, all_commands[i].name))
			return &all_commands[i];

	return NULL;
}

static int cmd_help(char **arg)
{
	char *topic = get_arg(arg);

	if (topic) {
		const struct command *cmd = find_command(topic);

		if (!cmd) {
			fprintf(stderr, "help: unknown command: %s\n", topic);
			return -1;
		}

		fputs(cmd->help, stdout);
	} else {
		int i;

		printf("Available commands:");
		for (i = 0; i < NUM_COMMANDS; i++)
			printf(" %s", all_commands[i].name);
		printf("\n");
		printf("Type \"help <command>\" for more information.\n");
		printf("Press Ctrl+D to quit.\n");
	}

	return 0;
}

static void sigint_handler(int signum)
{
}

int main(void)
{
	const static struct sigaction siga = {
		.sa_handler = sigint_handler,
		.sa_flags = 0
	};

	puts(
"MSPDebug version 0.1 - debugging tool for the eZ430-RF2500\n"
"Copyright (C) 2009 Daniel Beer <dlbeer@gmail.com>\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");

	init_codes();
	if (usbtr_open() < 0)
		return -1;
	usbtr_flush();
	if (msp_startup(1, 3000) < 0)
		return -1;

	sigaction(SIGINT, &siga, NULL);
	cmd_help(NULL);

	for (;;) {
		char buf[128];
		int len;
		char *arg = buf;
		char *cmd_text;

		printf("(msp-debug) ");
		fflush(stdout);
		if (!fgets(buf, sizeof(buf), stdin)) {
			if (feof(stdin))
				break;
			printf("\n");
			continue;
		}

		len = strlen(buf);
		while (len && isspace(buf[len - 1]))
			len--;
		buf[len] = 0;

		cmd_text = get_arg(&arg);
		if (cmd_text) {
			const struct command *cmd = find_command(cmd_text);

			if (cmd)
				cmd->func(&arg);
			else
				fprintf(stderr, "unknown command: %s "
						"(try \"help\")\n",
					cmd_text);
		}
	}

	printf("\n");
	msp_run();
	msp_shutdown();
	usbtr_close();

	return 0;
}
