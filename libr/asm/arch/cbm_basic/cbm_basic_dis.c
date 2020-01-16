/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "cbm_basic_dis.h"

#define CBM_BASIC_LINE_MAX 80

R_API size_t r_cbm_basic_disassemble(R_OUT RStrBuf *out, RBuffer *buf) {
	ut64 pos = 0;
	ut16 next_op_addr = r_buf_read_le16_at (buf, pos);
	if (next_op_addr == UT16_MAX) {
		return pos;
	}
	r_strbuf_appendf (out, "->0x%04x", (unsigned int)next_op_addr);
	if (!next_op_addr) {
		// zero addr means end of program
		return pos;
	}

	ut8 b;
	while (pos < CBM_BASIC_LINE_MAX) {
		// TODO: max pos
		b = r_buf_read8_at (buf, pos++);
		if (b == 0 || b == UT8_MAX) {
			// 0 => end of line
			// 0xff => fail
			break;
		}
		r_strbuf_appendf (out, " 0x%02x", (unsigned int)b);
	}

	return pos;
}