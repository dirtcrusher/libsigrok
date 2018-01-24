/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2018 <Ensimag 2017-2018 SLE 3A, Groupe 2>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"

void create_pslela_cmd_string(char **str, struct pslela_cmd* cmd) {
	char tmp_byte_hex[2];
	unsigned int i;

	// Allocate command string
	*str = calloc(
		1 // Command code
		+ 2 // Command length
		+ (cmd->len * 2) // Data
		+ 1 // Null terminator
		, sizeof(char)
	);

	// Append code character
	strncat(*str, &cmd->code, 1);

	// Append len characters
	bytetohex(cmd->len, tmp_byte_hex);
	strncat(*str, tmp_byte_hex, 2);

	// Append data characters
	for (i = 0; i < cmd->len; i++) {
		bytetohex(cmd->buff[i], tmp_byte_hex);
		strncat(*str, tmp_byte_hex, 2);
	}
}

int parse_pslela_cmd_string(char *str, struct pslela_cmd *cmd) {
	unsigned char tmp_byte, i;
	int total_len;

	// Verify that the string is at least the minimum size
	total_len = strlen(str);
	if (total_len < 3) {
		return -1;
	}

	// Parse command code
	cmd->code = str[0];

	// Parse command length
	hextobyte(str + 1, &tmp_byte);
	cmd->len = tmp_byte;

	// Verify that the string contains all the data
	if (total_len < (3 + (cmd->len * 2))) {
		return 1;
	}

	// Parse data
	for (i = 0; i < cmd->len; i++) {
		hextobyte(str + 3 + (i * 2), &tmp_byte);
		cmd->buff[i] = tmp_byte;
	}
	return 0;
}


int hextobyte(const char hex[2], unsigned char *byte) {
	unsigned char upper, lower;

	if ('a' <= hex[0] && hex[0] <= 'f') {
		upper = 10 + hex[0] - 'a';
	} else if ('A' <= hex[0] && hex[0] <= 'F') {
		upper = 10 + hex[0] - 'A';
	} else if ('0' <= hex[0] && hex[0] <= '9') {
		upper = hex[0] - '0';
	} else {
		/* err */
		return 1;
	}

	if ('a' <= hex[1] && hex[1] <= 'f') {
		lower = 10 + hex[1] - 'a';
	} else if ('A' <= hex[1] && hex[1] <= 'F') {
		lower = 10 + hex[1] - 'A';
	} else if ('0' <= hex[1] && hex[1] <= '9') {
		lower = hex[1] - '0';
	} else {
		/* err */
		return 1;
	}

	*byte = (upper << 4) | (lower & 0xf);
	return 0;
}

int bytetohex(const unsigned char byte, char hex[2]) {
	unsigned char half;

	half = byte & 0xf;
	if (half <= 9) {
		hex[1] = '0' + half;
	} else {
		hex[1] = 'a' + half - 10;
	}

	half = (byte >> 4) & 0xf;

	if (half <= 9) {
		hex[0] = '0' + half;
	} else {
		hex[0] = 'a' + half - 10;
	}

	return 0;
}

