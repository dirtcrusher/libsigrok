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


static int send_nonblocking(struct sp_port *port, char* str, size_t len)
{
	int ret;
	int retries = 10;
	size_t already_written = 0;

	while ((already_written < len) && (retries > 0)) {
		ret = sp_nonblocking_write(port, str + already_written, len - already_written);
		if (ret < 0) {
			return ret;
		} else {
			already_written += ret;
		}
		retries--;
		g_usleep(10000);
	}
	return already_written;
}

static int read_nonblocking(struct sp_port *port, char* buffer, size_t len)
{
	int ret;
	int retries = 10;
	size_t already_read = 0;

	while ((already_read < len) && (retries > 0)) {
		ret = sp_nonblocking_read(port, buffer + already_read, len - already_read);
		if (ret < 0) {
			return ret;
		} else {
			already_read += ret;
		}
		retries--;
		g_usleep(10000);
	}
	return already_read;
}

int send_pslela_cmd(struct sp_port *port, struct pslela_cmd *cmd)
{
	char *cmd_str;
	int ret;

	create_pslela_cmd_string(&cmd_str, cmd);
	sr_dbg("Sending command: %s", cmd_str);

	ret = send_nonblocking(port, cmd_str, strlen(cmd_str));
	if (ret < (int) strlen(cmd_str)) {
		sr_dbg("Error sending command");
		free(cmd_str);
		return SR_ERR_IO;
	}
	free(cmd_str);

	sr_dbg("Finished sending command");
	return SR_OK;
}

int read_pslela_cmd(struct sp_port *port, struct pslela_cmd *cmd)
{
	char response_header[4] = {0};
	int ret;

	sr_dbg("Reading response");

	ret = read_nonblocking(port, response_header, 3);
	if (ret < 3) {
		sr_dbg("Error reading command header");
		return SR_ERR_IO;
	}

	sr_dbg("Header %s", response_header);

	if (parse_pslela_cmd_string(response_header, cmd) < 0) {
		sr_dbg("Error parsing command header");
		return SR_ERR_IO;
	}

	ret = read_nonblocking(port, cmd->buff, cmd->len);
	if (ret < cmd->len) {
		sr_dbg("Error reading command data");
		return SR_ERR_IO;
	}

	sr_dbg("Finished reading response");
	return SR_OK;
}


void create_pslela_cmd_string(char **str, struct pslela_cmd* cmd)
{
	char tmp_byte_hex[2];

	// Allocate command string
	*str = calloc(4 + cmd->len, sizeof(char));

	// Append code character
	strncat(*str, &cmd->code, 1);

	// Append len characters
	bytetohex(cmd->len, tmp_byte_hex);
	strncat(*str, tmp_byte_hex, 2);

	// Append data
	strncat(*str, cmd->buff, cmd->len);
}

int parse_pslela_cmd_string(char *str, struct pslela_cmd *cmd)
{
	unsigned char tmp_byte;
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
	if (total_len < (3 + cmd->len)) {
		return 1;
	}

	// Copy data
	strncpy(cmd->buff, str + 3, cmd->len);
	return 0;
}


int hextobyte(const char hex[2], unsigned char *byte)
{
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

int bytetohex(const unsigned char byte, char hex[2])
{
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

int hextou32(const char hex[8], uint32_t *val)
{
	int ret;
	unsigned char *c = (unsigned char*) val;

	ret = hextobyte(&hex[0], &c[3]);
	ret = hextobyte(hex + 2, &c[2]);
	ret = hextobyte(hex + 4, &c[1]);
	ret = hextobyte(hex + 6, &c[0]);

	return ret;
}

void u32tohex(const uint32_t val, char hex[8])
{
	bytetohex((val >> 24), hex);
	bytetohex((val >> 16), &hex[2]);
	bytetohex((val >>  8), &hex[4]);
	bytetohex((val >>  0), &hex[6]);
}
