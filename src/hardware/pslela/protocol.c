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

	while (len && (retries > 0)) {
		ret = sp_nonblocking_write(port, str + already_written, len);
		if (ret < 0) {
			sr_dbg("sp_nonblock_write failed: %d", ret);
			return ret;
		} else if (ret == 0) {
			retries--;
			g_usleep(10000);
		} else {
			already_written += ret;
			len -= ret;
		}
	}

	if (retries == 0) {
		ret = SR_ERR_TIMEOUT;
	} else {
		ret = SR_OK;
	}

	return ret;
}

static int read_nonblocking(struct sp_port *port, char* buffer, size_t len)
{
	int ret;
	int retries = 10;
	size_t already_read = 0;

	while (len && (retries > 0)) {
		ret = sp_nonblocking_read(port, buffer + already_read, len);
		if (ret < 0) {
			return ret;
		} else if (ret == 0) {
			retries--;
			g_usleep(10000);
		} else {
			already_read += ret;
			len -= ret;
		}
	}

	if (retries == 0) {
		ret = SR_ERR_TIMEOUT;
	} else {
		ret = SR_OK;
	}

	return ret;
}

int pslela_send_cmd(const struct sr_dev_inst *sdi)
{
	struct pslela_dev *dev = sdi->priv;
	struct pslela_cmd *cmd = &dev->tx_cmd;
	int retval;
	char len[2];

	cmd->buff[cmd->len] = 0;
	sr_dbg("Sending  command: [%c%.2x|%s]", cmd->code, cmd->len,
		cmd->buff);

	retval = send_nonblocking(sdi->conn, &cmd->code, 1);
	if (retval) {
		return retval;
	}

	bytetohex(cmd->len, len);

	retval = send_nonblocking(sdi->conn, len, 2);
	if (retval) {
		return retval;
	}

	if (cmd->len) {
		retval = send_nonblocking(sdi->conn, cmd->buff, cmd->len);
	}

	return retval;
}

int pslela_recv_cmd(const struct sr_dev_inst *sdi)
{
	struct pslela_dev *dev = sdi->priv;
	struct pslela_cmd *cmd = &dev->rx_cmd;
	int retval;
	char len[2];

	retval = read_nonblocking(sdi->conn, &cmd->code, 1);
	if (retval) {
		return retval;
	} else if (cmd->code != PSLELA_CMD_SUCCESS
		   && cmd->code != PSLELA_CMD_ERROR) {
		sr_err("Received unknown response code 0x%.2x", cmd->code);
		return SR_ERR_IO;
	}

	retval = read_nonblocking(sdi->conn, len, 2);
	if (retval) {
		return retval;
	} else if (hextobyte(len, &cmd->len)) {
		sr_dbg("Convertion error");
		return SR_ERR_IO;
	}

	if (cmd->len) {
		retval = read_nonblocking(sdi->conn, cmd->buff, cmd->len);
	}

	cmd->buff[cmd->len] = 0;
	sr_dbg("Received command: [%c%.2x|%s]", cmd->code, cmd->len,
		cmd->buff);

	if (!retval && cmd->code == PSLELA_CMD_ERROR) {
		sr_err("Analyzer Error: '%s'\n", cmd->buff);
		return SR_ERR_DATA;
	}

	return retval;
}

static void init_cmd_start_capture(struct pslela_cmd *cmd, const struct target_config *cfg) {
	cmd->code = PSLELA_CMD_START_CAPTURE;
	cmd->len = 48;
	u32tohex(cfg->divider_numerator,      cmd->buff);
	u32tohex(cfg->divider_denominator,    cmd->buff +  8);
	u32tohex(cfg->nb_kisamples,           cmd->buff + 16);
	u32tohex(cfg->start_pattern,          cmd->buff + 24);
	u32tohex(cfg->stop_pattern,           cmd->buff + 32);
	bytetohex(cfg->synchronous_detection, cmd->buff + 40);
	bytetohex(cfg->trigger_line_select,   cmd->buff + 42);
	bytetohex(cfg->start_pattern_length,  cmd->buff + 44);
	bytetohex(cfg->stop_pattern_length,   cmd->buff + 46);
}

int pslela_start_capture(const struct sr_dev_inst *sdi)
{
	struct pslela_dev *dev = sdi->priv;
	int retval;

	init_cmd_start_capture(&dev->tx_cmd, &dev->cfg);
	retval = pslela_send_cmd(sdi);
	if (retval) {
		sr_err("Failed to send 'start capture'");
		return retval;
	}

	retval = pslela_recv_cmd(sdi);
	if (retval && retval != SR_ERR_DEV_CLOSED) {
		sr_err("Action 'start capture' failed");
	}

	return retval;
}

static int read_version(const struct sr_dev_inst *sdi)
{
	struct pslela_dev *dev = sdi->priv;
	int retval;

	dev->tx_cmd.code = PSLELA_CMD_READ_VERSION;
	dev->tx_cmd.len  = 0;

	retval = pslela_send_cmd(sdi);
	if (retval) {
		sr_dbg("readver: Fail to send");
		return retval;
	}

	retval = pslela_recv_cmd(sdi);
	if (retval && retval != SR_ERR_DATA) {
		sr_err("Action 'read version' failed");
	}

	if (!retval) {
		dev->version_str = g_strndup(dev->rx_cmd.buff, dev->rx_cmd.len);
		if (!dev->version_str) {
			/* TODO see errno for error code */
		}
	} else {
		sr_dbg("readver: Fail to recv");
	}

	return retval;
}

static int pslela_init(const struct sr_dev_inst *sdi)
{
	struct pslela_dev *dev = sdi->priv;
	memset(dev->tx_cmd.buff, '0', 256);
	return send_nonblocking(sdi->conn, dev->tx_cmd.buff, 256);
}


int pslela_probe(const struct sr_dev_inst *sdi)
{
	struct sp_port *dev_port = sdi->conn;
	unsigned int retries;
	int ret;

	ret = pslela_init(sdi);
	sr_dbg("Emptying write buffer to port");
	retries = 10;
	while ((retries > 0) && ((ret = sp_output_waiting(dev_port)) > 0)) {
	    if (ret < 0) {
		    sr_dbg("Error while emptying write buffer to port");
		    return SR_ERR_IO;
	    }
	    retries--;
	    g_usleep(100000);
	}
	if ((retries == 0) || (ret < 0)) {
	    sr_dbg("Couldn't empty write buffer to port");
	    return SR_ERR_IO;
	}

	ret = read_version(sdi);

	return ret;
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
