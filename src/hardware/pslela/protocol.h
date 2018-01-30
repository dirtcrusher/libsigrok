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

#ifndef LIBSIGROK_HARDWARE_PSLELA_PROTOCOL_H
#define LIBSIGROK_HARDWARE_PSLELA_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "pslela"

#define PSLELA_CMD_READ_VERSION  'v'
#define PSLELA_CMD_START_CAPTURE 's'
#define PSLELA_CMD_STOP_CAPTURE  't'
#define PSLELA_CMD_READ_CAPTURE  'r'
#define PSLELA_CMD_ERROR         'X'
#define PSLELA_CMD_SUCCESS       'O'

#define PSLELA_EXPECTED_VERSION  "101"

struct pslela_cmd {
	char code;
	unsigned char len;
	char buff[256];
};

void create_pslela_cmd_string(char **str, struct pslela_cmd *cmd);
int parse_pslela_cmd_string(char *str, struct pslela_cmd *cmd);

struct target_config {
    unsigned divider_numerator     : 32;
    unsigned divider_denominator   : 32;
    unsigned nb_kisamples          : 32;
    unsigned start_pattern         : 32;
    unsigned stop_pattern          : 32;
    unsigned synchronous_detection : 1;
    unsigned trigger_line_select   : 3;
    unsigned use_trigger           : 1;
    unsigned start_pattern_length  : 5;
    unsigned stop_pattern_length   : 5;
};

struct pslela_dev {
	int version;
	char *version_str;
	int timeout;
	struct target_config cfg;
	struct pslela_cmd tx_cmd;
	struct pslela_cmd rx_cmd;
};

int pslela_send_cmd(const struct sr_dev_inst *sdi);
int pslela_recv_cmd(const struct sr_dev_inst *sdi);
int pslela_probe(const struct sr_dev_inst *sdi);
int pslela_start_capture(const struct sr_dev_inst *sdi);

int hextobyte(const char hex[2], unsigned char *byte);
int bytetohex(const unsigned char byte, char hex[2]);
int hextou32(const char hex[8], uint32_t *val);
void u32tohex(const uint32_t val, char hex[8]);

#endif
