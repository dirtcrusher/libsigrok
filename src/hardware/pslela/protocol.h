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

// TODO
struct dev_context {
};

int hextobyte(const char hex[2], unsigned char *byte);
int bytetohex(const unsigned char byte, char hex[2]);

#endif
