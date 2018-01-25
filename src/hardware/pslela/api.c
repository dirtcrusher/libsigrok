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
#include <string.h>
#include <stdlib.h>
#include "protocol.h"

#define SERIAL_COMM_CONF "115200/8n1"

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
};

static const uint32_t drvopts[] = {
	SR_CONF_LOGIC_ANALYZER
};

static const uint32_t devopts[] = {
	SR_CONF_SAMPLERATE     | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_LIMIT_SAMPLES  | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
};

#define NUM_SAMPLERATES 3
static const uint64_t samplerates[NUM_SAMPLERATES] = {
	SR_HZ(1),
	SR_KHZ(1),
	SR_MHZ(1),
};

static struct sr_dev_inst *probe(struct sp_port *current_port, struct sr_dev_driver *di)
{
	struct sr_dev_inst *device;
	struct sp_port *device_port;
	struct pslela_cmd request_cmd, response_cmd;
	char *request_string, buffer[300] = {0}, bytes_received;
	char channel_strings[8][3];
	unsigned int retries;
	unsigned char totalReceived, i;

	sr_dbg("Probing '%s'", sp_get_port_name(current_port));

	if (sp_open(current_port, SP_MODE_READ_WRITE) != SP_OK) {
		sr_dbg("Couldn't open port");
		sp_free_port(current_port);
		return NULL;
	}

	// The port has been opened
	// We flush all buffers for good measure
	sp_flush(current_port, SP_BUF_BOTH);

	// We attempt to write a "get version" command to the port
	request_cmd.code = PSLELA_CMD_READ_VERSION;
	request_cmd.len = 0;
	create_pslela_cmd_string(&request_string, &request_cmd);
	if (sp_nonblocking_write(current_port, request_string, 3) < 0) {
		sr_dbg("Couldn't write to port");
		sp_free_port(current_port);
		return NULL;
	}
	free(request_string);

	retries = 10;
	while ((retries > 0) && (sp_output_waiting(current_port) != 0)) {
		retries--;
		g_usleep(10);
		continue;
	}
	if (retries == 0) {
		sr_dbg("Couldn't write to port");
		sp_free_port(current_port);
		return NULL;
	}

	// We attempt to read the response
	retries = 10;
	totalReceived = 0;
	while ((retries > 0) && (totalReceived < 3)) {
		bytes_received = sp_nonblocking_read(
			current_port,
			buffer + totalReceived,
			3 - totalReceived
		);
		if (bytes_received <= 0) {
			retries--;
			continue;
		}
		g_usleep(10);
		totalReceived += bytes_received;
	}
	if (retries == 0) {
		sr_dbg("Couldn't read from port");
		return NULL;
	}
	sr_dbg("Received %c%c%c", buffer[0], buffer[1], buffer[2]);

	if ((parse_pslela_cmd_string(buffer, &response_cmd) < 0)
		|| (response_cmd.code != PSLELA_CMD_SUCCESS)) {
		sr_dbg("Received incorrect response from device");
		sp_free_port(current_port);
		return NULL;
	}

	// We read the version string
	totalReceived = 0;
	retries = 10;
	while ((retries > 0) && (totalReceived < response_cmd.len)) {
		bytes_received = sp_nonblocking_read(
			current_port,
			buffer + 3 + totalReceived,
			response_cmd.len - totalReceived
		);
		if (bytes_received < 0) {
			retries--;
			continue;
		}
		totalReceived += bytes_received;
	}
	if (retries == 0) {
		sr_dbg("Couldn't read data from device");
		sp_free_port(current_port);
		return NULL;
	}
	parse_pslela_cmd_string(buffer, &response_cmd);
	sr_dbg("Received version string \"%s\"", response_cmd.buff);

	if (strcmp(response_cmd.buff, PSLELA_EXPECTED_VERSION)) {
		sr_info("Found device with incompatible firmware version");
		sp_free_port(current_port);
		return NULL;
	}
	sp_close(current_port);

	// At this point, we know the device is a correct PSLELA
	sr_info("Found device on %s", sp_get_port_description(current_port));

	// So we add it to the list of devices

	// Create new device instance
	device = sr_dev_inst_user_new(
		"PSLELAvendor",
		"PSLELAmodel",
		PSLELA_EXPECTED_VERSION
	);
	sp_copy_port(current_port, &device_port);
	device->conn = device_port;
	device->connection_id = malloc(sizeof(char) * strlen(sp_get_port_name(current_port)));
	strcpy(device->connection_id, sp_get_port_name(current_port));
	device->driver = di;
	device->priv = calloc(1, sizeof(struct dev_context));
	((struct dev_context *) (device->priv))->cur_samplerate = samplerates[0];

	// Add the 8 logic channels to it
	sr_dbg("Adding logic channels");
	for (i = 0; i < 8; i++) {
		sprintf(channel_strings[i], "D%i", i);
		sr_dev_inst_channel_add(device, i, SR_CHANNEL_LOGIC, channel_strings[i]);
	}

	return device;
}

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	GSList *devices, *options_iter;
	struct drv_context *driver_context;
	struct sr_dev_inst *device;
	struct sr_config *options_iter_data;
	const char *connexion_string;
	struct sp_port **all_ports, *current_port;
	unsigned int i;

	sr_dbg("Starting scan");

	// Initialize context
	devices = NULL;
	driver_context = di->context;
	driver_context->instances = NULL;

	// Get connexion info from options
	connexion_string = NULL;
	options_iter = options;
	while (options_iter != NULL) {
		options_iter_data = options_iter->data;
		switch (options_iter_data->key) {
			case SR_CONF_CONN:
				connexion_string = g_variant_get_string(
					options_iter_data->data,
					NULL
				);
				break;
		}
		options_iter = options_iter->next;
	}

	if (!connexion_string) {
		// Scan all serial ports
		sp_list_ports(&all_ports);

		i = 0;
		while (*(all_ports + i) != NULL) {
			device = probe(*(all_ports + i), di);
			if (device != NULL) {
				devices = g_slist_append(devices, device);
				driver_context->instances = g_slist_append(
					driver_context->instances,
					device
				);
			}
			i++;
		}
		sp_free_port_list(all_ports);
		return devices;
	}

	// Else, we try to connect to the defined port
	sp_get_port_by_name(connexion_string, &current_port);
	device = probe(current_port, di);
	sp_free_port(current_port);
	if (!device) {
		return NULL;
	}

	// Add the device instance to the list of device instances
	devices = g_slist_append(NULL, device);
	driver_context->instances = g_slist_append(driver_context->instances, device);

	return devices;
}

static int dev_open(struct sr_dev_inst *sdi)
{
	(void)sdi;

	sr_dbg("Device open");

	if (!sdi || !sdi->conn) {
		return SR_ERR_ARG;
	}

	if (sp_open(sdi->conn, SP_MODE_READ_WRITE) < 0) {
		return SR_ERR_IO;
	}

	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	(void)sdi;

	sr_dbg("Device close");

	if (!sdi || !sdi->conn) {
		return SR_ERR_ARG;
	}

	if (sp_close(sdi->conn) < 0) {
		return SR_ERR_IO;
	}

	return SR_OK;
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc;
	int ret;

	devc = sdi->priv;

	(void)sdi;
	(void)data;
	(void)cg;

	ret = SR_OK;
	switch (key) {
		case SR_CONF_SAMPLERATE:
			*data = g_variant_new_uint64(devc->cur_samplerate);
			break;
		case SR_CONF_LIMIT_SAMPLES:
			*data = g_variant_new_uint64(devc->cur_numsamples);
			break;
		default:
			return SR_ERR_NA;
	}

	return ret;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc;
	int ret;
	uint64_t samplerate;

	devc = sdi->priv;

	(void)sdi;
	(void)data;
	(void)cg;

	ret = SR_OK;
	switch (key) {
		case SR_CONF_SAMPLERATE:
			samplerate = g_variant_get_uint64(data);
			if ((samplerate < samplerates[0])
			    || (samplerate > samplerates[NUM_SAMPLERATES - 1])) {
				return SR_ERR_ARG;
			}
			devc->cur_samplerate = samplerate;
			break;
		case SR_CONF_LIMIT_SAMPLES:
			devc->cur_numsamples = g_variant_get_uint64(data);
			break;
		default:
			ret = SR_ERR_NA;
	}

	return ret;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

	ret = SR_OK;
	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
	case SR_CONF_DEVICE_OPTIONS:
		return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
	case SR_CONF_SAMPLERATE:
		*data = std_gvar_samplerates(ARRAY_AND_SIZE(samplerates));
		break;
	case SR_CONF_LIMIT_SAMPLES:
		*data = std_gvar_tuple_u64(0, 1000 * 1000);
		break;
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	sr_dbg("Device acq stop");

	// TODO NOOP?

	(void)sdi;

	return SR_OK;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	int err;
	struct pslela_cmd cmd, response;
	unsigned char *buffer;
	unsigned int i;
	struct sr_datafeed_logic packet_contents;
	struct sr_datafeed_packet packet;

	sr_dbg("Device acq start");

	// Send start command
	cmd.code = PSLELA_CMD_START_CAPTURE;
	cmd.len = 48;

#define START_PATTERN        0xDEADBEEF
#define START_PATTERN_LENGTH 32
#define STOP_PATTERN         0xDEADC0DE
#define STOP_PATTERN_LENGTH  32
#define SYNCHRONOUS_MODE     0
#define TRIGGER_SELECT_LINE  2
	// TODO calculate freq_div parameters
	// TODO send correct amount of KiSamples
	u32tohex(0x00000001,            cmd.buff +  0); // DIVID_NUM
	u32tohex(0x00000010,            cmd.buff +  8); // DIVID_DENOM
	u32tohex(0x00000001,            cmd.buff + 16); // KISAMPLES
	u32tohex(START_PATTERN,         cmd.buff + 24);
	u32tohex(STOP_PATTERN,          cmd.buff + 32);
	bytetohex(SYNCHRONOUS_MODE,     cmd.buff + 40);
	bytetohex(TRIGGER_SELECT_LINE,  cmd.buff + 42);
	bytetohex(START_PATTERN_LENGTH, cmd.buff + 44);
	bytetohex(STOP_PATTERN_LENGTH,  cmd.buff + 46);

	if ((err = send_pslela_cmd(sdi->conn, &cmd)) != SR_OK) {
		return err;
	}

	// Wait for capture finish
	cmd.code = PSLELA_CMD_READ_CAPTURE;
	cmd.len = 0;

	do {
		g_usleep(10);
		if ((err = send_pslela_cmd(sdi->conn, &cmd)) != SR_OK) {
			return err;
		}
		if ((err = read_pslela_cmd(sdi->conn, &response)) != SR_OK) {
			return err;
		}
	} while (response.code == PSLELA_CMD_ERROR);

	// Read capture response
	do {
		sr_dbg("Received %i data characters", response.len);

		// Prepare packet
		packet_contents.length = response.len / 2;
		packet_contents.unitsize = 8;

		buffer = malloc(packet_contents.length * sizeof(char));
		for (i = 0; i < packet_contents.length; i += 2) {
			hextobyte(response.buff + (2 * i), buffer + i);
		}

		packet.type = SR_DF_LOGIC;
		packet.payload = buffer;

		// Send packet
		sr_session_send(sdi, &packet);
		free(buffer);

		// Read next data
		if ((err = send_pslela_cmd(sdi->conn, &cmd)) != SR_OK) {
			return err;
		}
		if ((err = read_pslela_cmd(sdi->conn, &response)) != SR_OK) {
			return err;
		}
	} while (response.len != 0);

	// Stop capture
	dev_acquisition_stop((struct sr_dev_inst*)sdi);

	return SR_OK;
}

SR_PRIV struct sr_dev_driver pslela_driver_info = {
	.name = "pslela",
	.longname = "Projet SLE Logic Analyser",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = scan,
	.dev_list = std_dev_list,
	.dev_clear = std_dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};

SR_REGISTER_DEV_DRIVER(pslela_driver_info);