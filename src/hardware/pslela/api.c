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

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
	SR_CONF_SERIALCOMM
};

static const uint32_t drvopts[] = {
	SR_CONF_LOGIC_ANALYZER
};

static const uint32_t devopts[] = {
	SR_CONF_SAMPLERATE         | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_PATTERN_MODE       | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_NUM_LOGIC_CHANNELS | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_ENABLED            | SR_CONF_GET | SR_CONF_SET,
};

static const uint64_t samplerates[] = {
	SR_HZ(1),
	SR_KHZ(1),
	SR_MHZ(1)
};

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	sr_dbg("Starting scan");

	GSList *devices, *options_iter;
	struct drv_context *driver_context;
	struct sr_dev_inst *device;
	struct sr_config *options_iter_data;
	struct sp_port *current_port;
	struct pslela_cmd request_cmd, response_cmd;
	const char *connexion_string, *serial_comm_string;
	char *request_string, buffer[300] = {0}, bytes_received;
	char channel_strings[8][3];
	unsigned int retries;
	unsigned char totalReceived, i;

	// Initialize context
	devices = NULL;
	driver_context = di->context;
	driver_context->instances = NULL;

	// Get connexion info from options
	connexion_string = NULL;
	serial_comm_string = NULL;
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
			case SR_CONF_SERIALCOMM:
				serial_comm_string = g_variant_get_string(
						options_iter_data->data,
						NULL
				);
				break;
		}
		options_iter = options_iter->next;
	}

	if (!connexion_string) {
		return NULL;
	}
	if (!serial_comm_string) {
		serial_comm_string = "115200/8n1";
	}

	// Probe the serial port
	sr_dbg("Probing '%s' with options '%s'", connexion_string, serial_comm_string);

	sp_get_port_by_name(connexion_string, &current_port);
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
	while (retries > 0) {
		if (sp_output_waiting(current_port) != 0) {
			retries--;
			g_usleep(10);
			continue;
		}
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
		if (bytes_received < 0) {
			retries--;
			continue;
		}
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
	sr_info("Found device on %s", sp_get_port_description(current_port));

	sp_close(current_port);
	sp_free_port(current_port);

	// At this point, we know the device is a correct PSLELA
	// So we add it to the list of devices

	// Create new device instance
	device = sr_dev_inst_user_new(
		"PSLELAvendor",
		"PSLELAmodel",
		PSLELA_EXPECTED_VERSION
	);

	// Add the 8 logic channels to it
	for (i = 0; i < 8; i++) {
		sprintf(channel_strings[i], "D%i", i);
		sr_dbg("Adding channel %s", channel_strings[i]);
		sr_dev_inst_channel_add(device, i, SR_CHANNEL_LOGIC, channel_strings[i]);
	}

	// Add the device instance to the list of device instances
	devices = g_slist_append(NULL, device);
	driver_context->instances = g_slist_append(driver_context->instances, device);

	return devices;
}

static int dev_open(struct sr_dev_inst *sdi)
{
	(void)sdi;

	/* TODO: get handle from sdi->conn and open it. */

	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	(void)sdi;

	/* TODO: get handle from sdi->conn and close it. */

	return SR_OK;
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;

	sr_dbg("Config get");

	ret = SR_OK;
	switch (key) {
		/* TODO */
		default:
			return SR_ERR_NA;
	}

	return ret;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	(void)sdi;
	(void)data;
	(void)cg;
	sr_dbg("Config set");

	ret = SR_OK;
	switch (key) {
		/* TODO */
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
	sr_dbg("Config list");

	ret = SR_OK;
	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
	case SR_CONF_DEVICE_OPTIONS:
		return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	/* TODO: configure hardware, reset acquisition state, set up
	 * callbacks and send header packet. */

	(void)sdi;

	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	/* TODO: stop acquisition. */

	(void)sdi;

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
