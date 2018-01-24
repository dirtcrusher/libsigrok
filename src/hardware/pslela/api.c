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

	GSList *devices = NULL;
	struct drv_context *drvc = di->context;
	drvc->instances = NULL;

	// Get connexion info from options
	const char *conn = NULL, *serial_comm = NULL;
	GSList *l = options;
	while (l != NULL) {
		struct sr_config *sr_conf = l->data;
		switch (sr_conf->key) {
			case SR_CONF_CONN:
				conn = g_variant_get_string(sr_conf->data, NULL);
				break;
			case SR_CONF_SERIALCOMM:
				serial_comm = g_variant_get_string(sr_conf->data, NULL);
				break;
		}
		l = l->next;
	}

	if (!conn) {
		return NULL;
	}
	if (!serial_comm) {
		serial_comm = "9600/8n1";
	}

	// Probe the serial port
	sr_dbg("Probing '%s' with options '%s'", conn, serial_comm);

	struct sp_port *current_port;
	sp_get_port_by_name(conn, &current_port);
	if (sp_open(current_port, SP_MODE_READ_WRITE) != SP_OK) {
		sr_dbg("Couldn't open port");
		sp_free_port(current_port);
		return NULL;
	}

	// The port has been opened
	// We flush all buffers for good measure
	sp_flush(current_port, SP_BUF_BOTH);

	// We attempt to write a "get version" command to the port
	char *version_command = "v00";
	if (sp_nonblocking_write(current_port, version_command, 3) < 0) {
		sr_dbg("Couldn't write to port");
		sp_free_port(current_port);
		return NULL;
	}
	unsigned int retries = 10;
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
	char buffer[255] = {0};
	unsigned char totalReceived = 0;
	char received;
	while ((retries > 0) && (totalReceived < 3)) {
		received = sp_nonblocking_read(
			current_port,
			buffer + totalReceived,
			3 - totalReceived
		);
		if (received < 0) {
			retries--;
			continue;
		}
		totalReceived += received;
	}
	if (retries == 0) {
		sr_dbg("Couldn't read from port");
		return NULL;
	}
	sr_dbg("Received %c%c", buffer[0], buffer[1]);

	// We parse the response header received
	if (buffer[0] != PSLELA_CMD_SUCCESS) {
		sr_dbg("Received incorrect response from device");
		sp_free_port(current_port);
		return NULL;
	}
	unsigned char data_length;
	if (hextobyte(buffer + 1, &data_length)) {
		sr_dbg("Received incorrect response from device");
		sp_free_port(current_port);
		return NULL;
	}

	// We read the version string
	totalReceived = 0;
	retries = 10;
	while ((retries > 0) && (totalReceived < data_length)) {
		received = sp_nonblocking_read(
			current_port,
			buffer + totalReceived,
			data_length - totalReceived
		);
		if (received < 0) {
			retries--;
			continue;
		}
		totalReceived += received;
	}
	if (retries == 0) {
		sr_dbg("Couldn't read data from device");
		sp_free_port(current_port);
		return NULL;
	}
	sr_dbg("Received version string \"%s\"", buffer);

	if (strcmp(buffer, PSLELA_EXPECTED_VERSION)) {
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
	struct sr_dev_inst *device = sr_dev_inst_user_new(
		"PSLELAvendor",
		"PSLELAmodel",
		PSLELA_EXPECTED_VERSION
	);

	// Add the 8 logic channels to it
	char tmp[8][3];
	for (unsigned char i = 0; i < 8; i++) {
		sprintf(tmp[i], "D%i", i);
		sr_dbg("Adding channel %s", tmp[i]);
		sr_dev_inst_channel_add(device, i, SR_CHANNEL_LOGIC, tmp[i]);
	}

	// Add the device instance to the list of device instances
	devices = g_slist_append(NULL, device);
	drvc->instances = g_slist_append(drvc->instances, device);

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
