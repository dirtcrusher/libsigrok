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
#include <termios.h>
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

static const uint64_t samplerates[] = {
	SR_HZ(1),
	SR_HZ(5),
	SR_HZ(10),
	SR_HZ(50),
	SR_HZ(100),
	SR_HZ(500),
	SR_KHZ(1),
	SR_KHZ(5),
	SR_KHZ(10),
	SR_KHZ(50),
	SR_KHZ(100),
	SR_KHZ(500),
	SR_MHZ(1),
	SR_MHZ(10),
	SR_MHZ(20),
	SR_MHZ(30),
	SR_MHZ(40),
	SR_MHZ(50),
	SR_MHZ(60),
	SR_MHZ(70),
	SR_MHZ(80),
	SR_MHZ(90),
	SR_MHZ(100),
};
#define NUM_SAMPLERATES (ARRAY_SIZE(samplerates))


// Complete definition of sp_port as defined in libserialport_internal.h
// Really bad practice for putting this here, but there is no other way for
// changing tty flags (except not using libserialport...)
struct sp_port {
	char *name;
	char *description;
	enum sp_transport transport;
	int usb_bus;
	int usb_address;
	int usb_vid;
	int usb_pid;
	char *usb_manufacturer;
	char *usb_product;
	char *usb_serial;
	char *bluetooth_address;
	int fd;
};


static struct sr_dev_inst *probe(struct sp_port *current_port, struct sr_dev_driver *di)
{
	struct pslela_cmd     cmd;
	struct sp_port        *device_port;
	struct sp_port_config *port_config;
	struct sr_dev_inst    *device;
	struct termios         termios_p;
	char  channel_strings[8][3];
	char *request_string;
	unsigned char i;
	unsigned int  retries;
	int ret;

	sr_dbg("Probing '%s'", sp_get_port_name(current_port));

	// We open the port
	if (sp_open(current_port, SP_MODE_READ_WRITE) != SP_OK) {
		sr_dbg("Couldn't open port");
		return NULL;
	}

	// We configure the port
	port_config = NULL;
	sp_new_config(&port_config);
	sp_set_config_baudrate(port_config, 115200);
	sp_set_config_bits(port_config, 8);
	sp_set_config_parity(port_config, SP_PARITY_NONE);
	sp_set_config_stopbits(port_config, 1);
	sp_set_config_xon_xoff(port_config, SP_XONXOFF_OUT);

	if (sp_set_config(current_port, port_config) < 0) {
		sr_dbg("Couldn't configure port");
		sp_free_config(port_config);
		return NULL;
	}
	sp_free_config(port_config);

	// Since libserialport does some bad configuration, we manually remove
	// the ECHONL flag from the termios struct
	// NOTE: only works on Linux
	tcgetattr(current_port->fd, &termios_p);
	termios_p.c_cc[VMIN]=0;
	termios_p.c_cc[VTIME]=0;
	termios_p.c_cflag &= ~(HUPCL);
	termios_p.c_iflag |= IGNBRK;
	termios_p.c_iflag &= ~(IGNPAR | IXANY);
	termios_p.c_lflag &= ~(ECHOE | ECHOK);
	if (tcsetattr(current_port->fd, TCSAFLUSH, &termios_p) < 0) {
		sr_dbg("Couldn't manually configure port");
		sp_close(current_port);
		return NULL;
	}

	// The port has been opened
	// We flush all buffers for good measure
	sp_flush(current_port, SP_BUF_BOTH);

	// We write a lot of 0s so that we can synchronize with the device
	request_string = malloc(sizeof(char) * 260);
	memset(request_string, '0', sizeof(char) * 259);
	request_string[259] = 0;
	if (sp_nonblocking_write(current_port, request_string, 259) < 0) {
		sr_dbg("Couldn't write to port");
		free(request_string);
		sp_close(current_port);
		return NULL;
	}

	// We attempt to write a "get version" command to the port
	cmd.code = PSLELA_CMD_READ_VERSION;
	cmd.len = 0;
	if (send_pslela_cmd(current_port, &cmd) < 0) {
		sr_dbg("Couldn't write command to port");
		sp_close(current_port);
		return NULL;
	}

	sr_dbg("Emptying write buffer to port");
	retries = 10;
	while ((retries > 0) && ((ret = sp_output_waiting(current_port)) > 0)) {
	    if (ret < 0) {
		    sr_dbg("Error while emptying write buffer to port");
		    sp_close(current_port);
		    return NULL;
	    }
	    retries--;
	    g_usleep(100000);
	}
	if ((retries == 0) || (ret < 0)) {
	    sr_dbg("Couldn't empty write buffer to port");
	    sp_close(current_port);
	    return NULL;
	}

	// We attempt to read the response
	sr_dbg("Reading version from port");
	if (read_pslela_cmd(current_port, &cmd) < 0) {
		sr_dbg("Couldn't read version from port");
		sp_close(current_port);
		return NULL;
	}
	sr_dbg("Device version = %s", cmd.buff);

	// We test the version string
	if (strcmp(cmd.buff, PSLELA_EXPECTED_VERSION)) {
		sr_info("Found device with incompatible firmware version");
		sp_close(current_port);
		return NULL;
	}

	// At this point, we know the device is a correct PSLELA
	sp_close(current_port);
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
		sr_dbg("Freeing port list");
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
			*data = g_variant_new_uint64(devc->cur_kisamples * 1000);
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
			devc->cur_kisamples = g_variant_get_uint64(data) / 1000;
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
		*data = std_gvar_tuple_u64(1000, 1000 * 1000);
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
	struct dev_context *devc;
	unsigned char *buffer;
	unsigned int i;
	struct sr_datafeed_logic packet_contents;
	struct sr_datafeed_packet packet;

	devc = sdi->priv;

	sr_dbg("Device acq start");

	// Send start command
	cmd.code = PSLELA_CMD_START_CAPTURE;
	cmd.len = 48;

#define START_PATTERN        0xDEADBEEF
#define START_PATTERN_LENGTH 32
#define STOP_PATTERN         0xDEADC0DE
#define STOP_PATTERN_LENGTH  32
#define SYNCHRONOUS_MODE     1
#define TRIGGER_SELECT_LINE  2
	// TODO calculate freq_div parameters
	u32tohex(devc->cur_samplerate,  cmd.buff +  0); // DIVID_NUM
	sr_dbg("Configuring device: %08x", (unsigned int) devc->cur_samplerate);

	u32tohex(SR_MHZ(100),           cmd.buff +  8); // DIVID_DENOM
	sr_dbg("Configuring device: %08x", (unsigned int) SR_MHZ(100));

	u32tohex(devc->cur_kisamples,   cmd.buff + 16);
	sr_dbg("Configuring device: %08x", (unsigned int) devc->cur_kisamples);

	u32tohex(START_PATTERN,         cmd.buff + 24);
	sr_dbg("configuring device: %08x", (unsigned int) START_PATTERN);

	u32tohex(STOP_PATTERN,          cmd.buff + 32);
	sr_dbg("configuring device: %08x", (unsigned int) STOP_PATTERN);

	bytetohex(SYNCHRONOUS_MODE,     cmd.buff + 40);
	sr_dbg("configuring device: %02x", (unsigned int) SYNCHRONOUS_MODE);

	bytetohex(TRIGGER_SELECT_LINE,  cmd.buff + 42);
	sr_dbg("configuring device: %02x", (unsigned int) TRIGGER_SELECT_LINE);

	bytetohex(START_PATTERN_LENGTH, cmd.buff + 44);
	sr_dbg("configuring device: %02x", (unsigned int) START_PATTERN_LENGTH);

	bytetohex(STOP_PATTERN_LENGTH,  cmd.buff + 46);
	sr_dbg("configuring device: %02x", (unsigned int) STOP_PATTERN_LENGTH);

	if ((err = send_pslela_cmd(sdi->conn, &cmd)) != SR_OK) {
		return err;
	}
	if ((err = read_pslela_cmd(sdi->conn, &response)) != SR_OK) {
		return err;
	}
	if (response.code != PSLELA_CMD_SUCCESS) {
		return SR_ERR_DEV_CLOSED;
	}

	// Wait for capture finish
	cmd.code = PSLELA_CMD_READ_CAPTURE;
	cmd.len = 0;

	do {
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
		packet_contents.data = buffer;

		packet.type = SR_DF_LOGIC;
		packet.payload = &packet_contents;

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
