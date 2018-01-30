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

static const char *channel_str[] = {
	"D0",
	"D1",
	"D2",
	"D3",
	"D4",
	"D5",
	"D6",
	"D7",
};

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

static int serial_config(struct sp_port *current_port)
{
	int retval;
	struct termios         termios_p;
	struct sp_port_config *port_config;
	// We configure the port
	port_config = NULL;
	sp_new_config(&port_config);
	sp_set_config_baudrate(port_config, 115200);
	sp_set_config_bits(port_config, 8);
	sp_set_config_parity(port_config, SP_PARITY_NONE);
	sp_set_config_stopbits(port_config, 1);
	sp_set_config_xon_xoff(port_config, SP_XONXOFF_OUT);

	retval = sp_set_config(current_port, port_config);
	sp_free_config(port_config);
	if (retval < 0) {
		sr_dbg("Couldn't configure port");
		return SR_ERR;
	}

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
		return SR_ERR;
	}

	return SR_OK;
}

static struct sr_dev_inst *probe(struct sp_port *current_port, struct sr_dev_driver *di)
{
	struct pslela_dev     *dev;
	struct sp_port        *device_port;
	struct sr_dev_inst     probe_sdi;
	struct sr_dev_inst    *device;
	unsigned int i;
	int ret;

	sr_dbg("Probing '%s'", sp_get_port_name(current_port));

	// We open the port
	if (sp_open(current_port, SP_MODE_READ_WRITE) != SP_OK) {
		sr_dbg("Couldn't open port");
		return NULL;
	}
	ret = serial_config(current_port);
	if (ret != SR_OK) {
		sp_close(current_port);
		return NULL;
	}

	// The port has been opened
	// We flush all buffers for good measure
	sp_flush(current_port, SP_BUF_BOTH);

	dev = calloc(1, sizeof(struct pslela_dev));
	if (!dev) {
		sr_err("Malloc failed");
		sp_close(current_port);
		return NULL;
	}

	probe_sdi.priv = dev;
        probe_sdi.conn = current_port;

	ret = pslela_probe(&probe_sdi);
	if (ret != SR_OK) {
		sr_err("Probe failed");
		sp_close(current_port);
		return NULL;
	}

	// We test the version string
	if (strcmp(dev->version_str, PSLELA_EXPECTED_VERSION)) {
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
		"ENSIMAG 2017 SLE",
		"PSLELA Zybo",
		PSLELA_EXPECTED_VERSION
	);
	sp_copy_port(current_port, &device_port);
	device->conn = device_port;
	device->connection_id = malloc(sizeof(char) * (strlen(sp_get_port_name(current_port) + 1)));
	strcpy(device->connection_id, sp_get_port_name(current_port));
	device->priv = dev;
	device->driver = di;

	dev->cfg.divider_numerator = SR_KHZ(1);
	dev->cfg.divider_denominator = SR_MHZ(100);
	dev->cfg.nb_kisamples = 1;

	// Add the 8 logic channels to it
	sr_dbg("Adding logic channels");
	for (i = 0; i < 8; i++) {
		sr_dev_inst_channel_add(device, i, SR_CHANNEL_LOGIC, channel_str[i]);
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
	struct pslela_dev *dev = sdi->priv;
	struct target_config *cfg = &dev->cfg;
	int ret;

	(void)cg;

	ret = SR_OK;
	switch (key) {
		case SR_CONF_SAMPLERATE:
			*data = g_variant_new_uint64(cfg->divider_numerator);
			break;
		case SR_CONF_LIMIT_SAMPLES:
			*data = g_variant_new_uint64(cfg->nb_kisamples * 1000);
			break;
		default:
			return SR_ERR_NA;
	}

	return ret;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct pslela_dev *dev = sdi->priv;
	struct target_config *cfg = &dev->cfg;
	int ret;
	uint64_t samplerate;

	(void)cg;
#define START_PATTERN        0x00000001
#define START_PATTERN_LENGTH 1
#define STOP_PATTERN         0x0000000F
#define STOP_PATTERN_LENGTH  4
#define SYNCHRONOUS_MODE     0
#define TRIGGER_SELECT_LINE  1
	cfg->divider_denominator   = SR_MHZ(100);
	cfg->start_pattern         = START_PATTERN;
	cfg->stop_pattern          = STOP_PATTERN;
	cfg->synchronous_detection = SYNCHRONOUS_MODE;
	cfg->trigger_line_select   = TRIGGER_SELECT_LINE;
	cfg->start_pattern_length  = START_PATTERN_LENGTH;
	cfg->stop_pattern_length   = STOP_PATTERN_LENGTH;

	ret = SR_OK;
	switch (key) {
		case SR_CONF_SAMPLERATE:
			samplerate = g_variant_get_uint64(data);
			if ((samplerate < samplerates[0])
			    || (samplerate > samplerates[NUM_SAMPLERATES - 1])) {
				return SR_ERR_ARG;
			}
			cfg->divider_numerator = samplerate;
			break;
		case SR_CONF_LIMIT_SAMPLES:
			cfg->nb_kisamples = g_variant_get_uint64(data) / 1000;
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
	struct pslela_dev *dev = sdi->priv;
	unsigned char buffer[128];
	unsigned int i;
	struct sr_datafeed_logic packet_contents;
	struct sr_datafeed_packet packet;
	int err;

	sr_dbg("Device acq start");

	err = pslela_start_capture(sdi);
	if (err < 0) {
		return err;
	}

	// Wait for capture to finish
	dev->tx_cmd.code = PSLELA_CMD_READ_CAPTURE;
	dev->tx_cmd.len = 0;

	do {
		if ((err = pslela_send_cmd(sdi)) != SR_OK) {
			return err;
		}
		err = pslela_recv_cmd(sdi);
		if (err != SR_OK && err != SR_ERR_DATA) {
			return err;
		}
	} while (dev->rx_cmd.code == PSLELA_CMD_ERROR);

	// Read capture response
	do {
		sr_dbg("Received %i data characters", dev->rx_cmd.len);

		// Prepare packet
		packet_contents.length = dev->rx_cmd.len / 2;
		packet_contents.unitsize = 1;

		for (i = 0; i < packet_contents.length; i++) {
			hextobyte(&dev->rx_cmd.buff[2 * i], &buffer[i]);
		}
		packet_contents.data = buffer;
		packet.type = SR_DF_LOGIC;
		packet.payload = &packet_contents;

		// Send packet
		if (sr_session_send(sdi, &packet) < 0) {
			sr_err("Failed to send packet");
			return SR_ERR;
		}

		// Read next data
		if ((err = pslela_recv_cmd(sdi)) != SR_OK) {
			return err;
		}
	} while (dev->rx_cmd.len != 0);

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
