/**
 * @file main.c
 * SSL Socket Example with client authentication
 * @author Ajay Bhargav
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <lib.h>
#include <ril.h>
#include <os_api.h>

#include <network.h>
#include <net/sockets.h>

/**
 * Server IP
 */
#define SERVER_IP "tcpbin.com"
/**
 * Server Port
 */
#define SERVER_PORT 4244

int socket_id;

/**
 * Root Certificate for peer validation
 */
const char root_ca[] = 
"-----BEGIN CERTIFICATE-----\n"
"MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\n"
"TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n"
"cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4\n"
"WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu\n"
"ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY\n"
"MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc\n"
"h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+\n"
"0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U\n"
"A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW\n"
"T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH\n"
"B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC\n"
"B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv\n"
"KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn\n"
"OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn\n"
"jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw\n"
"qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI\n"
"rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\n"
"HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq\n"
"hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL\n"
"ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ\n"
"3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK\n"
"NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5\n"
"ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur\n"
"TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC\n"
"jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc\n"
"oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq\n"
"4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA\n"
"mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d\n"
"emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=\n"
"-----END CERTIFICATE-----\n";

/*
 * Please update Client certificate and privatekey,
 * visit tcpbin.com for more information
 */

/**
 * SSL Client certificate
 */
const char client_cert[] = 
"-----BEGIN CERTIFICATE-----\n"
"MIIDZTCCAk2gAwIBAgIBKjANBgkqhkiG9w0BAQsFADCBizELMAkGA1UEBhMCVVMx\n"
"CzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQKDAZ0\n"
"Y3BiaW4xDDAKBgNVBAsMA29wczETMBEGA1UEAwwKdGNwYmluLmNvbTEjMCEGCSqG\n"
"SIb3DQEJARYUaGFycnliYWdkaUBnbWFpbC5jb20wHhcNMjMwMzMxMTYzMzIxWhcN\n"
"MjMwNDAxMTYzMzIxWjAcMRowGAYDVQQDDBF0Y3BiaW4uY29tLWNsaWVudDCCASIw\n"
"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcuv6RWF4Yv0Hm7lcNcJ2oy6GI0\n"
"RhJqNOWuOuSVmI+KyLHylJWZBEmFN5apYB0Ddf7MsZUkE/nkiA3odfsbLKniBi1g\n"
"PFsuzFpK7CoEq1Rl2CoNJKoRxKDYIXWjK26ds9msmKpS+ZK8cO5NfHYjcTXqoHGb\n"
"5XX7yfO5KydAFcVURSO5ucf1gjKVGocwjbm+5gA8P/sz7QOgXVjXrSZF7XFPJS6a\n"
"zQW51B/lxxp2uZE6oE6JO0uFiMpqbCV0RsErwz+ibaEEPq+TsIo4P6x97Zt81Jcr\n"
"PmDorlKuQrRSvQ51n5FyithIfUOYICF+BOJwFmBoHv6pMG8UwIc6Fb2vr9ECAwEA\n"
"AaNCMEAwHQYDVR0OBBYEFH6MlHFNtl4sxBzM5TMr1MTX8taoMB8GA1UdIwQYMBaA\n"
"FOLuMowBSAZfV5v82LmlaIIOvU/DMA0GCSqGSIb3DQEBCwUAA4IBAQCfOSRZPv8U\n"
"ZF35C0ijfC19hV89xgsRPoDEndQ9CbQMO6PWnGibteKPkLBdHl7wkLriv89h9pj1\n"
"icxCUlzZ56scRb3/kIImZUQYY7y1oavtvSdD7/uTi2l3FxPmQj2QoGkP5QwZDO4e\n"
"5IxiWGJ0tAo2qJIg9rXZQ7gtGDJZFUqc1Zn9HoCYoyVU37E83LGeFf6NVVkkYEkX\n"
"7p1LUkMfTUbmYNVpVVASsOk9vaGme3EswERIeudslbFkZbeXqXPAr3LcJtF92QcM\n"
"ohiaTx3WXCzskzXySAgKls/mm/FpqvWpkp2Q/3DXcQrxlg3Bw0f6Edp7VrQrJVFg\n"
"B5eLvVMZQzEd\n"
"-----END CERTIFICATE-----\n";

/**
 * SSL Client private key
 */
const char client_key[] = 
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDnLr+kVheGL9B5\n"
"u5XDXCdqMuhiNEYSajTlrjrklZiPisix8pSVmQRJhTeWqWAdA3X+zLGVJBP55IgN\n"
"6HX7Gyyp4gYtYDxbLsxaSuwqBKtUZdgqDSSqEcSg2CF1oytunbPZrJiqUvmSvHDu\n"
"TXx2I3E16qBxm+V1+8nzuSsnQBXFVEUjubnH9YIylRqHMI25vuYAPD/7M+0DoF1Y\n"
"160mRe1xTyUums0FudQf5ccadrmROqBOiTtLhYjKamwldEbBK8M/om2hBD6vk7CK\n"
"OD+sfe2bfNSXKz5g6K5SrkK0Ur0OdZ+RcorYSH1DmCAhfgTicBZgaB7+qTBvFMCH\n"
"OhW9r6/RAgMBAAECggEAN7aqdL5SuQH46f1tIEGrNgrCujgC0xlJWjjc9I2g0KcP\n"
"quLdMBhKUjWKqgJzqUpWO2u1OE4Tiluq9j8Zf8SSxPY1quXQZeEnWnNH6vBpIdPR\n"
"foDgXyQdEO5FUgZaxzO2TjUsLZAFmXlUdfmyjv4HoIjE1dxONlrR1qy/W5w0IvOw\n"
"w3aA5wlSO4MJnQqkq3KuycH6qeywD2n6GhNDIgcBp5XPd8wQoxe8/2dZNyBxHf4G\n"
"6mHsnIU+NhvxPdKR3uNxBxf+qRPvcIdnQKXx2CjWSTr6ykSmNhitgoyG/B5FKK9P\n"
"6qe64LKMZP0sovD6RPLbMZ0wu7O6bd1RNk5xx+cA4QKBgQD9UdkTDdIikXLWUNrX\n"
"s7xEf2HOTzuL67WO1Q16jasVTJyW+pUXsiaisT8qjycBh/UiuC/XrTNPvHAn4xMs\n"
"Ch/l3D7MHgkP47Mpz/xP1WdiBWms/XBXAS59rdpc4ZtL966cOgztrGZ6G7CMhF5n\n"
"HJTgpHs3IZj3lnNkSwBK5Wsw1QKBgQDpoPBuv+/wZFSoQEAX49pVDle6+BB3M08t\n"
"wZZwnz+Hm+ejWH/ZlS6A1hbMSYrHhlGyfF6HAtFBM60wS0PFh+wxwxGWJe8ElNni\n"
"XtzQ+icSJk/GXE7p7D4BZFEJT0a0sjYIZicOVWLrJGDKjzC2intZc03kky07xTdn\n"
"IjM+HYfhDQKBgEPg37LsXCdpJAVriwiLn+IW5AVdU85tbawFSORS+8nsSnVmVfcQ\n"
"hKvJpOxpiYEuhjA0fJVlUr+F9eOqRCPj3qJAPw+A6Nq6H/MPSUO3Ikmwu51gF+8o\n"
"YOXKZR3IUk2r47z3DSnOrXMA4nD0szsb/ISpbl7agNuvE+KG+mAXU361AoGASsBE\n"
"zZq6AbeIYsEUANDVpctOBLOkSQ9wsRo0sVoysIgQqHIDjjGuTGizqK+LKOXwM+SZ\n"
"NiePnoYTTtV2HLituQpKETmX7WZXBJgHnRG8+JCri7MzSKNe/4ECcLEd1WkD4tIU\n"
"gwCNAuGD2qvQEUfjya4b6RuyKGKkpGoL7T7zn+0CgYBF2LdNRktvH5XVlH4vGPUx\n"
"IXp049jWAwjay7/u4iwbXqLa91hnBvddQ0QWNcoPBccKA9rn7XsStA1uCds8adZ6\n"
"WLyyXChBcVJjuNVSLWpWwI3A+AzKn7P7k+Yh2Tki/ijUGk0mDOBrExUC9z+bxUwG\n"
"j4t1p7Jp+pe0MgQtwHWsVg==\n"
"-----END PRIVATE KEY-----\n";

/**
 * SSl Client certificate and privatekey
 */
const struct ssl_certs_t certs = {
	.rootca = root_ca,
	.rootca_len = sizeof(root_ca),
	.cert = client_cert,
	.cert_len = sizeof(client_cert),
	.privatekey = client_key,
	.privatekey_len = sizeof(client_key),
};

/**
 * URC Handler
 * @param param1	URC Code
 * @param param2	URC Parameter
 */
static void urc_callback(unsigned int param1, unsigned int param2)
{
	switch (param1)
	{
	case URC_SYS_INIT_STATE_IND:
		if (param2 == SYS_STATE_SMSOK)
		{
			/* Ready for SMS */
		}
		break;
	case URC_SIM_CARD_STATE_IND:
		switch (param2)
		{
		case SIM_STAT_NOT_INSERTED:
			debug(DBG_OFF, "SYSTEM: SIM card not inserted!\n");
			break;
		case SIM_STAT_READY:
			debug(DBG_INFO, "SYSTEM: SIM card Ready!\n");
			break;
		case SIM_STAT_PIN_REQ:
			debug(DBG_OFF, "SYSTEM: SIM PIN required!\n");
			break;
		case SIM_STAT_PUK_REQ:
			debug(DBG_OFF, "SYSTEM: SIM PUK required!\n");
			break;
		case SIM_STAT_NOT_READY:
			debug(DBG_OFF, "SYSTEM: SIM card not recognized!\n");
			break;
		default:
			debug(DBG_OFF, "SYSTEM: SIM ERROR: %d\n", param2);
		}
		break;
	case URC_GSM_NW_STATE_IND:
		debug(DBG_OFF, "SYSTEM: GSM NW State: %d\n", param2);
		break;
	case URC_GPRS_NW_STATE_IND:
		break;
	case URC_CFUN_STATE_IND:
		break;
	case URC_COMING_CALL_IND:
		debug(DBG_OFF, "Incoming voice call from: %s\n", ((struct ril_callinfo_t *)param2)->number);
		/* Take action here, Answer/Hang-up */
		break;
	case URC_CALL_STATE_IND:
		switch (param2)
		{
		case CALL_STATE_BUSY:
			debug(DBG_OFF, "The number you dialed is busy now\n");
			break;
		case CALL_STATE_NO_ANSWER:
			debug(DBG_OFF, "The number you dialed has no answer\n");
			break;
		case CALL_STATE_NO_CARRIER:
			debug(DBG_OFF, "The number you dialed cannot reach\n");
			break;
		case CALL_STATE_NO_DIALTONE:
			debug(DBG_OFF, "No Dial tone\n");
			break;
		default:
			break;
		}
		break;
	case URC_NEW_SMS_IND:
		debug(DBG_OFF, "SMS: New SMS (%d)\n", param2);
		/* Handle New SMS */
		break;
	case URC_MODULE_VOLTAGE_IND:
		debug(DBG_INFO, "VBatt Voltage: %d\n", param2);
		break;
	case URC_ALARM_RING_IND:
		break;
	case URC_FILE_DOWNLOAD_STATUS:
		break;
	case URC_FOTA_STARTED:
		break;
	case URC_FOTA_FINISHED:
		break;
	case URC_FOTA_FAILED:
		break;
	case URC_STKPCI_RSP_IND:
		break;
	default:
		break;
	}
}

static void socket_init(void)
{
	struct ssl_sockopt_t sockopt;

	socket_id = ssl_socket_request((struct ssl_certs_t *)&certs);

	strcpy(sockopt.server_ip, SERVER_IP);
	sockopt.port = SERVER_PORT;
	sockopt.arg = NULL;
	sockopt.timeout = 30; /* handshake timeout 30s */
	ssl_socket_setopt(socket_id, &sockopt);
}

/**
 * SSL Socket Task
 * @param arg	Task Argument
 */
static void socket_task(void *arg)
{
	int ret;
	unsigned char buffer[] = "Hello World\n";
	unsigned char recv_buffer[128];

	/* Setup and initialize socket */
	socket_init();

	while (1)
	{
		/* Wait for GPRS */
		if (!network_isready())
		{
			printf("Waiting for data connection...\n");
			sleep(1);
			continue;
		}

		/* Check if socket not connected */
		if (ssl_socket_getstatus(socket_id) != SOCK_STA_CONNECTED)
		{
			/* Initiate SSL socket connection */
			ret = ssl_socket_open(socket_id);
			if (ret < 0)
			{
				printf("SSL socket open fail: %s\n", strerror(-ret));
				/* retry after 10s */
				sleep(10);
				continue;
			}
		}

		ret = ssl_socket_send(socket_id, buffer, strlen((char *)buffer), 0);
		printf("Socket send status: %d\n", ret);

		memset(recv_buffer, 0, sizeof(recv_buffer));
		ret = ssl_socket_read(socket_id, recv_buffer, sizeof(recv_buffer), 10000);
		if (ret < 0)
			printf("SSL socket read error: %s\n", strerror(-ret));
		else
			printf("SSL socket read (%d bytes):\n%s\n", ret, recv_buffer);
	}
}

/**
 * Application main entry point
 */
int main(void)
{
	int timeout = 0;

	/*
	 * Initialize library and Setup STDIO
	 */
#ifdef PLATFORM_EC200U
	logicrom_init("/dev/ttyUSB0", urc_callback);
#else
	logicrom_init("/dev/ttyS0", urc_callback);
#endif
	/* Start GPRS service */
	network_gprsenable(TRUE);

	printf("Waiting for network!\n");
	/* wait for network GPRS ready */
	while (!network_isgprsenable()) {
		sleep(1);
		if (++timeout > 120) {
			printf("Data connection fail!, rebooting...\n");
			sys_reset();
		}
	}

	printf("System Initialized\n");

	/* Create Application tasks */
	os_task_create(socket_task, "soctest", NULL, FALSE);

	while (1) {
		/* Main task loop */
		sleep(1);
	}
}
