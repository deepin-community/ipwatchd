/* IPwatchD - IP conflict detection tool for Linux
 * Copyright (C) 2007-2018 Jaroslav Imrich <jariq(at)jariq(dot)sk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

/** \file devinfo.c
 * \brief Contains logic used for acquiring information about network devices
 */


#include "ipwatchd.h"


extern IPWD_S_CONFIG config;
extern IPWD_S_DEVS devices;


//! Gets the IP and MAC addresses of specified device in human readable form
/*!
 * Based on examples from: http://english.geekpage.jp/programming/linux-network/
 * \param p_dev Name of the device (i.e. eth0)
 * \param p_ip Pointer to string where the IP address should be stored
 * \param p_mac Pointer to string where the MAC address should be stored
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_devinfo (const char *p_dev, char *p_ip, char *p_mac)
{
	struct ifaddrs *ifa, *ifap;
	int found = 0;

	if (getifaddrs (&ifa) == -1)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "getifaddrs error");
		return (IPWD_RV_ERROR);
	}

	/* Get MAC address first */
	for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next)
	{
		if (ifap->ifa_addr != NULL && ifap->ifa_addr->sa_family == AF_PACKET
			&& strcmp (ifap->ifa_name, p_dev) == 0)
		{
			struct sockaddr_ll *s = (struct sockaddr_ll *)ifap->ifa_addr;
			char *p_dev_mac = ether_ntoa((struct ether_addr *)s->sll_addr);
			if (p_dev_mac != NULL)
			{
				memset (p_mac, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
				strncpy (p_mac, p_dev_mac, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);
				found = 1;
				break;
			}
		}
	}

	if (!found)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not retrieve MAC address of the device \"%s\"", p_dev);
		freeifaddrs(ifa);
		return (IPWD_RV_ERROR);
	}

	/* Get all IP addresses */
	found = 0;
	for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next)
	{
		if (ifap->ifa_addr != NULL && ifap->ifa_addr->sa_family == AF_INET
			&& strcmp (ifap->ifa_name, p_dev) == 0)
		{
			struct sockaddr_in *sin = (struct sockaddr_in *)ifap->ifa_addr;
			char *p_dev_ip = inet_ntoa(sin->sin_addr);
			if (p_dev_ip != NULL)
			{
				/* Store first IP for backward compatibility */
				if (!found)
				{
					memset (p_ip, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
					strncpy (p_ip, p_dev_ip, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);
					found = 1;
				}
				ipwd_message (IPWD_MSG_TYPE_DEBUG, "Device %s has IP: %s", p_dev, p_dev_ip);
			}
		}
	}

	freeifaddrs(ifa);

	if (!found)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not retrieve any IP address of the device \"%s\"", p_dev);
		return (IPWD_RV_ERROR);
	}

	ipwd_message (IPWD_MSG_TYPE_DEBUG, "Device info: %s %s-%s", p_dev, p_ip, p_mac);

	return (IPWD_RV_SUCCESS);
}

//! Gets all IP addresses of specified device
/*!
 * \param p_dev Name of the device (i.e. eth0)
 * \param ips Pointer to array where IP addresses should be stored
 * \param ipnum Pointer to number of IP addresses found
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_devinfo_all_ips (const char *p_dev, char *p_mac, IPWD_S_IP **ips, int *ipnum)
{
	struct ifaddrs *ifa, *ifap;
	int count = 0;
	int capacity = 10; /* Initial capacity */

	*ips = (IPWD_S_IP *)malloc(capacity * sizeof(IPWD_S_IP));
	if (*ips == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "malloc failed for IP addresses array");
		return (IPWD_RV_ERROR);
	}

	if (getifaddrs (&ifa) == -1)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "getifaddrs error");
		free(*ips);
		*ips = NULL;
		return (IPWD_RV_ERROR);
	}

	/* Count and collect all IP addresses */
	for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next)
	{
		if (ifap->ifa_addr != NULL && strcmp (ifap->ifa_name, p_dev) == 0)
		{
			if (ifap->ifa_addr->sa_family == AF_PACKET)
			{
				struct sockaddr_ll *s = (struct sockaddr_ll *)ifap->ifa_addr;
				char *p_dev_mac = ether_ntoa((struct ether_addr *)s->sll_addr);
				if (p_dev_mac != NULL)
				{
					memset (p_mac, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
					strncpy (p_mac, p_dev_mac, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);
				}
			} else if (ifap->ifa_addr->sa_family == AF_INET)
			{
				struct sockaddr_in *sin = (struct sockaddr_in *)ifap->ifa_addr;
				char *p_dev_ip = inet_ntoa(sin->sin_addr);
				if (p_dev_ip != NULL)
				{
					/* Resize array if needed */
					if (count >= capacity)
					{
						capacity *= 2;
						IPWD_S_IP *temp = (IPWD_S_IP *)realloc(*ips, capacity * sizeof(IPWD_S_IP));
						if (temp == NULL)
						{
							ipwd_message (IPWD_MSG_TYPE_ERROR, "realloc failed for IP addresses array");
							freeifaddrs(ifa);
							free(*ips);
							*ips = NULL;
							return (IPWD_RV_ERROR);
						}
						*ips = temp;
					}

					/* Store IP address */
					memset ((*ips)[count].ip, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
					strncpy ((*ips)[count].ip, p_dev_ip, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);
					(*ips)[count].time.tv_sec = 0;
					(*ips)[count].time.tv_usec = 0;
					count++;

					ipwd_message (IPWD_MSG_TYPE_DEBUG, "Device %s has IP: %s", p_dev, p_dev_ip);
				}
			}
		}
	}

	freeifaddrs(ifa);
	*ipnum = count;

	if (count == 0)
	{
		free(*ips);
		*ips = NULL;
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not retrieve any IP address of the device \"%s\"", p_dev);
		return (IPWD_RV_ERROR);
	}

	ipwd_message (IPWD_MSG_TYPE_DEBUG, "Device %s has %d IP addresses", p_dev, count);
	return (IPWD_RV_SUCCESS);
}


//! Dynamically updates the devices structure with current network interfaces
/*!
 * This function should be called periodically to detect new network interfaces
 * that may have been added after program startup.
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_update_devices (void)
{
	int sock = -1;

	char ifaces_buf[10240];
	struct ifconf ifc;
	struct ifreq * ifr = NULL;
	struct ifreq * iface = NULL;

	int ifaces_num = 0;
	int i = 0, j = 0;
	int found = 0;

	pcap_t *h_pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	memset (ifaces_buf, 0, sizeof (ifaces_buf));
	memset (&ifc, 0, sizeof (ifc));
	memset (errbuf, 0, PCAP_ERRBUF_SIZE);

	/* Create UDP socket */
	sock = socket (AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not open socket for device update");
		return (IPWD_RV_ERROR);
	}

	/* Set buffer */
	ifc.ifc_len = sizeof (ifaces_buf);
	ifc.ifc_buf = ifaces_buf;

	/* Get current list of interfaces */
	if (ioctl (sock, SIOCGIFCONF, &ifc) < 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not retrieve current list of network interfaces");
		close (sock);
		return (IPWD_RV_ERROR);
	}

	/* Determine number of interfaces */
	ifaces_num = ifc.ifc_len / sizeof (struct ifreq);

	/* Get pointer to array with interfaces */
	ifr = ifc.ifc_req;

	/* Loop through current array with interfaces */
	for (i = 0; i < ifaces_num; i++)
	{
		iface = &ifr[i];

		/* Skip loopback devices */
		if (ioctl(sock, SIOCGIFFLAGS, iface) < 0)
		{
			continue;
		}

		if (iface->ifr_ifru.ifru_flags & IFF_LOOPBACK)
		{
			continue;
		}

		/* Check if device is valid ethernet device */
		h_pcap = pcap_open_live (iface->ifr_name, BUFSIZ, 0, 0, errbuf);
		if (h_pcap == NULL)
		{
			continue;
		}

		if (pcap_datalink (h_pcap) != DLT_EN10MB)
		{
			pcap_close (h_pcap);
			continue;
		}

		pcap_close (h_pcap);

		/* Check if this interface is already in our devices list */
		found = 0;
		for (j = 0; j < devices.devnum; j++)
		{
			if (strcasecmp (iface->ifr_name, devices.dev[j].device) == 0)
			{
				found = 1;
				break;
			}
		}

		/* If interface is not in our list, add it */
		if (!found)
		{
			ipwd_message (IPWD_MSG_TYPE_DEBUG, "New network interface detected: %s", iface->ifr_name);
			/* Put new interface into devices structure */
			IPWD_S_DEV *temp_dev = (IPWD_S_DEV *) realloc(devices.dev, (devices.devnum + 1) * sizeof(IPWD_S_DEV));
			if (temp_dev == NULL) {
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to resize devices structure for new interface");
				close (sock);
				return (IPWD_RV_ERROR);
			}
			devices.dev = temp_dev;

			/* Initialize the new device structure */
			memset (&devices.dev[devices.devnum], 0, sizeof(IPWD_S_DEV));
			strncpy (devices.dev[devices.devnum].device, iface->ifr_name, IPWD_MAX_DEVICE_NAME_LEN - 1);
			devices.dev[devices.devnum].mode = IPWD_PROTECTION_MODE_ACTIVE;
			devices.dev[devices.devnum].ips = NULL;
			devices.dev[devices.devnum].ipnum = 0;
			j = devices.devnum;
			devices.devnum = devices.devnum + 1;
		}

		/* Refresh device network info. This runs for both newly added
		 * interfaces and existing ones, so a device that first appeared
		 * without an IPv4 address becomes USABLE once DHCP assigns one. */
		IPWD_S_DEV *dev = &devices.dev[j];

		/* Free the previously fetched IP list before refreshing it */
		if (dev->ips != NULL)
		{
			free (dev->ips);
			dev->ips = NULL;
		}
		dev->ipnum = 0;

		/* Try to get current IP and MAC info */
		char ip[IPWD_MAX_DEVICE_ADDRESS_LEN];
		char mac[IPWD_MAX_DEVICE_ADDRESS_LEN];
		if (ipwd_devinfo (iface->ifr_name, ip, mac) == IPWD_RV_SUCCESS)
		{
			dev->state = IPWD_DEVICE_STATE_USABLE;
			memset (dev->mac, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
			strncpy (dev->mac, mac, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);

			/* Get all IP addresses for this interface */
			if (ipwd_devinfo_all_ips (iface->ifr_name, dev->mac, &dev->ips, &dev->ipnum) == IPWD_RV_SUCCESS)
			{
				ipwd_message (IPWD_MSG_TYPE_DEBUG, "Device %s has %d IP addresses and MAC %s (USABLE)",
					dev->device, dev->ipnum, mac);
			}
			else
			{
				/* Fallback: store at least the first IP address */
				dev->ips = (IPWD_S_IP *)malloc(sizeof(IPWD_S_IP));
				if (dev->ips != NULL)
				{
					memset (dev->ips[0].ip, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
					strncpy (dev->ips[0].ip, ip, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);
					dev->ips[0].time.tv_sec = 0;
					dev->ips[0].time.tv_usec = 0;
					dev->ipnum = 1;
					ipwd_message (IPWD_MSG_TYPE_DEBUG, "Device %s has IP %s and MAC %s (USABLE)",
						dev->device, ip, mac);
				}
				else
				{
					dev->state = IPWD_DEVICE_STATE_UNUSABLE;
					ipwd_message (IPWD_MSG_TYPE_ERROR, "malloc failed for fallback IP entry on device %s",
						dev->device);
				}
			}
		}
		else
		{
			dev->state = IPWD_DEVICE_STATE_UNUSABLE;
			memset (dev->mac, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
			ipwd_message (IPWD_MSG_TYPE_DEBUG, "Device %s (UNUSABLE - no IP address)",
				dev->device);
		}
	}

	/* Close socket */
	close (sock);

	return (IPWD_RV_SUCCESS);
}


//! Gets list of available network interfaces and fills devices structure with acquired information
/*!
 * Based on example from: http://www.doctort.org/adam/nerd-notes/enumerating-network-interfaces-on-linux.html
 * See netdevice(7) manual page for more information.
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int ipwd_fill_devices (void)
{

	int sock = -1;

	char ifaces_buf[10240];
	struct ifconf ifc;
	struct ifreq * ifr = NULL;
	struct ifreq * iface = NULL;

	int ifaces_num = 0;
	int i = 0;

	pcap_t *h_pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	memset (ifaces_buf, 0, sizeof (ifaces_buf));
	memset (&ifc, 0, sizeof (ifc));
	memset (errbuf, 0, PCAP_ERRBUF_SIZE);

	/* Verify that devices structure is empty and configuration mode is automatic */
	if ((devices.dev != NULL) || (devices.devnum != 0) || (config.mode != IPWD_CONFIGURATION_MODE_AUTOMATIC))
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Cannot proceed with automatic configuration. Please check that configuration file does not contain iface variables");
		return (IPWD_RV_ERROR);
	}

	/* Create UDP socket */
	sock = socket (AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not open socket");
		return (IPWD_RV_ERROR);
	}

	/* Set buffer */
	ifc.ifc_len = sizeof (ifaces_buf);
	ifc.ifc_buf = ifaces_buf;

	/* Get list of interfaces */
	if (ioctl (sock, SIOCGIFCONF, &ifc) < 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not retrieve list of network interfaces");
		close (sock);
		return (IPWD_RV_ERROR);
	}

	/* Determine number of interfaces */
	ifaces_num = ifc.ifc_len / sizeof (struct ifreq);

	/* Get pointer to array with interfaces */
	ifr = ifc.ifc_req;

	/* Loop through array with interfaces */
	for (i = 0; i < ifaces_num; i++)
	{
		iface = &ifr[i];

		/* Skip loopback devices */
		if (ioctl(sock, SIOCGIFFLAGS, iface) < 0)
		{
			ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not get interface flags for device \"%s\"", iface->ifr_name);
			continue;
		}

		if (iface->ifr_ifru.ifru_flags & IFF_LOOPBACK)
		{
			ipwd_message (IPWD_MSG_TYPE_DEBUG, "Skipping loopback device \"%s\"", iface->ifr_name);
			continue;
		}

		/* Check if device is valid ethernet device */
		h_pcap = pcap_open_live (iface->ifr_name, BUFSIZ, 0, 0, errbuf);
		if (h_pcap == NULL)
		{
			ipwd_message (IPWD_MSG_TYPE_ERROR, "IPwatchD is unable to work with device \"%s\"", iface->ifr_name);
			continue;
		}

		if (pcap_datalink (h_pcap) != DLT_EN10MB)
		{
			ipwd_message (IPWD_MSG_TYPE_ERROR, "Device \"%s\" is not valid ethernet device", iface->ifr_name);
			pcap_close (h_pcap);
			continue;
		}

		pcap_close (h_pcap);

		/* Put read values into devices structure */
		if ((devices.dev = (IPWD_S_DEV *) realloc (devices.dev, (devices.devnum + 1) * sizeof (IPWD_S_DEV))) == NULL)
		{
			ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to resize devices structure");
			close (sock);
			return (IPWD_RV_ERROR);
		}

		memset (devices.dev[devices.devnum].device, '\0', IPWD_MAX_DEVICE_NAME_LEN);
		strncpy (devices.dev[devices.devnum].device, iface->ifr_name, IPWD_MAX_DEVICE_NAME_LEN - 1);
        devices.dev[devices.devnum].mode = IPWD_PROTECTION_MODE_ACTIVE;

		/* Initialize IP addresses array to NULL - will be populated later */
		devices.dev[devices.devnum].ips = NULL;
		devices.dev[devices.devnum].ipnum = 0;

		ipwd_message (IPWD_MSG_TYPE_DEBUG, "Found device %s", devices.dev[devices.devnum].device);

		devices.devnum = devices.devnum + 1;

	}

	/* Close socket */
	close (sock);

	return (IPWD_RV_SUCCESS);

}
