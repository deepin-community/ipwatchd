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

/** \file analyse.c
 * \brief Contains logic used for analysing of captured ARP packets
 */


#include "ipwatchd.h"


extern IPWD_S_DEVS devices;
extern IPWD_S_CONFIG config;
extern int testing_flag;
extern IPWD_S_CHECK_CONTEXT check_context;
extern IPCONFLICT_DEV_INFO *ipconflict_dev_info;

static int ipwd_run_user_script (const char *script, const char *device, const char *ip, const char *mac)
{
	pid_t pid;
	pid_t wait_rv;
	int status;
	int waited = 0;
	char *const argv[] = {
		(char *) script,
		(char *) device,
		(char *) ip,
		(char *) mac,
		NULL
	};

	pid = fork ();
	if (pid < 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to execute user-defined script %s - fork failed: %s", script, strerror (errno));
		return (IPWD_RV_ERROR);
	}

	if (pid == 0)
	{
		execv (script, argv);
		_exit (127);
	}

	while ((wait_rv = waitpid (pid, &status, WNOHANG)) == 0)
	{
		if (waited >= IPWD_SCRIPT_TIMEOUT_SECONDS)
		{
			if (kill (pid, SIGKILL) != 0)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to terminate timed out user-defined script %s - %s", script, strerror (errno));
			}
			else
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "User-defined script %s timed out after %d seconds", script, IPWD_SCRIPT_TIMEOUT_SECONDS);
			}

			waitpid (pid, &status, 0);
			return (IPWD_RV_ERROR);
		}

		sleep (1);
		waited++;
	}

	if (wait_rv < 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to execute user-defined script %s - waitpid failed: %s", script, strerror (errno));
		return (IPWD_RV_ERROR);
	}

	if (WIFEXITED (status) && WEXITSTATUS (status) == 0)
	{
		return (IPWD_RV_SUCCESS);
	}

	if (WIFEXITED (status))
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "User-defined script %s exited with status %d", script, WEXITSTATUS (status));
	}
	else if (WIFSIGNALED (status))
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "User-defined script %s terminated by signal %d", script, WTERMSIG (status));
	}
	else
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "User-defined script %s did not complete successfully", script);
	}

	return (IPWD_RV_ERROR);
}

//! Callback for "pcap_loop" with standard parameters. Called when ARP packet is received (detection of conflict is done here).
/*!
 * \param args Last parameter of pcap_loop
 * \param header Packet header
 * \param packet Packet data
 */
void ipwd_analyse (u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
	struct timeval current_time;
	double difference = 0.0;
	int i = 0;

	/* Get addresses from packet */
	IPWD_S_ARP_HEADER *arpaddr;
	arpaddr = (IPWD_S_ARP_HEADER *) (packet + IPWD_ARP_HEADER_SIZE);

    /* Check Local MAC */
    if (ipwd_local_mac((const struct ether_addr *) &arpaddr->arp_sha) == 0)
	{
		ipwd_message (IPWD_MSG_TYPE_DEBUG, "ARP packet ignored because it comes from local machine.");
		return;
	}

	/* Source IP address */
	char rcv_sip[IPWD_MAX_DEVICE_ADDRESS_LEN];
	char *p_rcv_sip = NULL;

	/* Following variable was added because gcc 4.4.1 displayed warning: dereferencing type-punned pointer will break strict-aliasing rules */
	struct in_addr * p_arp_spa = (struct in_addr *) &arpaddr->arp_spa;

	if ((p_rcv_sip = inet_ntoa (*(p_arp_spa))) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not get source IP address from packet");
		return;
	}

	memset (rcv_sip, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
	strncpy (rcv_sip, p_rcv_sip, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);

	/* Source MAC address */
	char rcv_smac[IPWD_MAX_DEVICE_ADDRESS_LEN];
	char *p_rcv_smac = NULL;

	if ((p_rcv_smac = ether_ntoa ((const struct ether_addr *) &arpaddr->arp_sha)) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not get source MAC address from packet");
		return;
	}

	memset (rcv_smac, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
	strncpy (rcv_smac, p_rcv_smac, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);

	/* Destination IP address */
	char rcv_dip[IPWD_MAX_DEVICE_ADDRESS_LEN];
	char *p_rcv_dip = NULL;

	/* Following variable was added because gcc 4.4.1 displayed warning: dereferencing type-punned pointer will break strict-aliasing rules */
	struct in_addr * p_arp_tpa = (struct in_addr *) &arpaddr->arp_tpa;

	if ((p_rcv_dip = inet_ntoa (*(p_arp_tpa))) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not get destination IP address from packet");
		return;
	}

	memset (rcv_dip, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
	strncpy (rcv_dip, p_rcv_dip, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);

	/* Destination MAC address */
	char rcv_dmac[IPWD_MAX_DEVICE_ADDRESS_LEN];
	char *p_rcv_dmac = NULL;

	if ((p_rcv_dmac = ether_ntoa ((const struct ether_addr *) &arpaddr->arp_tha)) == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Could not get destination MAC address from packet");
		return;
	}

	memset (rcv_dmac, '\0', IPWD_MAX_DEVICE_ADDRESS_LEN);
	strncpy (rcv_dmac, p_rcv_dmac, IPWD_MAX_DEVICE_ADDRESS_LEN - 1);

	ipwd_message (IPWD_MSG_TYPE_DEBUG, "Received ARP packet: S:%s-%s D:%s-%s", rcv_sip, rcv_smac, rcv_dip, rcv_dmac);

	/* Update devices structure with actual IP and MAC addresses of interfaces */
	for (i = 0; i < devices.devnum; i++)
	{
		if (devices.dev[i].ips != NULL)
		{
			free(devices.dev[i].ips);
			devices.dev[i].ips = NULL;
			devices.dev[i].ipnum = 0;
		}

		if (ipwd_devinfo_all_ips (devices.dev[i].device, devices.dev[i].mac, &devices.dev[i].ips, &devices.dev[i].ipnum) == IPWD_RV_ERROR)
		{
			devices.dev[i].state = IPWD_DEVICE_STATE_UNUSABLE;
			continue;
		}
		else
		{
			devices.dev[i].state = IPWD_DEVICE_STATE_USABLE;
		}

		/* Ignore packets coming from local interfaces */
		if (strcasecmp (rcv_smac, devices.dev[i].mac) == 0)
		{
			int j;
			int is_local_ip = 0;
			for (j = 0; j < devices.dev[i].ipnum; j++)
			{
				if (strcasecmp (rcv_sip, devices.dev[i].ips[j].ip) == 0)
				{
					is_local_ip = 1;
					break;
				}
			}
			
			if (is_local_ip)
			{
				ipwd_message (IPWD_MSG_TYPE_DEBUG, "ARP packet ignored because it comes from local interface.");
			}
			else
			{
				/* Happens when there is more than one interface connected to the same subnet */
				ipwd_message (IPWD_MSG_TYPE_DEBUG, "ARP packet ignored because it comes from local machine.");
			}

			return;
		}
	}

    /* Check ip conflict */
    if (check_context.stage > 2) {
      if (strcasecmp (rcv_sip, check_context.ip) == 0 && strcasecmp (rcv_smac, check_context.dev.mac) != 0) {
        ipwd_message (IPWD_MSG_TYPE_DEBUG, "IP conflict with: %s %s-%s",
          check_context.ip, check_context.dev.mac, rcv_smac);
        ipwd_reply_to_method(check_context.msg, check_context.conn, rcv_smac);
        check_context.stage = -1;
      }
    }

	/* Search through devices structure */
	for (i = 0; i < devices.devnum; i++)
	{
		/* Skip devices that are currently unusable */
		if (devices.dev[i].state == IPWD_DEVICE_STATE_UNUSABLE)
			continue;

		/* Check if this device has any IP addresses */
		if (devices.dev[i].ipnum == 0)
			continue;

		int conflict_found = 0;
		int j;

		/* Check all IP addresses of this device */
		int conflict_ip_index = -1;
		for (j = 0; j < devices.dev[i].ipnum; j++)
		{
			if (testing_flag == 0)
			{
				/* Check if received packet causes conflict with this IP address of this interface */
				if (!((strcasecmp (rcv_sip, devices.dev[i].ips[j].ip) == 0) && (strcasecmp (rcv_smac, devices.dev[i].mac) != 0)))
				{
					IPCONFLICT_DEV_INFO *pre = ipconflict_dev_info;
					IPCONFLICT_DEV_INFO *info = pre->next;
					while (info)
					{
						if (strcasecmp(info->ip, devices.dev[i].ips[j].ip) == 0
							&& strcasecmp(info->mac , devices.dev[i].mac) == 0
							&& strcasecmp(info->remote_mac, rcv_smac) == 0)
						{
							ipwd_send_signal(check_context.conn, devices.dev[i].ips[j].ip, devices.dev[i].mac, rcv_smac, 0);
							pre->next = info->next;
							free(info);
							break;
						}
						pre = info;
						info = info->next;
					}

					ipwd_message (IPWD_MSG_TYPE_DEBUG, "Packet does not conflict with: %s %s-%s", devices.dev[i].device, devices.dev[i].ips[j].ip, devices.dev[i].mac);
					continue;
				}
			}

			/* Conflict found with this IP address */
			conflict_found = 1;
			conflict_ip_index = j;
			break;
		}

		/* If no conflict found with any IP address of this device, skip to next device */
		if (!conflict_found || conflict_ip_index == -1)
			continue;

		/* Get current system time */
		if (gettimeofday (&current_time, NULL) != 0)
		{
			ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to get current time");
			break;
		}

		difference = ((current_time.tv_sec + (current_time.tv_usec / 1000000.0)) - (devices.dev[i].ips[conflict_ip_index].time.tv_sec + (devices.dev[i].ips[conflict_ip_index].time.tv_usec / 1000000.0)));

		/* Check if current time is within the defend interval */
		if (difference < config.defend_interval)
		{
			ipwd_message (IPWD_MSG_TYPE_INFO, "MAC address %s causes IP conflict with address %s set on interface %s - no action taken because this happened within the defend interval", rcv_smac, devices.dev[i].ips[conflict_ip_index].ip, devices.dev[i].device);
			break;
		}

		/* Store conflict time for this specific IP address */
		devices.dev[i].ips[conflict_ip_index].time.tv_sec = current_time.tv_sec;
		devices.dev[i].ips[conflict_ip_index].time.tv_usec = current_time.tv_usec;

		/* Handle IP conflict */
		if (devices.dev[i].mode == IPWD_PROTECTION_MODE_ACTIVE)
		{
			ipwd_message (IPWD_MSG_TYPE_ALERT, "MAC address %s causes IP conflict with address %s set on interface %s - active mode - reply sent", rcv_smac, devices.dev[i].ips[conflict_ip_index].ip, devices.dev[i].device);

			/* Send reply to conflicting system */
			ipwd_genarp (devices.dev[i].device, devices.dev[i].ips[conflict_ip_index].ip, devices.dev[i].mac, rcv_sip, rcv_smac, ARPOP_REPLY);

			/* Send GARP request to update cache of our neighbours */
			ipwd_genarp (devices.dev[i].device, devices.dev[i].ips[conflict_ip_index].ip, devices.dev[i].mac, devices.dev[i].ips[conflict_ip_index].ip, "ff:ff:ff:ff:ff:ff", ARPOP_REQUEST);
		}
		else
		{
			ipwd_message (IPWD_MSG_TYPE_ALERT, "MAC address %s causes IP conflict with address %s set on interface %s - passive mode - reply not sent", rcv_smac, devices.dev[i].ips[conflict_ip_index].ip, devices.dev[i].device);
		}

        ipwd_send_signal(check_context.conn, devices.dev[i].ips[conflict_ip_index].ip, devices.dev[i].mac, rcv_smac, 1);

		/* Add ipConflict info to list record*/
		int exist = 0;
		IPCONFLICT_DEV_INFO *tail = ipconflict_dev_info;
		IPCONFLICT_DEV_INFO *info = ipconflict_dev_info->next;
		while (info)
		{
			if (strcasecmp(info->ip, devices.dev[i].ips[conflict_ip_index].ip) == 0
				&& strcasecmp(info->mac , devices.dev[i].mac) == 0
				&& strcasecmp(info->remote_mac, rcv_smac) == 0)
			{
				exist = 1;
			}
			if (info != NULL)
			{
				tail = info;
			}
			info = info->next;
		}
		
		if (exist == 0)
		{
			IPCONFLICT_DEV_INFO *newdevinfo = (IPCONFLICT_DEV_INFO *)malloc(sizeof(IPCONFLICT_DEV_INFO));			
			memcpy (newdevinfo->ip, devices.dev[i].ips[conflict_ip_index].ip, IPWD_MAX_DEVICE_ADDRESS_LEN);
			memcpy (newdevinfo->mac, devices.dev[i].mac, IPWD_MAX_DEVICE_ADDRESS_LEN);
			memcpy (newdevinfo->remote_mac, rcv_smac, IPWD_MAX_DEVICE_ADDRESS_LEN);
			ipwd_message (IPWD_MSG_TYPE_DEBUG, "Conflicted ip:%s mac %s remote_mac %s", newdevinfo->ip, newdevinfo->mac, newdevinfo->remote_mac);
			newdevinfo->next = NULL;
			tail->next = newdevinfo;
		}

		if (config.script != NULL)
		{
			/* Run user-defined script in form: script "dev" "ip" "mac" */
			ipwd_message (IPWD_MSG_TYPE_DEBUG, "Running user-defined script: %s", config.script);
			if (ipwd_run_user_script (config.script, devices.dev[i].device, devices.dev[i].ips[conflict_ip_index].ip, rcv_smac) == IPWD_RV_ERROR)
			{
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to execute user-defined script: %s", config.script);
			}
		}
		else
		{
			ipwd_message (IPWD_MSG_TYPE_DEBUG, "No user-defined script specified");
		}

		if (testing_flag == 1)
		{
			break;
		}

	}
}
