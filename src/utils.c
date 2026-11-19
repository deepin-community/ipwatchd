#include "ipwatchd.h"

int ipwd_local_mac(const struct ether_addr *mac) {
  struct ifaddrs *ifa, *ifap;
  struct sockaddr_ll *s;

  if (getifaddrs (&ifa) == -1) {
    ipwd_message (IPWD_MSG_TYPE_ERROR, "getifaddr error");
    return 1;
  }

  for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next) {
    if (strcmp (ifap->ifa_name, "lo") == 0) {
      continue; /* skip the lookback card */
    }

    if (ifap->ifa_addr == NULL)
      continue; /* if addr is NULL, this must be no ip address */

    switch (ifap->ifa_addr->sa_family) {
    case AF_INET:
      break;
    case AF_PACKET:
      s = (struct sockaddr_ll *)ifap->ifa_addr;
      if (memcmp(s->sll_addr, mac, sizeof(struct ether_addr)) == 0) {
        freeifaddrs(ifa);
        return 0;
      }
      break;
    default:
      break;
    }
  }

  freeifaddrs(ifa);

  return 1;
}

int ipwd_local_mac_by_interface(const char *interface, char **mac)
{
  struct ifaddrs *ifa, *ifap;
  struct sockaddr_ll *s;

  if (interface == NULL) {
    ipwd_message (IPWD_MSG_TYPE_ERROR, "interface is NULL");
    return 1;
  }

  if (getifaddrs (&ifa) == -1) {
    ipwd_message (IPWD_MSG_TYPE_ERROR, "getifaddr error");
    return 1;
  }

  for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next) {
    if (ifap->ifa_addr != NULL && ifap->ifa_addr->sa_family == AF_PACKET
      &&strcmp (ifap->ifa_name, interface) == 0) {
        s = (struct sockaddr_ll *)ifap->ifa_addr;
        *mac = ether_ntoa((struct ether_addr *)s->sll_addr);
        freeifaddrs(ifa);
        return 0;
    }
  }
  freeifaddrs(ifa);
  return 1;
}