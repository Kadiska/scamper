/*
 * scamper_getsrc.c
 *
 * $Id: scamper_getsrc.c,v 1.20 2020/03/17 07:32:16 mjl Exp $
 *
 * Copyright (C) 2005 Matthew Luckie
 * Copyright (C) 2007-2010 The University of Waikato
 * Author: Matthew Luckie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_debug.h"
#include "scamper_getsrc.h"
#include "utils.h"

static int udp4 = -1;
static int udp6 = -1;

extern scamper_addrcache_t *addrcache;


#ifdef _WIN32

uint32_t mask_ip4(uint32_t ip, uint8_t prefix_len)
{
  uint32_t ipv4_netmask = prefix_len == 0 ? 0 : (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF;
  return ip & ipv4_netmask;
}

static MIB_IPFORWARD_ROW2 *get_best_adapter(PMIB_IPFORWARD_TABLE2 table, struct sockaddr_storage * sas, BOOL include_virtual) {
  MIB_IPFORWARD_ROW2 * res = NULL;

  for (uint32_t idx = 0; idx < table->NumEntries; ++idx)
  {
    MIB_IPFORWARD_ROW2 * row = &(table->Table[idx]);
 
    if (sas->ss_family == AF_INET && sas->ss_family == row->DestinationPrefix.Prefix.si_family) 
    {
 
      if (mask_ip4(((struct sockaddr_in *)sas)->sin_addr.S_un.S_addr,
                   row->DestinationPrefix.PrefixLength) ==
          mask_ip4(row->DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr,
                   row->DestinationPrefix.PrefixLength) && (row->NextHop.Ipv4.sin_addr.S_un.S_addr != 0 || include_virtual)) {
        res = res == NULL || res->Metric > row->Metric ? row : res;
      }
    }  
  }
  return res;
}

#endif

/*
 * scamper_getsrc
 *
 * given a destination address, determine the src address used in the IP
 * header to transmit probes to it.
 */
scamper_addr_t *scamper_getsrc(const scamper_addr_t *dst, int ifindex) {
#ifndef _WIN32
  struct sockaddr_storage sas;
  scamper_addr_t *src;
  socklen_t socklen, sockleno;
  int sock;
  void *addr;
  char buf[64];

  if (dst->type == SCAMPER_ADDR_TYPE_IPV4) {
    if (udp4 == -1 && (udp4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
      printerror(__func__, "could not open udp4 sock");
      return NULL;
    }

    sock = udp4;
    addr = &((struct sockaddr_in *)&sas)->sin_addr;
    socklen = sizeof(struct sockaddr_in);

    sockaddr_compose((struct sockaddr *)&sas, AF_INET, dst->addr, 80);
  } else if (dst->type == SCAMPER_ADDR_TYPE_IPV6) {
    if (udp6 == -1 &&
        (udp6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
      printerror(__func__, "could not open udp6 sock");
      return NULL;
    }

    sock = udp6;
    addr = &((struct sockaddr_in6 *)&sas)->sin6_addr;
    socklen = sizeof(struct sockaddr_in6);

    sockaddr_compose((struct sockaddr *)&sas, AF_INET6, dst->addr, 80);

    if (scamper_addr_islinklocal(dst) != 0) {
      ((struct sockaddr_in6 *)&sas)->sin6_scope_id = ifindex;
    }
  } else
    return NULL;

  if (connect(sock, (struct sockaddr *)&sas, socklen) != 0) {
    printerror(__func__, "connect to dst failed for %s",
               scamper_addr_tostr(dst, buf, sizeof(buf)));
    return NULL;
  }

  sockleno = socklen;
  if (getsockname(sock, (struct sockaddr *)&sas, &sockleno) != 0) {
    printerror(__func__, "could not getsockname for %s",
               scamper_addr_tostr(dst, buf, sizeof(buf)));
    return NULL;
  }

  src = scamper_addrcache_get(addrcache, dst->type, addr);

  memset(&sas, 0, sizeof(sas));
  connect(sock, (struct sockaddr *)&sas, socklen);
  return src;
#else
  PMIB_IPFORWARD_TABLE2 table;
  struct sockaddr_storage sas;

  sockaddr_compose((struct sockaddr *)&sas, AF_INET, dst->addr, 80);

  if (GetIpForwardTable2((dst->type == SCAMPER_ADDR_TYPE_IPV4 ? AF_INET : AF_INET6), &table) != NO_ERROR)
      return NULL;

  MIB_IPFORWARD_ROW2 *adapter = get_best_adapter(table, &sas, FALSE);

  if (adapter == NULL) {
    adapter = get_best_adapter(table, &sas, TRUE);
  }
  if (adapter == NULL) {
    return NULL;
  }

  PIP_ADAPTER_ADDRESSES pAdapterInfo = NULL;
  ULONG ulOutBufLen = sizeof(IP_ADAPTER_ADDRESSES_LH);

    pAdapterInfo = (PIP_ADAPTER_ADDRESSES *)malloc(ulOutBufLen);
  if (pAdapterInfo == NULL) {
    printerror(__func__,
               "Error allocating memory needed to call GetAdaptersinfo\n");
    return 1;
  }

  // Make an initial call to GetAdaptersAddresses to get
  // the necessary size into the ulOutBufLen variable
  if (GetAdaptersAddresses(
          AF_INET,
          GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_WINS_INFO |
              GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
          0, pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
    free(pAdapterInfo);
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    if (pAdapterInfo == NULL) {
      printerror(__func__,
                 "Error allocating memory needed to call GetAdaptersinfo\n");
      return 1;
    }
  }

  if (GetAdaptersAddresses(AF_INET,
                           GAA_FLAG_INCLUDE_GATEWAYS |
                               GAA_FLAG_INCLUDE_WINS_INFO |
                               GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                           0, pAdapterInfo, &ulOutBufLen) != NO_ERROR)
    return 1;

    for (PIP_ADAPTER_ADDRESSES pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
    if (pAdapter->IfIndex == adapter->InterfaceIndex) {
      struct sockaddr_in *ip =
          ((struct sockaddr_in *)(pAdapter->FirstUnicastAddress->Address.lpSockaddr));
      void *addr = addr = &(ip->sin_addr);
      scamper_addr_t *src =
          scamper_addrcache_get(addrcache, dst->type, addr);
      return src;
    }
    }
    return NULL;
#endif
}

int scamper_getsrc_init() { return 0; }

void scamper_getsrc_cleanup() {
  if (udp4 != -1) {
#ifndef _WIN32
    close(udp4);
#else
    closesocket(udp4);
#endif
    udp4 = -1;
  }

  if (udp6 != -1) {
#ifndef _WIN32
    close(udp6);
#else
    closesocket(udp6);
#endif
    udp6 = -1;
  }

  return;
}
