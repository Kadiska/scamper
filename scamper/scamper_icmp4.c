/*
 * scamper_icmp4.c
 *
 * $Id: scamper_icmp4.c,v 1.123 2021/04/14 07:00:49 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013-2014 The Regents of the University of California
 * Copyright (C) 2020-2021 Matthew Luckie
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
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"
#include "scamper_ip4.h"
#include "scamper_icmp4.h"
#include "scamper_privsep.h"
#include "scamper_debug.h"
#include "utils.h"

static uint8_t *txbuf = NULL;
static size_t txbuf_len = 0;
static uint8_t rxbuf[65536];

static void icmp4_header(scamper_probe_t *probe, uint8_t *buf) {
  buf[0] = probe->pr_icmp_type; /* type */
  buf[1] = probe->pr_icmp_code; /* code */
  buf[2] = 0;
  buf[3] = 0; /* checksum */

  switch (probe->pr_icmp_type) {
    case ICMP_ECHO:
    case ICMP_ECHOREPLY:
    case ICMP_TSTAMP:
      bytes_htons(buf + 4, probe->pr_icmp_id);
      bytes_htons(buf + 6, probe->pr_icmp_seq);
      break;

    case ICMP_UNREACH:
      memset(buf + 4, 0, 4);
      if (probe->pr_icmp_code == ICMP_UNREACH_NEEDFRAG)
        bytes_htons(buf + 6, probe->pr_icmp_mtu);
      break;

    default:
      memset(buf + 4, 0, 4);
      break;
  }

  return;
}

uint16_t scamper_pcap_icmp4_cksum(scamper_probe_t *probe) {
  uint8_t hdr[8];
  uint16_t tmp, *w;
  int i, sum = 0;

  icmp4_header(probe, hdr);

  w = (uint16_t *)hdr;
  for (i = 0; i < 8; i += 2) sum += *w++;

  w = (uint16_t *)probe->pr_data;
  for (i = probe->pr_len; i > 1; i -= 2) sum += *w++;
  if (i != 0) sum += ((uint8_t *)w)[0];

  /* fold the checksum */
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  if ((tmp = ~sum) == 0) {
    tmp = 0xffff;
  }

  return tmp;
}

static void icmp4_build(scamper_probe_t *probe, uint8_t *buf) {
  uint16_t csum;

  icmp4_header(probe, buf);

  if (probe->pr_len > 0) memcpy(buf + 8, probe->pr_data, probe->pr_len);

  csum = in_cksum(buf, (size_t)(probe->pr_len + 8));
  memcpy(buf + 2, &csum, 2);

  return;
}

int scamper_pcap_icmp4_build(scamper_probe_t *probe, uint8_t *buf,
                             size_t *len) {
  size_t ip4hlen, req;
  int rc = 0;

  ip4hlen = *len;
  scamper_ip4_build(probe, buf, &ip4hlen);
  req = ip4hlen + 8 + probe->pr_len;

  if (req <= *len)
    icmp4_build(probe, buf + ip4hlen);
  else
    rc = -1;

  *len = req;
  return rc;
}

/*
 * scamper_pcap_icmp4_probe
 *
 * send an ICMP probe to a destination
 */
int scamper_pcap_icmp4_probe(scamper_probe_t *probe) {
  struct sockaddr_in sin4;
  char addr[128];
  size_t ip4hlen, len, tmp;
  int i, icmphdrlen;

#if !defined(IP_HDR_HTONS)
  struct ip *ip;
#endif

  assert(probe != NULL);
  assert(probe->pr_ip_proto == IPPROTO_ICMP);
  assert(probe->pr_ip_dst != NULL);
  assert(probe->pr_ip_src != NULL);
  assert(probe->pr_len > 0 || probe->pr_data == NULL);

  switch (probe->pr_icmp_type) {
    case ICMP_ECHO:
    case ICMP_TSTAMP:
      icmphdrlen = (1 + 1 + 2 + 2 + 2);
      break;

    default:
      probe->pr_errno = EINVAL;
      return -1;
  }

  if ((probe->pr_flags & SCAMPER_PROBE_FLAG_RXERR) == 0)
    scamper_ip4_hlen(probe, &ip4hlen);
  else
    ip4hlen = 0;

  /* compute length, for sake of readability */
  len = ip4hlen + icmphdrlen + probe->pr_len;

  if (txbuf_len < len) {
    if (realloc_wrap((void **)&txbuf, len) != 0) {
      printerror(__func__, "could not realloc");
      return -1;
    }
    txbuf_len = len;
  }

  /* build the IPv4 header from the probe structure */
  if ((probe->pr_flags & SCAMPER_PROBE_FLAG_RXERR) == 0) {
    tmp = len;
    scamper_ip4_build(probe, txbuf, &tmp);

    /*
     * byte swap the length and offset fields back to host-byte order
     * if required
     */
#if !defined(IP_HDR_HTONS)
    ip = (struct ip *)txbuf;
    ip->ip_len = ntohs(ip->ip_len);
    ip->ip_off = ntohs(ip->ip_off);
#endif
  } else {
    i = probe->pr_ip_ttl;
    if (setsockopt(probe->pr_fd, IPPROTO_IP, IP_TTL, &i, sizeof(i)) < 0) {
      printerror(__func__, "could not set IP_TTL");
      return -1;
    }
  }

  icmp4_build(probe, txbuf + ip4hlen);

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, probe->pr_ip_dst->addr,
                   0);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&probe->pr_tx);

  i = sendto(probe->pr_fd, txbuf, len, 0, (struct sockaddr *)&sin4,
             sizeof(struct sockaddr_in));

  if (i < 0) {
    /* error condition, could not send the packet at all */
    probe->pr_errno = errno;
    printerror(__func__, "could not send to %s (%d ttl, %d seq, %d len)",
               scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)),
               probe->pr_ip_ttl, probe->pr_icmp_seq, len);
    return -1;
  } else if ((size_t)i != len) {
    /* error condition, sent a portion of the probe */
    printerror_msg(__func__, "sent %d bytes of %d byte packet to %s", i,
                   (int)len,
                   scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)));
    return -1;
  }

  return 0;
}

/*
 * icmp4_quote_ip_len
 *
 * this function returns the ip header's length field inside an icmp message
 * in a consistent fashion based on the system it is running on and the
 * type of the message.
 *
 * thanks to the use of an ICMP_FILTER or scamper's own type filtering, the
 * two ICMP types scamper has to deal with are ICMP_TIMXCEED and ICMP_UNREACH
 *
 * note that the filtering will filter any ICMP_TIMXCEED message with a code
 * other than ICMP_TIMXCEED_INTRANS, but we might as well deal with the whole
 * type.
 *
 * the pragmatic way is just to use pcap, which passes packets up in network
 * byte order consistently.
 */
static uint16_t icmp4_quote_ip_len(const struct icmp *icmp) {
  uint16_t len;

#if defined(__linux__) || defined(__OpenBSD__) || defined(__sun__) || \
    defined(_WIN32)
  len = ntohs(icmp->icmp_ip.ip_len);
#elif defined(__FreeBSD__) && __FreeBSD_version >= 1000022
  len = ntohs(icmp->icmp_ip.ip_len);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__) || \
    defined(__DragonFly__)
  if (icmp->icmp_type == ICMP_TIMXCEED) {
    if (icmp->icmp_code <= 1)
      len = icmp->icmp_ip.ip_len;
    else
      len = ntohs(icmp->icmp_ip.ip_len);
  } else if (icmp->icmp_type == ICMP_UNREACH) {
    switch (icmp->icmp_code) {
      case ICMP_UNREACH_NET:
      case ICMP_UNREACH_HOST:
      case ICMP_UNREACH_PROTOCOL:
      case ICMP_UNREACH_PORT:
      case ICMP_UNREACH_SRCFAIL:
      case ICMP_UNREACH_NEEDFRAG:
      case ICMP_UNREACH_NET_UNKNOWN:
      case ICMP_UNREACH_NET_PROHIB:
      case ICMP_UNREACH_TOSNET:
      case ICMP_UNREACH_HOST_UNKNOWN:
      case ICMP_UNREACH_ISOLATED:
      case ICMP_UNREACH_HOST_PROHIB:
      case ICMP_UNREACH_TOSHOST:

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__DragonFly__)
      case ICMP_UNREACH_HOST_PRECEDENCE:
      case ICMP_UNREACH_PRECEDENCE_CUTOFF:
      case ICMP_UNREACH_FILTER_PROHIB:
#endif
        len = icmp->icmp_ip.ip_len;
        break;

      default:
        len = ntohs(icmp->icmp_ip.ip_len);
    }
  } else if (icmp->icmp_type == ICMP_PARAMPROB) {
    if (icmp->icmp_code <= 1)
      len = icmp->icmp_ip.ip_len;
    else
      len = ntohs(icmp->icmp_ip.ip_len);
  } else {
    len = icmp->icmp_ip.ip_len;
  }
#else
  len = icmp->icmp_ip.ip_len;
#endif

  return len;
}

/*
 * scamper_pcap_icmp4_ip_len
 *
 * given the ip header encapsulating the icmp response, return the length
 * of the ip packet
 */
static uint16_t icmp4_ip_len(const struct ip *ip) {
  uint16_t len;

#if defined(__linux__) || defined(__OpenBSD__) || defined(__sun__) || \
    defined(_WIN32)
  len = ntohs(ip->ip_len);
#elif defined(__FreeBSD__) && __FreeBSD_version >= 1100030
  len = ntohs(ip->ip_len);
#else
  len = ip->ip_len + (ip->ip_hl << 2);
#endif

  return len;
}

static void ip_quote_rr(scamper_icmp_resp_t *ir, int rrc, void *rrs) {
  ir->ir_inner_ipopt_rrc = rrc;
  ir->ir_inner_ipopt_rrs = rrs;
  return;
}

static void ip_rr(scamper_icmp_resp_t *ir, int rrc, void *rrs) {
  ir->ir_ipopt_rrc = rrc;
  ir->ir_ipopt_rrs = rrs;
  return;
}

static uint8_t ip_tsc(int fl, int len) {
  if (fl == 0) {
    if (len >= 4 && (len % 4) == 0) return len / 4;
  } else if (fl == 1 || fl == 3) {
    if (len >= 8 && (len % 8) == 0) return len / 8;
  }

  return 0;
}

static void ip_quote_ts(scamper_icmp_resp_t *ir, int fl, const uint8_t *buf,
                        int len) {
  const uint8_t *ptr = buf;
  uint8_t i, tsc;

  ir->ir_flags |= SCAMPER_ICMP_RESP_FLAG_INNER_IPOPT_TS;

  if ((tsc = ip_tsc(fl, len)) == 0) return;

  if (fl == 1 || fl == 3) {
    ir->ir_inner_ipopt_tsips = malloc_zero(sizeof(struct in_addr) * tsc);
    if (ir->ir_inner_ipopt_tsips == NULL) return;
  }

  if ((ir->ir_inner_ipopt_tstss = malloc_zero(sizeof(uint32_t) * tsc)) == NULL)
    return;

  for (i = 0; i < tsc; i++) {
    if (fl == 1 || fl == 3) {
      memcpy(&ir->ir_inner_ipopt_tsips[i], ptr, 4);
      ptr += 4;
    }
    ir->ir_inner_ipopt_tstss[i] = bytes_ntohl(ptr);
    ptr += 4;
  }

  ir->ir_inner_ipopt_tsc = tsc;
  return;
}

static void ip_ts(scamper_icmp_resp_t *ir, int fl, const uint8_t *buf,
                  int len) {
  const uint8_t *ptr = buf;
  uint8_t i, tsc;
  size_t size;

  ir->ir_flags |= SCAMPER_ICMP_RESP_FLAG_IPOPT_TS;

  if ((tsc = ip_tsc(fl, len)) == 0) return;

  if (fl == 1 || fl == 3) {
    size = sizeof(struct in_addr) * tsc;
    if ((ir->ir_ipopt_tsips = malloc_zero(size)) == NULL) return;
  }

  if ((ir->ir_ipopt_tstss = malloc_zero(sizeof(uint32_t) * tsc)) == NULL)
    return;

  for (i = 0; i < tsc; i++) {
    if (fl == 1 || fl == 3) {
      memcpy(&ir->ir_ipopt_tsips[i], ptr, 4);
      ptr += 4;
    }
    ir->ir_ipopt_tstss[i] = bytes_ntohl(ptr);
    ptr += 4;
  }

  ir->ir_ipopt_tsc = tsc;
  return;
}

static void ipopt_parse(scamper_icmp_resp_t *ir, const uint8_t *buf, int iphl,
                        void (*rr)(scamper_icmp_resp_t *, int, void *),
                        void (*ts)(scamper_icmp_resp_t *, int, const uint8_t *,
                                   int)) {
  int off, ol, p, fl, rrc;
  void *rrs;

  off = 20;
  while (off < iphl) {
    /* end of IP options */
    if (buf[off] == 0) break;

    /* no-op */
    if (buf[off] == 1) {
      off++;
      continue;
    }

    ol = buf[off + 1];

    /* check to see if the option could be included */
    if (ol < 2 || off + ol > iphl) break;

    if (buf[off] == 7 && rr != NULL) {
      /* record route */
      p = buf[off + 2];
      if (p >= 4 && (p % 4) == 0 && (rrc = (p / 4) - 1) != 0 &&
          (rrs = memdup(buf + off + 3, rrc * 4)) != NULL) {
        rr(ir, rrc, rrs);
      }
    } else if (buf[off] == 68 && ts != NULL) {
      /* timestamp */
      p = buf[off + 2];
      fl = buf[off + 3] & 0xf;
      if (p == 1) /* RFC 781, not in 791 */
        ts(ir, fl, buf + off + 4, ol - 4);
      else if (p >= 5 && p - 1 <= ol)
        ts(ir, fl, buf + off + 4, p - 5);
    }

    off += ol;
  }

  return;
}

/*
 * icmp4_recv_ip
 *
 * copy details of the ICMP message and the time it was received into the
 * response structure.
 */
static void icmp4_recv_ip(struct pcap_pkthdr *header, scamper_icmp_resp_t *ir,
                          const uint8_t *buf, int iphl) {
  const struct ip *ip = (const struct ip *)buf;
  const struct icmp *icmp = (const struct icmp *)(buf + iphl);

  timeval_cpy(&ir->ir_rx, &(header->ts));
  ir->ir_flags |= SCAMPER_ICMP_RESP_FLAG_KERNRX;

  if ((ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_KERNRX) == 0)
    gettimeofday_wrap(&ir->ir_rx);

  /* the response came from ... */
  memcpy(&ir->ir_ip_src.v4, &ip->ip_src, sizeof(struct in_addr));

  ir->ir_af = AF_INET;
  ir->ir_ip_ttl = ip->ip_ttl;
  ir->ir_ip_id = ntohs(ip->ip_id);
  ir->ir_ip_tos = ip->ip_tos;
  ir->ir_ip_size = icmp4_ip_len(ip);
  ir->ir_icmp_type = icmp->icmp_type;
  ir->ir_icmp_code = icmp->icmp_code;
  ipopt_parse(ir, buf, iphl, ip_rr, ip_ts);

  return;
}

static int ip_hl(const void *buf) {
  return (((const uint8_t *)buf)[0] & 0xf) << 2;
}

int scamper_pcap_icmp4_recv(scamper_pcap_t *pcap, scamper_icmp_resp_t *resp) {
  struct pcap_pkthdr header;
  const u_char *packet;

  ssize_t poffset;
  ssize_t pbuflen;
  struct icmp *icmp;
  struct ip *ip_outer = (struct ip *)rxbuf;
  struct ip *ip_inner;
  struct udphdr *udp;
  struct tcphdr *tcp;
  uint8_t type, code;
  uint8_t nh;
  int iphl;
  int iphlq;
  uint8_t *ext;
  ssize_t extlen;

  packet = pcap_next(pcap->pcap, &header);
  if (packet == NULL) return -1;

  // Ethernet header frame is 14 bytes long
  if (header.len < 14) return -1;
  pbuflen = header.len - 14;
  memcpy(rxbuf, packet + 14, pbuflen);

  if ((iphl = ip_hl(ip_outer)) < 20) {
    scamper_debug(__func__, "iphl %d < 20", iphl);
    return -1;
  }

  /*
   * an ICMP header has to be at least 8 bytes:
   * 1 byte type, 1 byte code, 2 bytes checksum, 4 bytes 'data'
   */
  if (pbuflen < iphl + 8) {
    scamper_debug(__func__, "pbuflen [%d] < iphl [%d] + 8", pbuflen, iphl);
    return -1;
  }

  icmp = (struct icmp *)(rxbuf + iphl);
  type = icmp->icmp_type;
  code = icmp->icmp_code;

  /* check to see if the ICMP type / code is what we want */
  if ((type != ICMP_TIMXCEED || code != ICMP_TIMXCEED_INTRANS) &&
      type != ICMP_UNREACH && type != ICMP_ECHOREPLY &&
      type != ICMP_TSTAMPREPLY && type != ICMP_PARAMPROB) {
    scamper_debug(__func__, "type %d, code %d not wanted", type, code);
    return -1;
  }

  memset(resp, 0, sizeof(scamper_icmp_resp_t));

  resp->ir_fd = pcap->fd;

  /*
   * if we get an ICMP echo reply, there is no 'inner' IP packet as there
   * was no error condition.
   * so get the outer packet's details and be done
   */
  if (type == ICMP_ECHOREPLY || type == ICMP_TSTAMPREPLY) {
    resp->ir_icmp_id = ntohs(icmp->icmp_id);
    resp->ir_icmp_seq = ntohs(icmp->icmp_seq);
    memcpy(&resp->ir_inner_ip_dst.v4, &ip_outer->ip_src,
           sizeof(struct in_addr));

    if (type == ICMP_TSTAMPREPLY) {
      resp->ir_icmp_tso = bytes_ntohl(rxbuf + iphl + 8);
      resp->ir_icmp_tsr = bytes_ntohl(rxbuf + iphl + 12);
      resp->ir_icmp_tst = bytes_ntohl(rxbuf + iphl + 16);
    }

    icmp4_recv_ip(&header, resp, rxbuf, iphl);

    return 0;
  }

  ip_inner = &icmp->icmp_ip;
  nh = ip_inner->ip_p;
  iphlq = ip_hl(ip_inner);
  poffset = iphl + 8 + iphlq;

  /* search for an ICMP / UDP / TCP header in this packet */
  while (poffset + 8 <= pbuflen) {
    /* if we can't deal with the inner header, then stop now */
    if (nh != IPPROTO_UDP && nh != IPPROTO_ICMP && nh != IPPROTO_TCP) {
      scamper_debug(__func__, "unhandled next header %d", nh);
      return -1;
    }

    resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_INNER_IP;

    /* record details of the IP header and the ICMP headers */
    icmp4_recv_ip(&header, resp, rxbuf, iphl);

    /* record details of the IP header found in the ICMP error message */
    memcpy(&resp->ir_inner_ip_dst.v4, &ip_inner->ip_dst,
           sizeof(struct in_addr));

    resp->ir_inner_ip_proto = nh;
    resp->ir_inner_ip_ttl = ip_inner->ip_ttl;
    resp->ir_inner_ip_id = ntohs(ip_inner->ip_id);
    resp->ir_inner_ip_off = ntohs(ip_inner->ip_off) & IP_OFFMASK;
    resp->ir_inner_ip_tos = ip_inner->ip_tos;
    resp->ir_inner_ip_size = icmp4_quote_ip_len(icmp);

    if (type == ICMP_UNREACH && code == ICMP_UNREACH_NEEDFRAG)
      resp->ir_icmp_nhmtu = ntohs(icmp->icmp_nextmtu);

    if (type == ICMP_PARAMPROB && code == ICMP_PARAMPROB_ERRATPTR)
      resp->ir_icmp_pptr = icmp->icmp_pptr;

    if (resp->ir_inner_ip_off == 0) {
      ipopt_parse(resp, rxbuf + iphl + 8, iphlq, ip_quote_rr, ip_quote_ts);

      if (nh == IPPROTO_UDP) {
        udp = (struct udphdr *)(rxbuf + poffset);
        resp->ir_inner_udp_sport = ntohs(udp->uh_sport);
        resp->ir_inner_udp_dport = ntohs(udp->uh_dport);
        resp->ir_inner_udp_sum = udp->uh_sum;
      } else if (nh == IPPROTO_ICMP) {
        icmp = (struct icmp *)(rxbuf + poffset);
        resp->ir_inner_icmp_type = icmp->icmp_type;
        resp->ir_inner_icmp_code = icmp->icmp_code;
        resp->ir_inner_icmp_sum = icmp->icmp_cksum;
        resp->ir_inner_icmp_id = ntohs(icmp->icmp_id);
        resp->ir_inner_icmp_seq = ntohs(icmp->icmp_seq);
      } else if (nh == IPPROTO_TCP) {
        tcp = (struct tcphdr *)(rxbuf + poffset);
        resp->ir_inner_tcp_sport = ntohs(tcp->th_sport);
        resp->ir_inner_tcp_dport = ntohs(tcp->th_dport);
        resp->ir_inner_tcp_seq = ntohl(tcp->th_seq);
      }
    } else {
      resp->ir_inner_data = rxbuf + poffset;
      resp->ir_inner_datalen = pbuflen - poffset;
    }

    /*
     * check for ICMP extensions
     *
     * the length of the message must be at least padded out to 128 bytes,
     * and must have 4 bytes of header beyond that for there to be
     * extensions included.
     * RFC 4884 says that the first 4 bits of the extension header
     * corresponds to a version number, and the version is two.  But
     * it appears some systems have the version in the subsequent 4 bits.
     */
    if (pbuflen - (iphl + 8) > 128 + 4) {
      ext = rxbuf + (iphl + 8 + 128);
      extlen = pbuflen - (iphl + 8 + 128);

      if (((ext[0] & 0xf0) == 0x20 || ext[0] == 0x02) &&
          ((ext[2] == 0 && ext[3] == 0) || in_cksum(ext, extlen) == 0)) {
        resp->ir_ext = memdup(ext, extlen);
        resp->ir_extlen = extlen;
      }
    }

    return 0;
  }

  scamper_debug(__func__, "packet not ours");

  return -1;
}

void scamper_pcap_icmp4_read_cb(scamper_pcap_t *pcap, void *param) {
  scamper_icmp_resp_t ir;
  memset(&ir, 0, sizeof(ir));
  if (scamper_pcap_icmp4_recv(pcap, &ir) == 0) scamper_icmp_resp_handle(&ir);
  scamper_icmp_resp_clean(&ir);
  return;
}

void scamper_pcap_icmp4_cleanup() {
  if (txbuf != NULL) {
    free(txbuf);
    txbuf = NULL;
  }

  return;
}

void scamper_pcap_icmp4_close(pcap_t *pcap) { pcap_close(pcap); }

pcap_t *scamper_pcap_icmp4_open_fd(void) {
  int opt = 1;
  pcap_t *pcap = NULL;

  return pcap;

err:
  if (pcap != NULL) scamper_pcap_icmp4_close(pcap);
  return NULL;
}

#ifdef _WIN32

#define DEVICE_NAME_SIZE MAX_ADAPTER_NAME_LENGTH + 4 + 12

static int had_match(struct in_addr *expected_ip,
                     PIP_ADAPTER_UNICAST_ADDRESS ips) {
  if (ips == NULL) return 0;
  struct sockaddr_in *ip = (ips->Address.lpSockaddr);
  if (expected_ip->s_addr == ip->sin_addr.s_addr)
    return 1;
  else
    return had_match(expected_ip, ips->Next);
}

static int get_device_name_by_ip(char *name, struct in_addr *expected_ip) {
  PIP_ADAPTER_ADDRESSES pAdapterInfo = NULL;
  PIP_ADAPTER_ADDRESSES pAdapter = NULL;
  DWORD dwRetVal = 0;
  UINT i;
  int ret = 0;

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
  pAdapter = pAdapterInfo;
  while (pAdapter) {
    if (had_match(expected_ip, pAdapter->FirstUnicastAddress)) {
      if (pAdapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
        strcpy(name, "\\Device\\NPF_Loopback");
      } else {
        strcpy(name, "\\Device\\NPF_");
        strcat(name, pAdapter->AdapterName);
      }
      goto cleanup;
    }
    pAdapter = pAdapter->Next;
  }
  ret = -1;

cleanup:
  if (pAdapterInfo != NULL) free(pAdapterInfo);
  return ret;
}

#else

#define DEVICE_NAME_SIZE IFNAMSIZ

static int get_device_name_by_ip(char *name, struct in_addr *expected_ip) {
  int ret = 0;
  struct ifaddrs *addrs = NULL;

  if (getifaddrs(&addrs) != 0) return 1;

  for (struct ifaddrs *addr = addrs; addr != NULL; addr = addr->ifa_next) {
    if (addr->ifa_addr->sa_family == AF_INET &&
        ((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr ==
            expected_ip->s_addr) {
      strcpy(name, addr->ifa_name);
      goto cleanup;
    }
  }
  ret = -1;

cleanup:
  if (addrs != NULL) freeifaddrs(addrs);
  return ret;
}

#endif

pcap_t *scamper_pcap_icmp4_open(const void *addr) {
  char device[DEVICE_NAME_SIZE];
  char errbuf[1024];

  char bpf_expr[100];
  struct bpf_program fcode;
  char ip[100];

  pcap_t *pcap = NULL;

  if (get_device_name_by_ip(device, addr) != 0) {
    printerror(__func__, "cannot open device");
    goto err;
  }

  pcap = pcap_open_live(device, BUFSIZ, 0, 10, errbuf);
  if (pcap == NULL) {
    printerror(__func__, "cannot initialize pcap: %s", errbuf);
    goto err;
  }

#ifdef _WIN32
  pcap_setmintocopy(pcap, 1);
#endif

  strcpy(bpf_expr, "ip proto \\icmp and dst ");

  addr_tostr(AF_INET, addr, ip, sizeof(ip));
  strcat(bpf_expr, ip);

  if (pcap_compile(pcap, &fcode, bpf_expr, 1, 0) < 0) {
    printerror(__func__, "cannot compile bpf expression");
    goto err;
  }

  if (pcap_setfilter(pcap, &fcode) != 0) {
    printerror(__func__, "cannot set bpf filter");
    goto err;
  }

  return pcap;

err:
  if (pcap != NULL) scamper_pcap_icmp4_close(pcap);
  return NULL;
}
