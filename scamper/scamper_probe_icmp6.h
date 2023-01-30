/*
 * scamper_probe_icmp6.h
 *
 * $Id: scamper_probe_icmp6.h,v 1.20 2015/04/23 21:57:49 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2009 The University of Waikato
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

#ifndef __SCAMPER_probe_icmp6_H
#define __SCAMPER_probe_icmp6_H

int scamper_probe_icmp6_open(const void *addr);
int scamper_probe_icmp6_open_fd(void);
void scamper_probe_icmp6_close(int fd);

void scamper_probe_icmp6_cleanup(void);
void scamper_probe_icmp6_read_cb(void * fd, void *param);

#ifdef __SCAMPER_PROBE_H
int scamper_probe_icmp6_probe(scamper_probe_t *probe);
int scamper_probe_icmp6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
uint16_t scamper_probe_icmp6_cksum(scamper_probe_t *probe);
#endif

#ifdef __SCAMPER_ICMP_RESP_H
int scamper_probe_icmp6_recv(int fd, scamper_icmp_resp_t *resp);
#endif

#endif /* __SCAMPER_probe_icmp6_H */
