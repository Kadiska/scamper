/*
 * scamper_probe_icmp4.h
 *
 * $Id: scamper_probe_icmp4.h,v 1.22 2020/04/27 07:32:21 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2009 The University of Waikato
 * Copyright (C) 2020      Matthew Luckie
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

#ifndef __SCAMPER_probe_icmp4_H
#define __SCAMPER_probe_icmp4_H

int scamper_probe_icmp4_open(const void *addr);
int scamper_probe_icmp4_open_fd(void);
int scamper_probe_icmp4_open_err(const void *addr);
void scamper_probe_icmp4_close(int fd);

void scamper_probe_icmp4_cleanup(void);
void scamper_probe_icmp4_read_cb(void * fd, void *param);
void scamper_probe_icmp4_read_err_cb(void * fd, void *param);

#ifdef __SCAMPER_PROBE_H
int scamper_probe_icmp4_probe(scamper_probe_t *probe);
int scamper_probe_icmp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
uint16_t scamper_probe_icmp4_cksum(scamper_probe_t *probe);
#endif

#ifdef __SCAMPER_ICMP_RESP_H
int scamper_probe_icmp4_recv(int fd, scamper_icmp_resp_t *resp);
int scamper_probe_icmp4_recv_user(int fd, scamper_icmp_resp_t *resp);
#endif

#endif /* __SCAMPER_probe_icmp4_H */
