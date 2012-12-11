/* transport.c - MTP/audio transport
 *
 * Copyright (C) 2006-2011 Netfors ApS.
 *
 * Author: Anders Baekgaard <ab@netfors.com>
 *
 * This file is part of chan_ss7.
 *
 * chan_ss7 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * chan_ss7 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with chan_ss7; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/param.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#ifdef USE_ZAPTEL
#include "zaptel.h"
#define FAST_HDLC_NEED_TABLES
#include "fasthdlc.h"
#define DAHDI_DEV "/dev/zap"
#define DAHDI_DEV_CHANNEL "/dev/zap/channel"
#define DAHDI_AUDIOMODE ZT_AUDIOMODE
#define DAHDI_AUDIOMODE ZT_AUDIOMODE
#define DAHDI_BUFFERINFO ZT_BUFFERINFO
#define DAHDI_DIAL ZT_DIAL
#define DAHDI_DIAL_OPERATION ZT_DIAL_OPERATION
#define DAHDI_DIAL_OP_APPEND ZT_DIAL_OP_APPEND
#define DAHDI_ECHOCANCEL ZT_ECHOCANCEL
#define DAHDI_ECHOTRAIN ZT_ECHOTRAIN
#define DAHDI_FLUSH ZT_FLUSH
#define DAHDI_FLUSH_ALL ZT_FLUSH_ALL
#define DAHDI_GETEVENT ZT_GETEVENT
#define DAHDI_GET_BUFINFO ZT_GET_BUFINFO
#define DAHDI_LAW_ALAW ZT_LAW_ALAW
#define DAHDI_POLICY_IMMEDIATE ZT_POLICY_IMMEDIATE
#define DAHDI_SETLAW ZT_SETLAW
#define DAHDI_SET_BLOCKSIZE ZT_SET_BLOCKSIZE
#define DAHDI_SET_BUFINFO ZT_SET_BUFINFO
#define DAHDI_SPECIFY ZT_SPECIFY
#define DAHDI_GET_PARAMS ZT_GET_PARAMS
#define dahdi_bufferinfo zt_bufferinfo
#define dahdi_dialoperation zt_dialoperation
#else
#include <dahdi/user.h>
#define FAST_HDLC_NEED_TABLES
#include <dahdi/fasthdlc.h>
#define DAHDI_DEV "/dev/dahdi"
#define DAHDI_DEV_CHANNEL "/dev/dahdi/channel"
#endif


#ifdef MTP_STANDALONE
#include "aststubs.h"
#else
#include "asterisk.h"
#include "asterisk/logger.h"
#endif
#include "config.h"
#include "mtp.h"
#include "transport.h"
#include "utils.h"


static int setnonblock_fd(int s)
{
  int res, flags;

  res = fcntl(s, F_GETFL);
  if(res < 0) {
    ast_log(LOG_WARNING, "Could not obtain flags for socket fd: %s.\n", strerror(errno));
    return -1;
  }
  flags = res | O_NONBLOCK;
  res = fcntl(s, F_SETFL, flags);
  if(res < 0) {
    ast_log(LOG_WARNING, "Could not set socket fd non-blocking: %s.\n", strerror(errno));
    return -1;
  }
  return 0;
}



#ifndef MTP_OVER_UDP
static void set_buffer_info(int fd, int cic, int numbufs, int bufsize)
{
  struct dahdi_bufferinfo bi;
  int res;

  bi.txbufpolicy = DAHDI_POLICY_IMMEDIATE;
  bi.rxbufpolicy = DAHDI_POLICY_IMMEDIATE;
  bi.numbufs = numbufs;
  bi.bufsize = bufsize;
  res = ioctl(fd, DAHDI_SET_BUFINFO, &bi);
  if(res) {
    ast_log(LOG_WARNING, "Failure to set buffer policy for circuit %d: %s.\n", cic, strerror(errno));
  }
}

int adjust_buffers(int fd, int cic)
{
  struct dahdi_bufferinfo bi;
  int res;

  res = ioctl(fd, DAHDI_GET_BUFINFO, &bi);
  if(res) {
    ast_log(LOG_WARNING, "Failure to get buffer policy for circuit %d: %s.\n", cic, strerror(errno));
    return 0;
  }
  if (bi.numbufs >= 8) {
    static struct timeval lastreport = {0, 0};
    struct timeval now;
    gettimeofday(&now, NULL);
    if (now.tv_sec - lastreport.tv_sec > 10) {
      ast_log(LOG_DEBUG, "Limit exceeded when trying to adjust numbufs to %d, for circuit %d.\n", bi.numbufs, cic);
      lastreport = now;
    }
    return 0;
  }
  set_buffer_info(fd, cic, bi.numbufs + 1, AUDIO_READSIZE);
  ast_log(LOG_DEBUG, "Adjusting numbufs to %d for circuit %d.\n", bi.numbufs + 1, cic);
  return 1;
}


int adjust_schannel_buffers(int fd, struct link* link, int ts, int bufcount, int bufsize)
{
  set_buffer_info(fd, link->first_cic+ts, bufcount, bufsize);
  ast_log(LOG_NOTICE, "Adjusting channels buffers for link %s/%d, size=%d, count=%d.\n", link->name, ts, bufsize, bufcount);
  return 1;
}


void set_audiomode(int fd)
{
  int res;
  int z = 1;

  res = ioctl(fd, DAHDI_AUDIOMODE, &z);
  if (res)
    ast_log(LOG_WARNING, "Unable to set fd %d to audiomode\n", fd);
}


void clear_audiomode(int fd)
{
  int res;
  int z = 0;

  res = ioctl(fd, DAHDI_AUDIOMODE, &z);
  if (res)
    ast_log(LOG_WARNING, "Unable to clear audiomode on fd %d\n", fd);
}


static int opendev(int zapid)
{
  int fd = open(DAHDI_DEV_CHANNEL, O_RDWR | O_NONBLOCK);
  int res;

  if(fd < 0) {
    char devname[100];
    sprintf(devname, "%s/%d", DAHDI_DEV, zapid);
    fd = open(devname, O_RDWR | O_NONBLOCK);
    if(fd < 0) {
      ast_log(LOG_WARNING, "Unable to open signalling devices %s, %s and %s: %s\n", DAHDI_DEV_CHANNEL, "/dev/zap/channel", devname, strerror(errno));
      return -1;
    }
    return fd;
  }
  res = ioctl(fd, DAHDI_SPECIFY, &zapid);
  if(res) {
    ast_log(LOG_WARNING, "Failure in DAHDI_SPECIFY for dahdi id %d: %s.\n", zapid, strerror(errno));
    return -1;
  }
  return fd;
}

int openchannel(struct link* link, int channel)
{
  int cic = link->first_cic + channel;
  int zapid = link->first_zapid + channel + 1;
  int fd;
  int parm, res;

  ast_log(LOG_DEBUG, "Configuring CIC %d on dahdi device %d.\n", cic, zapid);
  fd = opendev(zapid);
  if (fd < 0)
    return fd;
  parm = DAHDI_LAW_ALAW;
  res = ioctl(fd, DAHDI_SETLAW, &parm);
  if(res) {
    ast_log(LOG_DEBUG, "Failure to set circuit   %d to ALAW: %s.\n", cic, strerror(errno));
    return -1;
  }
  set_buffer_info(fd, cic, 4, AUDIO_READSIZE);
  parm = AUDIO_READSIZE;
  res = ioctl(fd, DAHDI_SET_BLOCKSIZE, &parm);
  if(res) {
    ast_log(LOG_WARNING, "Failure to set blocksize for circuit %d: %s.\n", cic, strerror(errno));
    return -1;
  }
  res = setnonblock_fd(fd);
  if(res < 0) {
    ast_log(LOG_WARNING, "Could not set non-blocking on circuit %d: %s.\n", cic, strerror(errno));
    return -1;
  }
  return fd;
}

void flushchannel(int fd, int cic)
{
  int parm, res;

  /* Flush timeslot of old data. */
  parm = DAHDI_FLUSH_ALL;
  res = ioctl(fd, DAHDI_FLUSH, &parm);
  if (res) {
    ast_log(LOG_WARNING, "Unable to flush input on circuit %d\n", cic);
  }
  set_buffer_info(fd, cic, 4, AUDIO_READSIZE);
}


int openschannel(struct link* link, int channel, int* sigtype)
{
  struct dahdi_bufferinfo bi;
  struct dahdi_params params;
  int fd, res;
  int zapid = channel + 1 + link->first_zapid;

  fd = opendev(zapid);
  if (fd < 0)
    return fd;
  bi.txbufpolicy = DAHDI_POLICY_IMMEDIATE;
  bi.rxbufpolicy = DAHDI_POLICY_IMMEDIATE;
  bi.numbufs = NUM_ZAP_BUF;
  bi.bufsize = ZAP_BUF_SIZE;
  if (ioctl(fd, DAHDI_SET_BUFINFO, &bi)) {
    ast_log(LOG_WARNING, "Unable to set buffering policy on signalling link "
            "dahdi device: %s\n", strerror(errno));
    goto fail;
  }
  if (ioctl(fd, DAHDI_GET_PARAMS, &params)) {
    ast_log(LOG_WARNING, "Unable to get signalling channel params "
            "dahdi device: %s\n", strerror(errno));
    *sigtype = 0;
  }
  else
    *sigtype = params.sigtype;

  res = setnonblock_fd(fd);
  if(res < 0) {
    ast_log(LOG_WARNING, "SS7: Could not set signalling link fd non-blocking: "
            "%s.\n", strerror(errno));
    goto fail;
  }
  return fd;
 fail:
  return -1;
}

int io_get_dahdi_event(int fd, int* e)
{
  return ioctl(fd, DAHDI_GETEVENT, e);
}


int io_enable_echo_cancellation(int fd, int cic, int echocan_taps, int echocan_train)
{
  int res, parm = 1;

  res = ioctl(fd, DAHDI_AUDIOMODE, &parm);
  if (res)
    ast_log(LOG_WARNING, "Unable to set fd %d to audiomode\n", fd);

  res = ioctl(fd, DAHDI_ECHOCANCEL, &echocan_taps);
  if (res) {
    ast_log(LOG_WARNING, "Unable to enable echo cancellation on cic %d\n", cic);
    return res;
  } else {
    ast_log(LOG_DEBUG, "Enabled echo cancellation on cic %d\n", cic);
    res = ioctl(fd, DAHDI_ECHOTRAIN, &echocan_train);
    if (res) {
      ast_log(LOG_WARNING, "Unable to request echo training on cic %d\n", cic);
      return res;
    } else {
      ast_log(LOG_DEBUG, "Engaged echo training on cic %d\n", cic);
    }
  }
  return 0;
}

void io_disable_echo_cancellation(int fd, int cic)
{
  int res;
  int x = 0;

  res = ioctl(fd, DAHDI_ECHOCANCEL, &x);
  if (res) 
    ast_log(LOG_WARNING, "Unable to disable echo cancellation on cic %d\n", cic);
  else
    ast_log(LOG_DEBUG, "disabled echo cancellation on cic %d\n", cic);
}


int io_send_dtmf(int fd, int cic, char digit)
{
  struct dahdi_dialoperation zo;
  int res;

  zo.op = DAHDI_DIAL_OP_APPEND;
  zo.dialstr[0] = 'T';
  zo.dialstr[1] = digit;
  zo.dialstr[2] = 0;
  res = ioctl(fd, DAHDI_DIAL, &zo);
  if(res) {
    ast_log(LOG_WARNING, "DTMF generation of %c failed on CIC=%d.\n", digit, cic);
    return res;
  } else {
    ast_log(LOG_DEBUG, "Passed on digit %c to CIC=%d.\n", digit, cic);
  }
  return 0;
}


#else
#define MTPPORT 11000
static int transport_socket(int localport, const char* remotehost, int remoteport);

int openschannel(struct link* link, int channel, int* sigtype)
{
  int id = channel + 1 + link->first_zapid;
  int i;

  *sigtype = 0;
  for (i = 0; i < this_host->n_peers; i++) {
    if (this_host->peers[i].link == link)
      return transport_socket(MTPPORT+id, this_host->peers[i].hostname, MTPPORT+id);
  }
  ast_log(LOG_ERROR, "Cannot open schannel, there is no configured peer host for link '%s'\n", link->name);
  return -1;
}


int openchannel(struct link* link, int channel)
{
  int zapid = link->first_zapid + channel + 1;
  int i;

  for (i = 0; i < this_host->n_peers; i++) {
    if (this_host->peers[i].link == link)
      return transport_socket(MTPPORT+zapid, this_host->peers[i].hostname, MTPPORT+zapid);
  }
  ast_log(LOG_ERROR, "Cannot open channel, there is no configured peer host for link '%s'\n", link->name);
  return -1;
}

int adjust_buffers(int fd, int cic)
{
  return 1;
}

int adjust_schannel_buffers(int fd, struct link* link, int ts, int bufcount, int bufsize)
{
}


void set_audiomode(int fd)
{
}


void clear_audiomode(int fd)
{
}


void flushchannel(int fd, int cic)
{
}

int io_get_dahdi_event(int fd, int* e)
{
  return 0;
}

int io_enable_echo_cancellation(int fd, int cic, int echocan_taps, int echocan_train)
{
  return 0;
}

void io_disable_echo_cancellation(int fd, int cic)
{
}

int io_send_dtmf(int fd, int cic, char digit)
{
  return 0;
}

static int setup_socket(int localport, int sockettype, int ipproto)
{
  struct sockaddr_in sock;
  in_addr_t addr = INADDR_ANY;
  int parm;
  int s;

  memset(&sock, 0, sizeof(struct sockaddr_in));
  sock.sin_family = AF_INET;
  sock.sin_port = htons(localport);
  memcpy(&sock.sin_addr, &addr, sizeof(addr));

  s = socket(PF_INET, sockettype, ipproto);
  if (s < 0) {
    ast_log(LOG_ERROR, "Cannot create UDP socket, errno=%d: %s\n", errno, strerror(errno));
    return -1;
  }
  parm = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &parm, sizeof(int));
  setnonblock_fd(s);

  if (bind(s, &sock, sizeof(sock)) < 0) {
    ast_log(LOG_ERROR, "Cannot bind receiver socket, errno=%d: %s\n", errno, strerror(errno));
    close(s);
    return -1;
  }
  if (sockettype != SOCK_DGRAM)
    if (listen(s, 8) < 0) {
      ast_log(LOG_ERROR, "Cannot listen on socket, errno=%d: %s\n", errno, strerror(errno));
      close(s);
      return -1;
    }
  return s;
}

static int transport_socket(int localport, const char* remotehost, int remoteport)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  char port[8];
  int s, res;

  s = setup_socket(localport, SOCK_DGRAM, 0);
#ifdef xxxusestcp
  if (listen(s, 1) < 0) {
    ast_log(LOG_ERROR, "Cannot listen on UDP socket, errno=%d: %s\n", errno, strerror(errno));
    close(s);
    s = -1;
    return -1;
  }
#endif


  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  sprintf(port, "%d", remoteport);
  res = getaddrinfo(remotehost, port, NULL, &result);
  if (res != 0) {
    ast_log(LOG_ERROR, "Invalid hostname/IP address '%s' or port '%s': %s.\n", remotehost, port, gai_strerror(res)
	    );
    return -1;
  }
  for (rp = result; rp; rp = rp->ai_next) {
    if ((res = connect(s, rp->ai_addr, rp->ai_addrlen)) != -1)
      break;
  }
  if (rp == NULL) {
    ast_log(LOG_ERROR, "Could not connect to hostname/IP address '%s', port '%s': %s.\n", remotehost, port, strerror(errno));
    close(s);
  }
  freeaddrinfo(result);

  return s;
}
#endif
