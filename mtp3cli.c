/* mtp3d.c - mtp2/mtp3 daemon
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


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include "config.h"
#include "mtp3io.h"
#include "mtp.h"

static void usage(void)
{
  fprintf(stderr, "usage: mtp3cli [-h host] [-p port] cmd ...\n");
  exit(1);
}

static int connect_socket(const char* host, const char* port)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, res;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = MTP3_SOCKETTYPE;
  hints.ai_protocol = MTP3_IPPROTO;
  res = getaddrinfo(host, port, NULL, &result);
  if (res != 0) {
    fprintf(stderr, "Invalid hostname/IP address '%s' or port '%s': %s.\n", host, port, gai_strerror(res)
	    );
    return -1;
  }
  for (rp = result; rp; rp = rp->ai_next) {
    res = socket(rp->ai_family, hints.ai_socktype, hints.ai_protocol);
    if (res == -1)
      continue;
    if ((s = connect(res, rp->ai_addr, rp->ai_addrlen)) != -1)
      break;
    close(res);
  }
  if (rp == NULL) {
    fprintf(stderr, "Could not connect to hostname/IP address '%s', port '%s': %s.\n", host, port, strerror(errno));
    res = -1;
  }
  freeaddrinfo(result);
  return res;
}


int main(int argc, char* argv[])
{
  char host[128] = "localhost";
  char port[10] = "11999";
  char buf[10240];
  struct mtp_req* req = (struct mtp_req*) buf;
  int c, i, res;
  int sock;
  struct pollfd fds[1];

  while ((c = getopt(argc, argv, "h:p:")) != -1) {
    switch (c) {
    case 'h':
      strcpy(host, optarg);
      break;
    case 'p':
      strcpy(port, optarg);
      break;
    default:
      usage();
    }
  }
  req->typ = MTP_REQ_CLI;
  *req->buf = 0;
  for (i = optind; i < argc; i++) {
    strcat((char*) req->buf, argv[i]);
    strcat((char*) req->buf, "\n");
  }
  req->len = strlen((char*) req->buf) + 1;
  sock = connect_socket(host, port);
  if (sock == -1)
    return -1;
  res = write(sock, req, sizeof(struct mtp_req) + req->len);
  if (res == -1) {
    fprintf(stderr, "Could not write socket: %s.\n", strerror(errno));
    return -1;
  }
  fds[0].fd = sock;
  fds[0].events = POLLIN|POLLERR|POLLNVAL|POLLHUP;
  res = poll(fds, 1, 10000);
  shutdown(sock, SHUT_WR);
  do {
    res = read(sock, buf, sizeof(buf));
    printf("read %d\n", res);
    if (res == -1) {
      if (errno == ENOTCONN)
	break;
      fprintf(stderr, "Could not read socket: %s.\n", strerror(errno));
      return -1;
    }
    res = write(1, buf, res);
  } while (res != 0);
  return 0;
}
