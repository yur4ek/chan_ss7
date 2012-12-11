/* cluster.c - chan_ss7 clustering/redundancy
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
#include <sys/param.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "asterisk.h"
#include "asterisk/options.h"
#include "asterisk/logger.h"
#include "asterisk/config.h"
#include "asterisk/sched.h"
#include "asterisk/utils.h"
#include "asterisk/cli.h"
#include "asterisk/lock.h"
#include "asterisk/channel.h"


#include "astversion.h"
#include "config.h"
#include "cli.h"
#include "lffifo.h"
#include "utils.h"
#include "mtp3io.h"
#include "mtp.h"
#include "cluster.h"

/* Delay between cluster thread wakeups. */
#define CLUSTER_WAKEUP_INTERVAL 500
#define CLUSTER_KEEP_ALIVE_INTERVAL 500
#define CLUSTER_ALIVE_TIMEOUT 1000
#define CLUSTER_CONNECT_RETRY_INTERVAL 2000
#define CLUSTER_CONNECT_TIMEOUT 10000

static int receivepipe[2] = {-1, -1};
static struct lffifo *receivebuf;

static struct sched_context *cluster_sched = NULL;
static pthread_t cluster_thread = AST_PTHREADT_NULL;
static int cluster_running = 0;

static struct receiver_stat {
  struct {
    int connected;
    int inprogress;
    int fails; /* statistics */
    unsigned long forwards; /* statistics */
    int fd;
    struct timeval lasttry;
    int reported;
  } target[2*MAX_HOSTS];
} receiver_stats[MAX_LINKS_PER_HOST];

int n_accepted = 0;
static struct {
  int fd;
  struct in_addr addr;
  int senderix;
} accepted[2*MAX_HOSTS+2];

static int receiver_socket = -1;

static enum{FD_PIPE, FD_LISTEN, FD_ACCEPTED, FD_RECEIVER, FD_INPROGRESS } fds_type[2*MAX_HOSTS+2];
int n_fds = 0;
static struct pollfd fds[2*MAX_HOSTS+2];
static struct receiver fds_receivers[2*MAX_HOSTS+2];
static int fds_targetix[2*MAX_HOSTS+2];
static int rebuild_fds = 1;

int n_senders = 0;
static struct {
  struct host* host;
  struct in_addr addr;
  int hostix;
  struct timeval last;
  alivestate state;
  int up;
  int down;
} senders[2*MAX_HOSTS];

static struct timeval host_last_event_stamp[MAX_HOSTS] = {{0, 0}, };
static unsigned long host_last_seq_no[MAX_HOSTS] = {0, };

static struct timeval now;

static unsigned long sequence_number = 0;


static void disconnect_receiver(struct receiver* receiver, int targetix);

void (*isup_event_handler)(struct mtp_event*) = NULL;
void (*isup_block_handler)(struct link*) = NULL;

static void set_socket_opt(int s, int l, int o, int v)
{
  int err;
  int len = sizeof(v);

  if ((err = setsockopt(s, l, o, &v, len)) < 0) {
    ast_log(LOG_WARNING, "Cannot set socket option, %s\n", strerror(errno));
  }
}

static void declare_host_state(struct host* host, alivestate state)
{
  if (host->state != state) {
    host->state = state;
    if (state == STATE_DEAD) {
      int i;
      int receiverix, targetix;

      for (receiverix = 0; receiverix < this_host->n_receivers; receiverix++) {
	struct receiver* receiver = &this_host->receivers[receiverix];
	for (targetix = 0; targetix < receiver->n_targets; targetix++) {
	  if (receiver->targets[targetix].host == host)
	    disconnect_receiver(receiver, targetix);
	}
      }
      if (isup_block_handler) {
	for (i = 0; i < host->n_spans; i++) {
	  int l;
	  for (l = 0; l < this_host->spans[i].n_links; l++) {
	    struct link* link = host->spans[i].links[l];
	    if (link->enabled)
	      (*isup_block_handler)(link);
	  }
	}
      }
      ast_log(LOG_WARNING, "No alive signal from %s, assumed down.\n", host->name);
    }
    else if (state == STATE_ALIVE) {
      ast_log(LOG_WARNING, "Alive signal from %s, now up.\n", host->name);
    }
  }
}

static int find_sender(struct host* host, struct in_addr addr)
{
  int i;
  for (i = 0; i < n_senders; i++)
    if ((senders[i].host == host) && (memcmp(&senders[i].addr, &addr, sizeof(addr)) == 0))
      return i;
  return -1;
}

static void add_sender(struct host* host, struct in_addr addr, int hostix)
{
  if (find_sender(host, addr) != -1) {
    ast_log(LOG_NOTICE, "Cluster has multiple identical entries: host %s %s\n", host->name, inaddr2s(addr));
    return;
  }
  senders[n_senders].host = host;
  senders[n_senders].hostix = hostix;
  senders[n_senders].addr = addr;
  senders[n_senders].last.tv_sec = 0;
  senders[n_senders].last.tv_usec = 0;
  senders[n_senders].state = STATE_UNKNOWN;
  senders[n_senders].up = 0;
  senders[n_senders].down = 0;
  ast_log(LOG_DEBUG, "Added host %s %s, hostix %d, id %d\n", host->name, inaddr2s(addr), senders[n_senders].hostix, n_senders);
  n_senders++;
}

static void set_sender_last(int senderix, struct timeval last)
{
  struct host* host = senders[senderix].host;
  senders[senderix].last = last;
  if (senders[senderix].state != STATE_ALIVE) {
    senders[senderix].up += 1;
    ast_log(LOG_WARNING, "Alive signal from %s %s\n", senders[senderix].host->name, inaddr2s(senders[senderix].addr));
  }
  senders[senderix].state = STATE_ALIVE;
  host_last_event_stamp[senders[senderix].hostix] = last;
  declare_host_state(host, STATE_ALIVE);
}

static void check_senders(void)
{
  int i;
  int hostix = 0;
  struct host* host;

  for (i = 0; i < n_senders; i++) {
    int tdiff = timediff_msec(now, senders[i].last);
    if ((tdiff > CLUSTER_ALIVE_TIMEOUT) && (senders[i].state == STATE_ALIVE)) {
      ast_log(LOG_WARNING, "No alive signal from %s %s, for %d msec\n", senders[i].host->name, inaddr2s(senders[i].addr), tdiff);
      senders[i].state = STATE_DEAD;
      senders[i].down += 1;
    }
  }
  while ((host = lookup_host_by_id(hostix)) != NULL) {
    if (host != this_host) {
      int alive = 0;
      int dead = 0;
      for (i = 0; i < n_senders; i++) {
	if (senders[i].host == host) {
	  alive = alive || (senders[i].state == STATE_ALIVE);
	  dead = dead || (senders[i].state == STATE_DEAD);
	}
      }
      if (dead && !alive) {
	int tdiff = timediff_msec(now, host_last_event_stamp[hostix]);
	if (tdiff > CLUSTER_ALIVE_TIMEOUT) {
	  declare_host_state(host, STATE_DEAD);
	}
      }
    }
    hostix++;
  }
}

static void cluster_put(int linkix, unsigned char* buf, int len)
{
  int res = 0;

  if (!cluster_running)
    return;
  res = lffifo_put(receivebuf, (unsigned char *)buf, len);
  if(res) {
    ast_log(LOG_ERROR, "Cluster receive buffer full, packet lost.\n");
    /* Todo FIFO full ... */
  } else {
    res = write(receivepipe[1], &linkix, sizeof(linkix));
    if (res < 0) {
      ast_log(LOG_NOTICE, "Could not write cluster event pipe: %s.\n", strerror(errno));
    }
  }
}

void cluster_mtp_received(struct link* link, struct mtp_event* event)
{
  if (!cluster_running || !this_host->n_receivers)
    return;
  ast_log(LOG_DEBUG, "cluster mtp received on link '%s', typ=%d\n", link ? link->name : "?", event->typ);
  cluster_put(link ? link->linkix : -1, (unsigned char *)event, sizeof(*event) + event->len);
}

void cluster_mtp_sent(struct link* link, struct mtp_req* req)
{
  if (!cluster_running || !this_host->n_receivers)
    return;
  ast_log(LOG_DEBUG, "cluster mtp sent on link '%s', typ=%d\n", link ? link->name : "?", req->typ);
  cluster_put(link ? link->linkix : -1, (unsigned char *)req, sizeof(*req) + req->len);
}

void cluster_mtp_forward(struct mtp_req* req)
{
  int typ = req->typ;
  struct link* link = req->isup.link;
  if (!cluster_running)
    return;
  ast_log(LOG_DEBUG, "cluster mtp forward, link %s, typ=%d, len=%d\n", link ? link->name : "?", req->typ, req->len);
  req->typ = MTP_REQ_ISUP_FORWARD;
  cluster_put(link ? link->linkix : -1, (unsigned char *)req, sizeof(*req) + req->len);
  req->typ = typ;
}

int cluster_receivers_alive(struct linkset* linkset)
{
  int i, j;

  if (this_host->has_signalling_receivers) {
    for (i = 0; i < this_host->n_receivers; i++) {
      for (j = 0; j < this_host->receivers[i].n_targets; j++) {
	struct host* host = this_host->receivers[i].targets[j].host;
	int k, l;
	if (host->state != STATE_ALIVE)
	  continue;
	for (k = 0; k < host->n_spans; k++) {
	  for (l = 0; l < host->spans[k].n_links; l++) {
	    struct link* link = host->spans[k].links[l];
	    if (link->schannel.mask)
	      return 1;
	  }
	}
      }
    }
  }
  return 0;
}

static int setup_receiver_socket(void)
{
  struct sockaddr_in sock;
  in_addr_t addr = INADDR_ANY;

  memset(&sock, 0, sizeof(struct sockaddr_in));
  sock.sin_family = AF_INET;
  sock.sin_port = htons(clusterlistenport);
  memcpy(&sock.sin_addr, &addr, sizeof(addr));

  receiver_socket = socket(PF_INET, SOCK_STREAM, 0);
  if (receiver_socket < 0) {
    ast_log(LOG_ERROR, "Cannot create receiver socket, errno=%d: %s\n", errno, strerror(errno));
    return -1;
  }
  set_socket_opt(receiver_socket, SOL_SOCKET, SO_REUSEADDR, 1);
  if (bind(receiver_socket, &sock, sizeof(sock)) < 0) {
    ast_log(LOG_ERROR, "Cannot bind receiver socket, errno=%d: %s\n", errno, strerror(errno));
    close(receiver_socket);
    receiver_socket = -1;
    return -1;
  }
  if (listen(receiver_socket, MAX_HOSTS) < 0) {
    ast_log(LOG_ERROR, "Cannot listen on receiver socket, errno=%d: %s\n", errno, strerror(errno));
    close(receiver_socket);
    receiver_socket = -1;
    return -1;
  }
  return 0;
}

static void disconnect_receiver(struct receiver* receiver, int targetix)
{
  struct receiver_stat* receiver_stat = &receiver_stats[receiver->receiverix];

  if (receiver_stat->target[targetix].connected || receiver_stat->target[targetix].inprogress) {
    ast_log(LOG_DEBUG, "Disconnect receiver %s %d\n", receiver->targets[targetix].host->name, targetix);
    if (receiver_stat->target[targetix].fd != -1) {
      close(receiver_stat->target[targetix].fd);
      receiver_stat->target[targetix].fd = -1;
    }
    receiver_stat->target[targetix].connected = 0;
    receiver_stat->target[targetix].inprogress = 0;
    receiver_stat->target[targetix].fails += 1;
  }
}

static void connect_receiver(int receiverix, int targetix)
{
  struct sockaddr_in sock;
  struct in_addr addr = this_host->receivers[receiverix].targets[targetix].inf->addr;
  char* host_name = this_host->receivers[receiverix].targets[targetix].host->name;
  int s;
  int flags;
  int res;

  receiver_stats[receiverix].target[targetix].fd = -1;
  receiver_stats[receiverix].target[targetix].connected = 0;
  receiver_stats[receiverix].target[targetix].inprogress = 0;
  gettimeofday(&receiver_stats[receiverix].target[targetix].lasttry, NULL);
  s = socket(PF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    ast_log(LOG_ERROR, "Cannot create receiver socket, errno=%d: %s\n", errno, strerror(errno));
    return;
  }
  memset(&sock, 0, sizeof(struct sockaddr_in));
  sock.sin_family = AF_INET;
  sock.sin_port = htons(clusterlistenport);
  memcpy(&sock.sin_addr, &addr, sizeof(addr));

  res = fcntl(s, F_GETFL);
  if(res < 0) {
    ast_log(LOG_WARNING, "SS7: Could not obtain flags for socket fd: %s.\n", strerror(errno));
    return;
  }
  flags = res | O_NONBLOCK;
  res = fcntl(s, F_SETFL, flags);
  if(res < 0) {
    ast_log(LOG_WARNING, "SS7: Could not set socket fd non-blocking: %s.\n", strerror(errno));
    return;
  }
  ast_log(LOG_DEBUG, "Trying to connect to %s %s\n", host_name, inaddr2s(sock.sin_addr));

  if (connect(s, &sock, sizeof(sock)) < 0) {
    if (errno != EINPROGRESS) {
      ast_log(LOG_ERROR, "Cannot connect receiver socket %s, %s\n", inaddr2s(sock.sin_addr), strerror(errno));
      close(s);
      return;
    }
    // set_socket_opt(s, SOL_TCP, TCP_NODELAY, 1);
  }
  receiver_stats[receiverix].target[targetix].fd = s;
  receiver_stats[receiverix].target[targetix].inprogress = 1;
}

static void connect_receivers(void)
{
  int receiverix, targetix;

  for (receiverix = 0; receiverix < this_host->n_receivers; receiverix++) {
    for (targetix = 0; targetix < this_host->receivers[receiverix].n_targets; targetix++) {
      connect_receiver(receiverix, targetix);
    }
  }
}

static int check_receiver_connections(void)
{
  int receiverix, targetix;
  int any = 0;

  for (receiverix = 0; receiverix < this_host->n_receivers; receiverix++) {
    for (targetix = 0; targetix < this_host->receivers[receiverix].n_targets; targetix++) {
      int tdiff = timediff_msec(now, receiver_stats[receiverix].target[targetix].lasttry);
      if (!receiver_stats[receiverix].target[targetix].connected && !receiver_stats[receiverix].target[targetix].inprogress) {
	if (tdiff > CLUSTER_CONNECT_RETRY_INTERVAL) {
	  any++;
	  connect_receiver(receiverix, targetix);
	}
      }
      else if (receiver_stats[receiverix].target[targetix].inprogress) {
	if (tdiff > CLUSTER_CONNECT_TIMEOUT) {
	  close(receiver_stats[receiverix].target[targetix].fd);
	  receiver_stats[receiverix].target[targetix].inprogress = 0;
	  any++;
	  ast_log(LOG_NOTICE, "Timed out on receiver connection to %s, receiverix %d targetix %d, tdiff %d\n", inaddr2s(this_host->receivers[receiverix].targets[targetix].inf->addr), receiverix, targetix, tdiff);
	}
      }
    }
  }
  return any;
}

static void cluster_send_packet(struct receiver* receiver, int targetix, unsigned char* buf, int len)
{
  int res;
  struct receiver_stat* receiver_stat = &receiver_stats[receiver->receiverix];

  //  ast_log(LOG_DEBUG, "send packet %s, targetix %d, connected %d\n", receiver->targets[targetix].host->name, targetix, receiver_stat->target[targetix].connected);
  if (receiver_stats[receiver->receiverix].target[targetix].connected) {
    gettimeofday(&receiver_stat->target[targetix].lasttry, NULL);
    res = write(receiver_stat->target[targetix].fd, buf, len);
    if (res < 0) {
      close(receiver_stat->target[targetix].fd);
      receiver_stat->target[targetix].connected = 0;
      receiver_stat->target[targetix].fails += 1;
      rebuild_fds = 1;
      ast_log(LOG_ERROR, "Write socket to host '%s' target %d, errno=%d: %s\n", receiver->targets[targetix].host->name, targetix, errno, strerror(errno));
    }
  }
}

static void cluster_send_packets(struct receiver* receiver, unsigned char* buf, int len)
{
  int targetix, firstsendix = -1;
  struct mtp_event* event = (struct mtp_event*) buf;
  struct receiver_stat* receiver_stat = &receiver_stats[receiver->receiverix];

  event->seq_no = sequence_number++;
  for (targetix = 0; targetix < receiver->n_targets; targetix++) {
    ast_log(LOG_DEBUG, "send packets %s, targetix %d, connected %d\n", receiver->targets[targetix].host->name, targetix, receiver_stat->target[targetix].connected);
    if (receiver_stat->target[targetix].connected) {
      if (firstsendix == -1)
	firstsendix = targetix;
      if ((event->typ != MTP_REQ_ISUP_FORWARD) ||
	  ((event->typ == MTP_REQ_ISUP_FORWARD) && /* Only one other host should forward ISUP packet */
	   (receiver->targets[targetix].host == receiver->targets[firstsendix].host)))
	if (event->typ == MTP_REQ_ISUP_FORWARD)
	  receiver_stat->target[targetix].forwards += 1;
	cluster_send_packet(receiver, targetix, buf, len);
    }
  }
}

static void cluster_send_keep_alive(void)
{
  struct mtp_event event;
  int receiverix, targetix;

  event.typ = MTP_EVENT_ALIVE;
  event.len = 0;
  event.seq_no = sequence_number++;
  for (receiverix = 0; receiverix < this_host->n_receivers; receiverix++) {
    for (targetix = 0; targetix < this_host->receivers[receiverix].n_targets; targetix++) {
      int tdiff = timediff_msec(now, receiver_stats[receiverix].target[targetix].lasttry);
      if (tdiff > CLUSTER_KEEP_ALIVE_INTERVAL)
	cluster_send_packet(&this_host->receivers[receiverix], targetix, (unsigned char*) &event, sizeof(event));
    }
  }
}

static int find_next_timeout(void)
{
  int receiverix, targetix;
  int maxwait = CLUSTER_KEEP_ALIVE_INTERVAL;

  for (receiverix = 0; receiverix < this_host->n_receivers; receiverix++) {
    for (targetix = 0; targetix < this_host->receivers[receiverix].n_targets; targetix++) {
      if (receiver_stats[receiverix].target[targetix].connected) {
	int tdiff = timediff_msec(now, receiver_stats[receiverix].target[targetix].lasttry);
	int wait = CLUSTER_KEEP_ALIVE_INTERVAL - tdiff;
	if (wait < maxwait)
	  maxwait = wait;
      }
    }
  }
  if (maxwait < 0)
    maxwait = 0;
  return maxwait;
}

static int cluster_receive_packet(int senderix, int fd)
{
  int res;
  int hostix = senders[senderix].hostix;
  char buf[MTP_EVENT_MAX_SIZE];
  struct mtp_event* event = (struct mtp_event*) &buf;
  struct mtp_req* req = (struct mtp_req*) &buf;
  int sz = sizeof(event->typ);

  res = read(fd, buf, sz);
  if (res <= 0) {
    ast_log(LOG_NOTICE, "Could not read received packet: %s.\n", strerror(errno));
    return -1;
  }
  else if (res == 0) {
    ast_log(LOG_NOTICE, "Received 0 bytes, closing socket: %s.\n", strerror(errno));
    shutdown(fd, SHUT_RDWR);
    return -1;
  }
  if (event->typ < MTP_EVENT_ALIVE) {
    res = read(fd, &buf[sz], sizeof(*req)-sz);
    if (res > 0)
      res = read(fd, req->buf, req->len);
    //    ast_log(LOG_DEBUG, "Received mtp req %d, buff len %d, res %d\n", req->typ, req->len, res);
  }
  else {
    res = read(fd, &buf[sz], sizeof(*event)-sz);
    if (res > 0)
      res = read(fd, event->buf, event->len);
  }
  if (host_last_seq_no[hostix] >= event->seq_no) {
    return 0;
  }
  host_last_seq_no[hostix] = event->seq_no;
  if (res > 0) {
    ast_log(LOG_DEBUG, "Received event, senderix=%d, hostix=%d, lastseq=%ld, seqno=%d, typ=%d\n", senderix, hostix, host_last_seq_no[hostix], event->seq_no, event->typ);
    if ((event->typ == MTP_EVENT_ISUP) || (event->typ == MTP_REQ_ISUP_FORWARD)) {
      if (isup_event_handler)
	(*isup_event_handler)(event);
    }
  }
  if (res < 0)
    ast_log(LOG_NOTICE, "Could not read received packet: %s.\n", strerror(errno));
  return res;
}

static void *cluster_thread_main(void *data)
{
  int i, j;
  int res;
  fds[0].fd = receivepipe[0];
  fds[0].events = POLLIN;
  fds_type[0] = FD_PIPE;
  fds[1].fd = receiver_socket;
  if (receiver_socket > 0)
    fds[1].events = POLLIN;
  else
    fds[1].events = 0;
  fds_type[1] = FD_LISTEN;

  ast_verbose(VERBOSE_PREFIX_3 "Starting cluster thread, pid=%d.\n", getpid());

  while (cluster_running) {
    int timeout;
    int maxtimeout;

    gettimeofday(&now, NULL);
    timeout = ast_sched_wait(cluster_sched);
    maxtimeout = find_next_timeout();
    if(timeout <= 0 || timeout > CLUSTER_WAKEUP_INTERVAL) {
      timeout = CLUSTER_WAKEUP_INTERVAL;
    }
    if (timeout > maxtimeout)
      timeout = maxtimeout;
    if (rebuild_fds) {
      n_fds = 2;
      for (i = 0; i < n_accepted; i++) {
	fds[n_fds].fd = accepted[i].fd;
	fds[n_fds].events = POLLIN|POLLERR|POLLHUP;
	fds_type[n_fds++] = FD_ACCEPTED;
      }
      for (i = 0; i < this_host->n_receivers; i++) {
	for (j = 0; j < this_host->receivers[i].n_targets; j++) {
	  fds_receivers[n_fds] = this_host->receivers[i];
	  fds_targetix[n_fds] = j;
	  if (receiver_stats[i].target[j].connected) {
	    fds[n_fds].fd = receiver_stats[i].target[j].fd;
	    fds[n_fds].events = POLLERR|POLLHUP;
	    fds_type[n_fds++] = FD_RECEIVER;
	  }
	  else if (receiver_stats[i].target[j].inprogress) {
	    fds[n_fds].fd = receiver_stats[i].target[j].fd;
	    fds[n_fds].events = POLLOUT|POLLERR|POLLHUP;
	    fds_type[n_fds++] = FD_INPROGRESS;
	  }
	}
      }
      rebuild_fds = 0;
    }
    res = poll(fds, n_fds, timeout);
    gettimeofday(&now, NULL);

    if(res < 0) {
      if(errno == EINTR) {
        /* Just try again. */
      } else {
        ast_log(LOG_ERROR, "poll() failure, errno=%d: %s\n", errno, strerror(errno));
      }
    } else if(res > 0) {
      for (i = 0; i < n_fds; i++) {
	if(!(fds[i].revents & (POLLERR|POLLNVAL|POLLHUP|POLLIN|POLLOUT)))
	  continue;
	switch (fds_type[i]) {
	case FD_PIPE: {
	  if(fds[i].revents & POLLIN) {
	    int linkix;
	    unsigned char fifobuf[1024];
	    struct mtp_req* req = (struct mtp_req*) &fifobuf;

	    res = read(fds[i].fd, &linkix, sizeof(linkix));
	    if (res < 0) {
	      ast_log(LOG_NOTICE, "Could not read cluster event pipe: %s.\n", strerror(errno));
	      continue;
	    }
	    if ((res = lffifo_get(receivebuf, fifobuf, sizeof(fifobuf))) != 0) {
	      if(res < 0) {
		ast_log(LOG_ERROR, "Got oversize packet in cluster receive buffer.\n");
		continue;
	      }
	    }
	    ast_log(LOG_DEBUG, "fifo get res %d, typ %d, linkix %d, link %s\n", res, req->typ, linkix, links[linkix].name);
	    if (res > 0) {
	      if ((req->typ == MTP_REQ_ISUP) || (req->typ == MTP_REQ_ISUP_FORWARD) || (req->typ == MTP_EVENT_ISUP)) {
		if (links[linkix].receiver) {
		  cluster_send_packets(links[linkix].receiver, fifobuf, res);
		}
		else {
		  ast_log(LOG_WARNING, "No way to send packet to cluster, link='%s', reqtype=%d\n", links[linkix].name, req->typ);
		}
	      }
	    }
	    
	  }
	  break;
	}
	case FD_LISTEN: {
	  if(fds[i].revents & POLLIN) {
	    struct sockaddr_in from_addr;
	    unsigned int len = sizeof(struct sockaddr_in);
	    int afd = accept(receiver_socket, (struct sockaddr *)&from_addr, &len);
	    if (afd != -1) {
	      struct host* host = lookup_host_by_addr(from_addr.sin_addr);
	      if (host) {
		int senderix = find_sender(host, from_addr.sin_addr);
		if (senderix >= 0) {
		  set_sender_last(senderix, now);
		  accepted[n_accepted].fd = afd;
		  accepted[n_accepted].addr = from_addr.sin_addr;
		  accepted[n_accepted++].senderix = senderix;
		  rebuild_fds = 1;
		  host_last_seq_no[senders[senderix].hostix] = 0;
		}
		else {
		  ast_log(LOG_NOTICE, "Got socket connection from unexpected sender %s %s\n", host->name, inaddr2s(from_addr.sin_addr));
		}
	      }
	      ast_log(LOG_NOTICE, "Accepted socket connection from %s, fd %d\n", host?host->name : "unknown", afd);
	    }
	    else {
	      ast_log(LOG_WARNING, "Accept of receiver connection failed: %s.\n", strerror(errno));
	    }
	    break;
	  }
	}
	case FD_ACCEPTED: {
	  int ix = i - 2;
	  int err = 0;
	  if(fds[i].revents & POLLIN) {
	    err = cluster_receive_packet(accepted[ix].senderix, fds[i].fd);
	    set_sender_last(accepted[ix].senderix, now);
	  }
	  if((err == -1) || (fds[i].revents & (POLLERR|POLLNVAL))) {
	    int error;
	    unsigned int len = sizeof(error);
	    getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &error, &len);
	    ast_log(LOG_NOTICE, "Got error on accepted socket: %d %s\n", i, strerror(error));
	    close(fds[i].fd);
	    for (j = ix; j < n_accepted-1; j++)
	      accepted[j] = accepted[j+1];
	    n_accepted--;
	    rebuild_fds = 1;
	  }
	  break;
	}
	case FD_RECEIVER:
	case FD_INPROGRESS: {
	  struct receiver* receiver = &fds_receivers[i];
	  struct receiver_stat* receiver_stat = &receiver_stats[receiver->receiverix];
	  int targetix = fds_targetix[i];
	  char* host_name = receiver->targets[targetix].host->name;
	  char* if_name = receiver->targets[targetix].inf->name;

	  rebuild_fds = 1;
	  if(fds[i].revents & (POLLERR|POLLNVAL)) {
	    if (receiver_stat->target[targetix].reported++ % 100 == 0) {
	      int error;
	      unsigned int len = sizeof(error);
	      getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &error, &len);
	      ast_log(LOG_NOTICE, "Socket connection failed to host: %s, inf %s, addr %s, error: %s\n", host_name, if_name, inaddr2s(receiver->targets[targetix].inf->addr), strerror(error));
	    }
	    disconnect_receiver(receiver, targetix);
	  }
	  else if(fds[i].revents & (POLLHUP)) {
	    ast_log(LOG_NOTICE, "Lost connection to receiver host: %s, inf %s, addr %s\n", host_name, if_name, inaddr2s(receiver->targets[targetix].inf->addr));
	    disconnect_receiver(receiver, targetix);
	  }
	  else if(fds[i].revents & (POLLIN|POLLOUT)) {
	    ast_log(LOG_NOTICE, "Connected to receiver host: %s, inf %s, addr %s \n", host_name, if_name, inaddr2s(receiver->targets[targetix].inf->addr));
	    receiver_stat->target[targetix].connected = 1;
	    receiver_stat->target[targetix].inprogress = 0;
	    receiver_stat->target[targetix].reported = 0;
	  }
	}
	break;
	}
      }
    }
    cluster_send_keep_alive();
    if (check_receiver_connections())
      rebuild_fds = 1;
    check_senders();
  }
  return NULL;
}

static void build_sender_list(void)
{
  int hostix = 0;
  struct host* host = NULL;
  
  while ((host = lookup_host_by_id(hostix)) != NULL) {
    if (host != this_host) {
      int linkix, targetix;

      for (linkix = 0; linkix < host->n_receivers; linkix++) {
	for (targetix = 0; targetix < host->receivers[linkix].n_targets; targetix++) {
	  if (host->receivers[linkix].targets[targetix].host == this_host) {
	    int j;
	    for (j = 0; j < host->n_ifs; j++) {
	      add_sender(host, host->ifs[j].addr, hostix);
	    }
	  }
	}
      }
    }
    hostix++;
  }
  if (!n_senders) {
    ast_log(LOG_DEBUG, "Found no senders to supervise\n");
  }
}

static void wait_for_connections(void)
{
  int cnt;
  int linkix, targetix;
  for (cnt = 0; cnt < 800; cnt++) {
    int n = 0, c = 0;
    for (linkix = 0; linkix < this_host->n_receivers; linkix++) {
      for (targetix = 0; targetix < this_host->receivers[linkix].n_targets; targetix++) {
	c += 1;
	if (receiver_stats[linkix].target[targetix].connected)
	  n += 1;
      }
    }
    if (cnt % 100 == 0)
      ast_log(LOG_DEBUG, "wait %d %d %d %d\n", n, c, n_accepted, n_senders);
    if ((n == c) && (n_accepted == n_senders))
      break;
    usleep(10*1000);
  }
}

int cluster_init(void (*isup_event_handler_callback)(struct mtp_event*),
		 void (*isup_block_handler_callback)(struct link*))
{
  int i, j;

  int res;
  int flags;
  struct sched_param sp;

  isup_event_handler = isup_event_handler_callback;
  isup_block_handler = isup_block_handler_callback;
  build_sender_list();
  for (i = 0; i < this_host->n_receivers; i++) {
    for (j = 0; j < this_host->receivers[i].n_targets; j++) {
      receiver_stats[i].target[j].fd = -1;
      receiver_stats[i].target[j].connected = 0;
      receiver_stats[i].target[j].inprogress = 0;
      receiver_stats[i].target[j].reported = 0;
    }
  }

  for (i = 0; i < this_host->n_receivers; i++) {
    for (j = 0; j < this_host->receivers[i].n_targets; j++) {
      struct host* host = this_host->receivers[i].targets[j].host;
      int l, k;
      for (k = 0; k < host->n_spans; k++) {
	for (l = 0; l < host->spans[k].n_links; l++) {
	  struct link* link = host->spans[k].links[l];
	  if (link->schannel.mask)
	    this_host->has_signalling_receivers = 1;
	}
      }
    }
  }

  if (this_host->has_signalling_receivers)
    if (setup_receiver_socket())
      goto fail;
  connect_receivers();
  receivepipe[0] = receivepipe[1] = -1;
  receivebuf = lffifo_alloc(200000);

  res = pipe(receivepipe);
  if(res < 0) {
    ast_log(LOG_ERROR, "Unable to allocate cluster event pipe: %s.\n",
            strerror(errno));
    goto fail;
  }
  res = fcntl(receivepipe[0], F_GETFL);
  if(res < 0) {
    ast_log(LOG_ERROR, "Could not obtain flags for read end of "
            "cluster event pipe: %s.\n", strerror(errno));
    goto fail;
  }
  flags = res | O_NONBLOCK;
  res = fcntl(receivepipe[0], F_SETFL, flags);
  if(res < 0) {
    ast_log(LOG_ERROR, "Could not set read end of cluster event pipe "
            "non-blocking: %s.\n", strerror(errno));
    goto fail;
  }
  res = fcntl(receivepipe[1], F_GETFL);
  if(res < 0) {
    ast_log(LOG_ERROR, "Could not obtain flags for write end of "
            "cluster event pipe: %s.\n", strerror(errno));
    goto fail;
  }
  flags = res | O_NONBLOCK;
  res = fcntl(receivepipe[1], F_SETFL, flags);
  if(res < 0) {
    ast_log(LOG_ERROR, "Could not set write end of cluster event pipe "
            "non-blocking: %s.\n", strerror(errno));
    goto fail;
  }
  cluster_sched = sched_context_create();
  if(cluster_sched == NULL) {
    ast_log(LOG_ERROR, "Unable to create cluster scheduling context.\n");
    goto fail;
  }

  cluster_running = 1;          /* Otherwise there is a race, and
                                   cluster may exit immediately */
  if(ast_pthread_create(&cluster_thread, NULL, cluster_thread_main, NULL) < 0) {
    ast_log(LOG_ERROR, "Unable to start cluster thread.\n");
    cluster_running = 0;
    goto fail;
  }
  memset(&sp, 0, sizeof(sp));
  sp.sched_priority = 10;
  res = pthread_setschedparam(cluster_thread, SCHED_RR, &sp);
  if(res != 0) {
    ast_log(LOG_WARNING, "Failed to set cluster thread to realtime priority: %s.\n",
            strerror(res));
  }
  wait_for_connections();
  return 0;
 fail:
  cluster_cleanup();
  return -1;
}

void cluster_cleanup(void)
{
  int i, j;

  if(cluster_running) {
    cluster_running = 0;
    /* Monitor wakes up periodically, so no need to signal it explicitly. */
    pthread_join(cluster_thread, NULL);
  }

  if(cluster_sched) {
    sched_context_destroy(cluster_sched);
    cluster_sched = NULL;
  }
  if(receivebuf) {
    lffifo_free(receivebuf);
    receivebuf = NULL;
  }
  if(receivepipe[0] != -1) {
    close(receivepipe[0]);
    receivepipe[0] = -1;
  }
  if(receivepipe[1] != -1) {
    close(receivepipe[1]);
    receivepipe[1] = -1;
  }
  if (receiver_socket != -1) {
    shutdown(receiver_socket, SHUT_RDWR);
    close(receiver_socket);
    receiver_socket = -1;
  }
  for (i = 0; i < n_accepted; i++) {
    shutdown(accepted[i].fd, SHUT_RDWR);
    close(accepted[i].fd);
  }
  n_accepted = 0;


  if (this_host) {
    for (i = 0; i < this_host->n_receivers; i++) {
      for (j = 0; j < this_host->receivers[i].n_targets; j++) {
	if (receiver_stats[i].target[j].connected || receiver_stats[i].target[j].inprogress) {
	  shutdown(receiver_stats[i].target[j].fd, SHUT_RDWR);
	  close(receiver_stats[i].target[j].fd);
	  receiver_stats[i].target[j].connected = 0;
	  receiver_stats[i].target[j].inprogress = 0;
	}
      }
    }
  }
  n_senders = 0;
}


int cmd_cluster_start(int fd, int argc, argv_type argv)
{
  if (!cluster_running)
    return cluster_init(isup_event_handler, isup_block_handler);
  return 0;
}

int cmd_cluster_stop(int fd, int argc, argv_type argv)
{
  if (cluster_running)
    cluster_cleanup();
  return 0;
}

int cmd_cluster_status(int fd, int argc, argv_type argv)
{
  int i;
  int linkix, targetix;

  gettimeofday(&now, NULL);
  for (i = 0; i < n_senders; i++) {
    int tdiff = timediff_msec(now, senders[i].last);
    char* s = "";
    switch (senders[i].state) {
    case STATE_UNKNOWN:
      s = "unknown"; tdiff = 0; break;
    case STATE_ALIVE:
      s = "alive"; break;
    case STATE_DEAD:
      s = "dead"; break;
    }
    ast_cli(fd, "sender %s, addr %s, state %s, last %d msec, up %d, down %d\n", senders[i].host->name, inaddr2s(senders[i].addr), s, tdiff, senders[i].up, senders[i].down);
  }
  for (linkix = 0; linkix < this_host->n_receivers; linkix++) {
    for (targetix = 0; targetix < this_host->receivers[linkix].n_targets; targetix++) {
      char* if_name = this_host->receivers[linkix].targets[targetix].inf->name;
      char* host_name = this_host->receivers[linkix].targets[targetix].host->name;
      struct in_addr addr = this_host->receivers[linkix].targets[targetix].inf->addr;
      char* c = (receiver_stats[linkix].target[targetix].connected) ? "connected" : "";
      char* p = (receiver_stats[linkix].target[targetix].inprogress) ? "inprogress" : "";
      int tdiff = timediff_msec(now, receiver_stats[linkix].target[targetix].lasttry);

      ast_cli(fd, "receiver %s if %s, addr %s, c:%s, p:%s, last try %d msec, %d fails, %lu forwards\n",
	      host_name, if_name,  inaddr2s(addr), c, p,
	      tdiff, receiver_stats[linkix].target[targetix].fails,
	      receiver_stats[linkix].target[targetix].forwards);
    }
  }
  return 0;
}

