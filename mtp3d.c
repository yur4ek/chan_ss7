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
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "lffifo.h"
#include "mtp.h"
#include "isup.h"
#include "transport.h"
#include "utils.h"
#include "aststubs.h"
#include "mtp3io.h"
#include "cli.h"
#include "dump.h"


static int do_fork = 0;
static int do_pid = 0;

static struct lffifo **mtp_send_fifo;

#define MAXCLIENTS 32
int n_registry;
struct {
  int ss7_protocol;
  int host_ix;
  struct sockaddr_in client;
  int peerfd;
  struct link* link;
  union {
    struct {
      int subsystem;
    } sccp;
  };
} registry[MAXCLIENTS];

void l4sccp_inservice(struct link* link);
void l4sccp_event(struct mtp_event* event);
void l4sccp_link_status_change(struct link* link, int up);
void l4isup_inservice(struct link* link);
void l4isup_event(struct mtp_event* event);
void l4isup_link_status_change(struct link* link, int up);

int cmd_linkset_status(int fd, int argc, char *argv[]);
int cmd_block(int fd, int argc, char *argv[]);
int cmd_unblock(int fd, int argc, char *argv[]);
int cmd_linestat(int fd, int argc, char *argv[]);
int cmd_cluster_start(int fd, int argc, char *argv[]);
int cmd_cluster_stop(int fd, int argc, char *argv[]);
int cmd_cluster_status(int fd, int argc, char *argv[]);
int cmd_reset(int fd, int argc, char *argv[]);


static pthread_t mtp_thread = 0;
/* This is the monitor thread which mainly handles scheduling/timeouts. */
static int mtp_thread_running = 0;
/* This is the monitor thread which mainly handles scheduling/timeouts. */
static pthread_t monitor_thread = 0;
static int monitor_running = 0;

static int start_mtp_thread(void)
{
  return start_thread(&mtp_thread, mtp_thread_main, &mtp_thread_running, 15);
}

static void stop_mtp_thread(void)
{
    mtp_thread_signal_stop();
    stop_thread(&mtp_thread, &mtp_thread_running);
}



static void process_event(struct mtp_event* event)
{
  switch(event->typ) {
  case MTP_EVENT_ISUP:
    l4isup_event(event);
    break;
  case MTP_EVENT_SCCP:
    l4sccp_event(event);
    break;
	    
  case MTP_EVENT_LOG:
    ast_log(event->log.level, event->log.file, event->log.line,
	    event->log.function, "%s", event->buf);
    break;

  case MTP_EVENT_DUMP:
    dump_event(event);
    break;

  case MTP_EVENT_STATUS:
    {
      struct link* link = event->status.link;
      char* name = link ? link->name : "(peer)";
      switch(event->status.link_state) {
      case MTP_EVENT_STATUS_LINK_UP:
	l4isup_link_status_change(link, 1);
	l4sccp_link_status_change(link, 1);
	ast_log(LOG_WARNING, "MTP is now UP on link '%s'.\n", name);
	break;
      case MTP_EVENT_STATUS_LINK_DOWN:
	l4isup_link_status_change(link, 0);
	l4sccp_link_status_change(link, 0);
	ast_log(LOG_WARNING, "MTP is now DOWN on link '%s'.\n", name);
	break;
      case MTP_EVENT_STATUS_INSERVICE:
	ast_log(LOG_WARNING, "MTP is now INSERVICE for linkset '%s'.\n", link->linkset->name);
	l4isup_inservice(link);
	l4sccp_inservice(link);
	break;
      default:
	ast_log(LOG_NOTICE, "Unknown event type STATUS (%d), "
		"not processed.\n", event->status.link_state);
      }
    }
    break;
  default:
    ast_log(LOG_NOTICE, "Unexpected mtp event type %d.\n", event->typ);
  }
}

/* Monitor thread main loop.
   Monitor reads events from the realtime MTP thread, and processes them at
   non-realtime priority. It also handles timers for ISUP etc.
*/
static void *monitor_main(void *data) {
  int res;
  struct pollfd fds[1];
  struct lffifo *receive_fifo = mtp_get_receive_fifo();

  ast_verbose(VERBOSE_PREFIX_3 "Starting monitor thread, pid=%d.\n", getpid());

  fds[0].fd = get_receive_pipe();
  fds[0].events = POLLIN;

  while(monitor_running) {
    int timeout = 20;

    res = poll(fds, 1, timeout);
    if(res < 0) {
      if(errno == EINTR) {
        /* Just try again. */
      } else {
        ast_log(LOG_ERROR, "poll() failure, errno=%d: %s\n",
                errno, strerror(errno));
      }
    } else if(res > 0) {
      /* Events waiting in the receive buffer. */
      unsigned char dummy[512];
      unsigned char eventbuf[MTP_EVENT_MAX_SIZE];
      struct mtp_event *event;

      /* Empty the pipe before pulling from fifo. This way the race
         condition between mtp and monitor threads may cause spurious
         wakeups, but not loss/delay of messages. */
      res = read(fds[0].fd, dummy, sizeof(dummy));

      /* Process all available events. */
      while((res = lffifo_get(receive_fifo, eventbuf, sizeof(eventbuf))) != 0) {
        if(res < 0) {
          ast_log(LOG_ERROR, "Yuck! oversized frame in receive fifo, bailing out.\n");
          return NULL;
        }
        event = (struct mtp_event *)eventbuf;
	process_event(event);
      }
    }
  }
  return NULL;
}


void l4sccp_inservice(struct link* link)
{
}

void l4sccp_event(struct mtp_event* event)
{
  unsigned char* buf = event->buf;
  int dpc = buf[0] | ((buf[1] & 0x3f) << 8);
  int opc = ((buf[1] & 0xc0) >> 6) | (buf[2] << 2) | ((buf[3] & 0x0f) << 10);
  int typ = buf[4];

  int n;

  ast_log(LOG_DEBUG, "SCCP event, OPC=%d, DPC=%d, typ=%d\n", opc, dpc, typ);
  for (n = 0; n < n_registry; n++) {
    if ((registry[n].ss7_protocol == SS7_PROTO_SCCP) /* xxx check dpc/subsystem */) {
      event->sccp.slinkix = event->sccp.slink->linkix;
      mtp3_reply(registry[n].peerfd, (void*) event, sizeof(*event)+event->len, (const struct sockaddr*) &registry[n].client, sizeof(registry[n].client));
      return;
    }
  }
  if (n == n_registry) {
    ast_log(LOG_ERROR, "Unhandled SCCP event, OPC=%d, DPC=%d, typ=%d\n", opc, dpc, typ);
  }
}

void l4sccp_link_status_change(struct link* link, int up)
{
}


void l4isup_inservice(struct link* link)
{
  if (!mtp_send_fifo)
    mtp_send_fifo = mtp_get_send_fifo();
  ast_log(LOG_NOTICE, "l4isup_inservice link=%s\n", link->name);
}

void l4isup_event(struct mtp_event* event)
{
  ast_log(LOG_DEBUG, "l4isup_event\n");
  struct isup_msg isup_msg;
  int res;

  res = decode_isup_msg(&isup_msg, event->isup.slink->linkset->variant, event->buf, event->len);
  if(!res) {
    /* Q.764 (2.9.5): Discard invalid message.*/
    ast_log(LOG_NOTICE, "ISUP decoding error, message discarded. (typ=%d)\n", isup_msg.typ);
  } else {
    int opc = isup_msg.opc;
    int dpc = isup_msg.dpc;
    int cic = isup_msg.cic;
    int i, n, l;
    struct linkset* linkset = event->isup.slink->linkset;
    ast_log(LOG_DEBUG, "ISUP event, OPC=%d, DPC=%d, CIC=%d, typ=%s\n", opc, dpc,  cic, isupmsg(isup_msg.typ));
    for (n = 0; n < n_registry; n++) {
      if (registry[n].ss7_protocol == SS7_PROTO_ISUP) {
	struct host* host = lookup_host_by_id(registry[n].host_ix);
	for (i = 0; i < host->n_spans; i++) {
	  for (l = 0; l < host->spans[i].n_links; l++) {
	    struct link* link = host->spans[i].links[l];
	    if (link->linkset == linkset) {
	      if ((link->first_cic <= cic) && (link->first_cic+32 > cic)) {
		event->isup.slinkix = event->isup.slink->linkix;
		mtp3_reply(registry[n].peerfd, (void*) event, sizeof(*event)+event->len, (const struct sockaddr*) &registry[n].client, sizeof(registry[n].client));
		return;
	      }
	    }
	  }
	}
      }
    }
    ast_log(LOG_ERROR, "Unhandled ISUP event, OPC=%d, DPC=%d, CIC=%d, typ=%s\n", opc, dpc,  cic, isupmsg(isup_msg.typ));
  }
}

void l4isup_link_status_change(struct link* link, int up)
{
  ast_log(LOG_DEBUG, "l4isup_link_status_change link=%s, up=%d\n", link->name, up);
  link->linkset->inservice += (up*2-1);
  if (up)
    l4isup_inservice(link);
}


static void close_socket(int servsock, int* asockets, int* n_asockets, int p)
{
  int i, j;

  close(servsock);
  for (i = p+1; i < *n_asockets; i++)
    asockets[i-1] = asockets[i];
  (*n_asockets)--;

  for (i = 0; i < n_registry; i++) {
    if (registry[i].peerfd == servsock) {
      for (j = i+1; j < n_registry; j++)
	registry[j-1] = registry[j];
      n_registry--;
      break;
    }
  }
}

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


static void mtp_mainloop(void)
{
  int res;
  struct pollfd fds[MAX_LINKS*2] = {{0,}};
  int n_listen = 0;
  int asockets[MAX_LINKS];
  int n_asockets = 0;
  int rebuild_fds = 1;
  int n_fds = 0;
  unsigned char buf[1024];
  int i, port;

  ast_verbose(VERBOSE_PREFIX_3 "Starting mtp mainloop, pid=%d.\n", getpid());

  for (i = 0; i < this_host->n_slinks; i++) {
    struct link* link = this_host->slinks[i];
    if (strcmp(link->mtp3server_host, this_host->name) == 0) {
      if (*link->mtp3server_port) {
	port = atoi(link->mtp3server_port);
	link->mtp3fd = mtp3_setup_socket(port, 0);
	if (link->mtp3fd == -1) {
	  ast_log(LOG_ERROR, "Could not setup mtp3 listen port %d, %d:%s\n", port, errno, strerror(errno));
	  return;
	}
	printf("Using mtp3 service port %d, socket %d\n", port, link->mtp3fd);
	n_listen++;
      }
    }
  }
  if (!n_listen) {
    fprintf(stderr, "No signaling channels\n");
    exit(1);
  }

  while(monitor_running) {
    int timeout = 2000;
    int servsock;

  loop:
    if (rebuild_fds) {
      rebuild_fds = 0;
      n_fds = 0;

      for (i = 0; i < n_links; i++) {
	struct link* link = &links[i];
	if (link->mtp3fd > -1) {
	  fds[n_fds].fd = link->mtp3fd;
	  fds[n_fds++].events = POLLIN|POLLERR|POLLNVAL|POLLHUP;
	}
      }
      for (i = 0; i < n_asockets; i++) {
	fds[n_fds].fd = asockets[i];
	fds[n_fds++].events = POLLIN|POLLERR|POLLNVAL|POLLHUP;
      }
    }
    res = poll(fds, n_fds, timeout);
    if(res < 0) {
      if(errno == EINTR) {
        /* Just try again. */
      } else {
        ast_log(LOG_ERROR, "poll() failure, errno=%d: %s\n",
                errno, strerror(errno));
      }
    } else if(res > 0) {
      servsock = -1;
      for (i = 0; i < n_fds; i++)
	if(fds[i].revents & (POLLIN|POLLERR|POLLNVAL|POLLHUP)) {
	  servsock = fds[i].fd;
	  break;
	}
      if (servsock < 0)
	continue;
      if(fds[i].revents & (POLLERR|POLLNVAL|POLLHUP)) {
	if (i < n_listen) {
	  rebuild_fds++;
	  continue;
	}
	close_socket(servsock, asockets, &n_asockets, i-n_listen);
	rebuild_fds++;
	continue;
      }
      if (mtp3_sockettype == SOCK_STREAM) {
	if (i < n_listen) {
	  struct sockaddr_in from_addr;
	  unsigned int len = sizeof(struct sockaddr_in);
	  int afd = accept(servsock, (struct sockaddr *)&from_addr, &len);
	  if (afd != -1) {
	    ast_log(LOG_NOTICE, "Accepted socket connection from %s, fd %d\n", inet_ntoa(from_addr.sin_addr), afd);
	    setnonblock_fd(afd);
	    asockets[n_asockets++] = afd;
	    rebuild_fds = 1;
	    continue;
	  }
	  else {
	    ast_log(LOG_WARNING, "Accept of receiver connection failed: %s.\n", strerror(errno));
	  }
	}
      }
      for(;;) {
	struct sockaddr_in from;
	socklen_t fromlen = sizeof(from);
	if (mtp3_ipproto == IPPROTO_TCP)
	  res = recvfrom(servsock, buf, sizeof(struct mtp_req), 0, &from, &fromlen);
	else
	  res = recvfrom(servsock, buf, MTP_REQ_MAX_SIZE, 0, &from, &fromlen);
	if(res == 0) {
	  /* EOF. */
	  close_socket(servsock, asockets, &n_asockets, i-n_listen);
	  rebuild_fds = 1;
	  break;
	} else if(res < 0) {
	  if(errno == EAGAIN || errno == EWOULDBLOCK) {
	    break;
	  } else if(errno == EINTR) {
	    /* Try again. */
	  } else {
	    /* Some unexpected error. */
	    ast_log(LOG_WARNING, "Error reading mtp3 socket %d, errno=%d: %s.\n", servsock, errno, strerror(errno));
	    close_socket(servsock, asockets, &n_asockets, i-n_listen);
	    rebuild_fds = 1;
	    break;
	  }
	} else {
	  struct mtp_req *req = (struct mtp_req *)buf;
#undef inet_ntoa
	  if (fromlen) {
	    if (from.sin_port == 0) {
	      printf("got data from invalid source %s:%d, ignoring\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	    //xxx	    break;
	    }
	  }
	  if ((req->typ == MTP_REQ_ISUP) || (req->typ == MTP_REQ_SCCP) || (req->typ == MTP_REQ_CLI)) {
	    int p = res;
	    do {
	      if (req->len > sizeof(buf)-res) {
		ast_log(LOG_WARNING, "Packet too large %d on fd %d, closing connection.\n", req->len, servsock);
		shutdown(servsock, SHUT_RD);
		res = 0;
	      }
	      else {
		if (mtp3_ipproto == IPPROTO_TCP)
		  res = recvfrom(servsock, &buf[p], req->len, 0, &from, &fromlen);
	      }
	      if (res == 0) {
		ast_log(LOG_WARNING, "Unexpectec EOF on mtp3 socket %d\n", servsock);
		close_socket(servsock, asockets, &n_asockets, i-n_listen);
		rebuild_fds = 1;
		goto loop;
	      }
	      else if (res < 0) {
		if(errno == EINTR) {
		  continue;
		} else {
		  /* Some unexpected error. */
		  ast_log(LOG_WARNING, "Error reading mtp3 socket %d, errno=%d: %s.\n", servsock, errno, strerror(errno));
		  close_socket(servsock, asockets, &n_asockets, i-n_listen);
		  rebuild_fds = 1;
		  goto loop;
		}
	      }
	      p += res;
	    } while ((res > 0) && (p < req->len));
	  }
	  switch (req->typ) {
	  case MTP_REQ_REGISTER_L4:
	    {
	      int i;
	      for (i = 0; i < n_registry; i++) {
		if ((registry->ss7_protocol == req->regist.ss7_protocol) &&
		    (registry[i].host_ix == req->regist.host_ix) &&
		    (memcmp(&registry[i].client.sin_addr, &from.sin_addr, sizeof(from.sin_addr))== 0) &&
		    (registry[i].link == &links[req->regist.linkix])) {
		  if (registry->ss7_protocol == SS7_PROTO_ISUP) {
		      break; /* client re-registers, possibly with new sin_port */
		  } else if (registry->ss7_protocol == SS7_PROTO_ISUP)
		    if (registry[i].sccp.subsystem == req->regist.sccp.subsystem)
		      break;
		}
	      }
	      if (i == MAXCLIENTS) {
		ast_log(LOG_ERROR, "Too many client connections\n");
		break;
	      }
	      registry[i].ss7_protocol = req->regist.ss7_protocol;
	      registry[i].host_ix = req->regist.host_ix;
	      registry[i].peerfd = servsock;
	      registry[i].client = from;
	      if (req->regist.linkix >= n_links) {
		ast_log(LOG_ERROR, "ISUP req register link_ix %d out of range, max %d\n", req->regist.linkix, n_links);
		break;
	      }
	      registry[i].link = &links[req->regist.linkix];
	      if ((req->regist.ss7_protocol == SS7_PROTO_ISUP) ||
		  (req->regist.ss7_protocol == SS7_PROTO_SCCP)) {
		ast_log(LOG_NOTICE, "Registered client protocol %d for link '%s'\n", req->regist.ss7_protocol, links[req->regist.linkix].name);
		if (req->regist.ss7_protocol == SS7_PROTO_SCCP) {
		  registry[i].sccp.subsystem = req->regist.sccp.subsystem;
		}
	      }
	      else
		ast_log(LOG_ERROR, "Unknown req register ss7 protocol %d.\n", req->regist.ss7_protocol);
	      if (i == n_registry)
		n_registry++;
	    }
	    break;
	  case MTP_REQ_ISUP:
	    {
	      int i;
	      struct link* link;
	      for (i = 0; i < n_registry; i++) {
		if ((memcmp((void*) &registry[i].client, (void*) &from, sizeof(from)) == 0) &&
		    (registry[i].ss7_protocol == SS7_PROTO_ISUP)) {
		  link = registry[i].link;
		  if (!mtp_send_fifo) {
		    ast_log(LOG_ERROR, "Send fifo not ready for link '%s'\n", link->name);
		    break;
		  }
		  if (!mtp_send_fifo[link->linkset->lsi]) {
		    ast_log(LOG_ERROR, "Send fifo missing for link '%s', lsi %d\n", link->name, link->linkset->lsi);
		    break;
		  }
		  req->isup.link = NULL;
		  req->isup.slink = &links[req->isup.slinkix];
		  ast_log(LOG_DEBUG, "ISUP req, link %s, slinkix %d\n", link->name, req->isup.slinkix);
		  res = lffifo_put(mtp_send_fifo[req->isup.slink->linkset->lsi], (unsigned char *)req, sizeof(struct mtp_req) + req->len);
		  break;
		}
	      }
	      if (i == n_registry) {
		unsigned char buf[MTP_EVENT_MAX_SIZE];
		struct mtp_event *event = (struct mtp_event*) buf;
		event->typ = MTP_EVENT_REQ_REGISTER;
		event->regist.ss7_protocol = SS7_PROTO_ISUP;
		event->regist.isup.slinkix = req->isup.slinkix;
		event->len = 0;
		mtp3_reply(servsock, (void*) buf, sizeof(*event)+event->len, (const struct sockaddr*) &from, fromlen);
	      }
	    }
	    break;
	  case MTP_REQ_SCCP:
	    {
	      int i;
	      struct link* link;
	      for (i = 0; i < n_registry; i++) {
		if ((memcmp((void*) &registry[i].client, (void*) &from, sizeof(from)) == 0) &&
		    (registry[i].ss7_protocol == SS7_PROTO_SCCP)) {
		  link = &links[req->sccp.slinkix];
		  if (!mtp_send_fifo) {
		    ast_log(LOG_ERROR, "Send fifo not ready for link '%s'\n", link->name);
		    break;
		  }
		  if (!mtp_send_fifo[link->linkset->lsi]) {
		    ast_log(LOG_ERROR, "Send fifo missing for link '%s', lsi %d\n", link->name, link->linkset->lsi);
		    break;
		  }
		  req->sccp.slink = &links[req->sccp.slinkix];
		  ast_log(LOG_DEBUG, "SCCP req, link %s, slinkix %d\n", link->name, req->sccp.slinkix);
		  res = lffifo_put(mtp_send_fifo[req->sccp.slink->linkset->lsi], (unsigned char *)req, sizeof(struct mtp_req) + req->len);
		  break;
		}
	      }
	      if (i == n_registry) {
		unsigned char buf[MTP_EVENT_MAX_SIZE];
		struct mtp_event *event = (struct mtp_event*) buf;
		event->typ = MTP_EVENT_REQ_REGISTER;
		event->regist.ss7_protocol = SS7_PROTO_SCCP;
		event->len = 0;
		mtp3_reply(servsock, (void*) buf, sizeof(*event)+event->len, (const struct sockaddr*) &from, fromlen);
	      }
	    }
	    break;
	  case MTP_REQ_CLI:
	    cli_handle(fds[i].fd, (char*) req->buf);
	    break;
	  default:
	    ast_log(LOG_NOTICE, "Unknown req type %d, closing connection.\n", req->typ);
	    shutdown(fds[i].fd, SHUT_RD);
	    break;
	  }
	}
      }
    }
  }
}

static void setup_dump(const char* fn)
{
  init_dump(0, fn, 1, 1, 0, 0, 1);
}

static void usage(void)
{
  fprintf(stderr, "usage: mtp3d [-c <configdir>] [-m <protocol-dump-file>] [-d] [-p]\n");
  exit(1);
}

  
static void reopen_logfiles(void)
{
  if (!freopen("/var/log/mtp3d.log", "a", stdout)) {
    fprintf(stderr, "Cannot open /var/log/mtp3d.log for writing\n");
    exit(1);
  }
  if (!freopen("/var/log/mtp3d.log", "a", stderr))
    fprintf(stderr, "Cannot open /var/log/mtp3d.log for writing\n");
}

static void sigterm(int p)
{
  monitor_running = 0;
}

static void sighup(int p)
{
  reopen_logfiles();
  ast_log(LOG_NOTICE, "Log file reopened\n");
}

static void sigpipe(int p)
{
}

static void setsigactions(void)
{
  struct sigaction sa;

  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler= sigterm;
  sigaction(SIGTERM, &sa, NULL);
  sa.sa_handler= sighup;
  sigaction(SIGHUP, &sa, NULL);
  sa.sa_handler= sigpipe;
  sigaction(SIGPIPE, &sa, NULL);
}

static int setup_daemon(void)
{
  if (do_fork) {
    if (daemon(0, 1)) {
      fprintf(stderr, "daemon returned error: %d: %s, exiting\n", errno, strerror(errno));
      exit(1);
    }
  }
  setsigactions();
  return 0;
}

static int make_pid_file(void)
{
  if (do_pid) {
    FILE* pidfile = fopen("/var/run/mtp3d.pid", "w");
    if (!pidfile) {
      fprintf(stderr, "Cannot open /var/run/mtp3d.pid %d: %s\n", errno, strerror(errno));
      return 1;
    }
    fprintf(pidfile, "%d\n", getpid());
    fclose(pidfile);
  }
  return 0;
}

int cmd_linkset_status(int fd, int argc, char *argv[])
{
  return 0;
}
int cmd_block(int fd, int argc, char *argv[])
{
  return 0;
}
int cmd_unblock(int fd, int argc, char *argv[])
{
  return 0;
}
int cmd_linestat(int fd, int argc, char *argv[])
{
  return 0;
}
int cmd_cluster_start(int fd, int argc, char *argv[])
{
  return 0;
}
int cmd_cluster_stop(int fd, int argc, char *argv[])
{
  return 0;
}
int cmd_cluster_status(int fd, int argc, char *argv[])
{
  return 0;
}
int cmd_reset(int fd, int argc, char *argv[])
{
  return 0;
}

int main(int argc, char* argv[])
{
  char dumpfn[PATH_MAX] = {0,};
  int c;

  strcpy(ast_config_AST_CONFIG_DIR, "/etc/asterisk");
  
  while ((c = getopt(argc, argv, "fc:m:dp")) != -1) {
    switch (c) {
    case 'c':
      strcpy(ast_config_AST_CONFIG_DIR, optarg);
      break;
    case 'm':
      strcpy(dumpfn, optarg);
      break;
    case 'd':
      option_debug++;
      break;
    case 'f':
      do_fork = 1;
      break;
    case 'p':
      do_pid = 1;
      break;
    default:
      usage();
    }
  }
  is_mtp3d = 1;
  if (do_fork) {
    reopen_logfiles();
  }
  printf("Using %s for config directory\n", ast_config_AST_CONFIG_DIR);
  if(load_config(0)) {
    return -1;
  }
  setsigactions();
  if (*dumpfn)
    setup_dump(dumpfn);
  if (do_pid || do_fork)
    if (setup_daemon())
      return -1;
  if(mtp_init()) {
    ast_log(LOG_ERROR, "Unable to initialize MTP.\n");
    return -1;
  }
  if (do_pid)
  make_pid_file();
  if(start_mtp_thread()) {
    ast_log(LOG_ERROR, "Unable to start MTP thread.\n");
    return -1;
  }
  monitor_running = 1;          /* Otherwise there is a race, and
                                   monitor may exit immediately */
  if(pthread_create(&monitor_thread, NULL, monitor_main, NULL) < 0) {
    ast_log(LOG_ERROR, "Unable to start monitor thread.\n");
    monitor_running = 0;
    return -1;
  }
  mtp_mainloop();
  stop_mtp_thread();
  return 0;
}
