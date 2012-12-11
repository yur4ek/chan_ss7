/* chan_ss7.c - Implementation of SS7 (MTP2, MTP3, and ISUP) for Asterisk.
 *
 * Copyright (C) 2005-2006-2011 Netfors ApS.
 *
 * Author: Kristian Nielsen <kn@sifira.dk>,
 *         Anders Baekgaard <ab@netfors.com>
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

#include <unistd.h>
#include <sys/poll.h>
#include <netinet/in.h>

#include "asterisk.h"
#include "asterisk/channel.h"
#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/options.h"
#include "asterisk/utils.h"
#include "asterisk/sched.h"
#include "asterisk/cli.h"
#include "asterisk/lock.h"

#include "astversion.h"
#include "config.h"
#include "cli.h"
#include "lffifo.h"
#include "utils.h"
#include "mtp.h"
#include "transport.h"
#include "isup.h"
#include "l4isup.h"
#include "cluster.h"
#include "mtp3io.h"
#include "dump.h"

#ifdef USE_ASTERISK_1_2
#define AST_MODULE_LOAD_SUCCESS  0
#define AST_MODULE_LOAD_DECLINE  1
#define AST_MODULE_LOAD_FAILURE -1
#endif

static const char desc[] = "SS7 Protocol Support";
static const char config[] = "ss7.conf";

/* This is the MTP2/MTP3 thread, which runs at high real-time priority
   and is careful not to wait for locks in order not to loose MTP
   frames. */
static pthread_t mtp_thread = AST_PTHREADT_NULL;
static int mtp_thread_running = 0;


/* This is the monitor thread which mainly handles scheduling/timeouts. */
static pthread_t monitor_thread = AST_PTHREADT_NULL;
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
    break;
  case MTP_EVENT_REQ_REGISTER:
    if (event->regist.ss7_protocol == 5) {
      struct link* link = &links[event->regist.isup.slinkix];
      mtp3_register_isup(link->mtp3fd, link->linkix);
    }
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
	ast_log(LOG_WARNING, "MTP is now UP on link '%s'.\n", name);
	break;
      case MTP_EVENT_STATUS_LINK_DOWN:
	l4isup_link_status_change(link, 0);
	ast_log(LOG_WARNING, "MTP is now DOWN on link '%s'.\n", name);
	break;
      case MTP_EVENT_STATUS_INSERVICE:
	ast_log(LOG_WARNING, "Signaling ready for linkset '%s'.\n", link->linkset->name);
	l4isup_inservice(link);
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
  int res = 0, nres;
  struct pollfd fds[(MAX_LINKS+1)];
  int i, n_fds = 0;
  int rebuild_fds = 1;
  struct lffifo *receive_fifo = mtp_get_receive_fifo();
  time_t lastcheck = 0, now;

  ast_verbose(VERBOSE_PREFIX_3 "Starting monitor thread, pid=%d.\n", getpid());

  fds[0].fd = get_receive_pipe();
  fds[0].events = POLLIN;
  while(monitor_running) {
    time(&now);
    if (lastcheck + 10 < now) {
      rebuild_fds = 1;
      lastcheck = now;
    }
    if (rebuild_fds) {
      if (rebuild_fds > 1)
	poll(fds, 0, 200); /* sleep */
      rebuild_fds = 0;
      n_fds = 1;
      for (i = 0; i < n_linksets; i++) {
	struct linkset* linkset = &linksets[i];
	int j;
	for (j = 0; j < linkset->n_links; j++) {
	  int k, l, f = 0;
	  struct link* link = linkset->links[j];
	  for (k = 0; (k < this_host->n_spans) && !f; k++) {
	    for (l = 0; l < (this_host->spans[k].n_links) && !f; l++) {
	      if ((this_host->spans[k].links[l] == link) ||
		  (this_host->spans[k].links[l]->linkset == link->linkset) ||
		  (is_combined_linkset(this_host->spans[k].links[l]->linkset, link->linkset))) {
		if (link->remote) {
		  if (link->mtp3fd == -1) {
		    link->mtp3fd = mtp3_connect_socket(link->mtp3server_host, *link->mtp3server_port ? link->mtp3server_port : "11999");
		    if (link->mtp3fd != -1)
		      res = mtp3_register_isup(link->mtp3fd, link->linkix);
		    else
		      poll(NULL, 0, 5000);
		    if ((link->mtp3fd == -1) || (res == -1))
		      rebuild_fds += 2;
		  }
		  fds[n_fds].fd = link->mtp3fd;
		  fds[n_fds++].events = POLLIN|POLLERR|POLLNVAL|POLLHUP;
		  f = 1;
		}
	      }
	    }
	  }
	}
      }
    }
    int timeout = timers_wait();

    nres = poll(fds, n_fds, timeout);
    if(nres < 0) {
      if(errno == EINTR) {
        /* Just try again. */
      } else {
        ast_log(LOG_ERROR, "poll() failure, errno=%d: %s\n",
                errno, strerror(errno));
      }
    } else if(nres > 0) {
      for (i = 0; (i < n_fds) && (nres > 0); i++) {
	unsigned char eventbuf[MTP_EVENT_MAX_SIZE];
	struct mtp_event *event = (struct mtp_event*) eventbuf;
	struct link* link = NULL;
	if(fds[i].revents) {
	  int j;
	  for (j = 0; j < n_links; j++) {
	    if (links[j].remote && (links[j].mtp3fd == fds[i].fd)) {
	      link = &links[j];
	      break;
	    }
	  }
	}
	else
	  continue;
	if(fds[i].revents & (POLLERR|POLLNVAL|POLLHUP)) {
	  if (i == 0) { /* receivepipe */
	    ast_log(LOG_ERROR, "poll() return bad revents for receivepipe, 0x%04x\n", fds[i].revents);
	  }
	  close(fds[i].fd);
	  if (link)
	    link->mtp3fd = -1;
	  rebuild_fds++; rebuild_fds++; /* when > 1, use short sleep */
	  nres--;
	  continue;
	}
	if(!(fds[i].revents & POLLIN))
	  continue;
	if (i == 0) {
	  /* Events waiting in the receive buffer. */
	  unsigned char dummy[512];

	  /* Empty the pipe before pulling from fifo. This way the race
	     condition between mtp and monitor threads may cause spurious
	     wakeups, but not loss/delay of messages. */
	  res = read(fds[i].fd, dummy, sizeof(dummy));

	  /* Process all available events. */
	  while((res = lffifo_get(receive_fifo, eventbuf, sizeof(eventbuf))) != 0) {
	    if(res < 0) {
	      ast_log(LOG_ERROR, "Yuck! oversized frame in receive fifo, bailing out.\n");
	      return NULL;
	    }
	    process_event(event);
	  }
	}
	else {
	  if (mtp3_ipproto == IPPROTO_TCP) {
	    res = read(fds[i].fd, eventbuf, sizeof(struct mtp_event));
	    if ((res > 0) && (event->len > 0)) {
	      int p = res;
	      int len = event->len;
	      if (sizeof(struct mtp_event) + event->len > MTP_EVENT_MAX_SIZE) {
		ast_log(LOG_NOTICE, "Got too large packet: len %zu, max %zu, closing connection", sizeof(struct mtp_event) + event->len, MTP_EVENT_MAX_SIZE);
		len = 0;
		res = 0;
		shutdown(fds[i].fd, SHUT_RD);
	      }
	      do {
		res = read(fds[i].fd, &eventbuf[p], len);
		if (res > 0) {
		  p += res;
		  len -= res;
		}
		else if ((res < 0) && (errno != EINTR)) {
		  len = 0;
		}
		else {
		  len = 0;
		}
	      } while (len > 0);
	    }
	  }
	  else
	    res = read(fds[i].fd, eventbuf, sizeof(eventbuf)+MTP_MAX_PCK_SIZE);
	  if (res > 0) {
	    if (event->typ == MTP_EVENT_ISUP) {
	      event->isup.link = NULL;
	      event->isup.slink = &links[event->isup.slinkix];
	    }
	    process_event(event);
	  }
	  else if (res == 0) {
	    int j;
	    for (j = 0; j < n_links; j++) {
	      struct link* link = &links[j];
	      if (link->remote && (link->mtp3fd == fds[i].fd)) {
		close(fds[i].fd);
		link->mtp3fd = -1;
		rebuild_fds++;
	      }
	    }
	  }
	}
	nres--;
      }
    }

    /* We need to lock the global glock mutex around ast_sched_runq() so that
       we avoid a race with ss7_hangup. With the lock, invalidating the
       channel in ss7_hangup() and removing associated monitor_sched entries
       is an atomic operation, so that we avoid calling timer handlers with
       references to invalidated channels. */
    run_timers();
  }
  for (i = 0; i < n_links; i++) {
    struct link* link = &links[i];
    if (link->remote && (link->mtp3fd != -1))
      close(link->mtp3fd);
  }
  return NULL;
}


static void stop_monitor(void) {
  int i;

  if(monitor_running) {
    monitor_running = 0;
    /* Monitor wakes up every 1/2 sec, so no need to signal it explicitly. */
    pthread_join(monitor_thread, NULL);
  }
  for (i = 0; i < n_links; i++) {
    struct link* link = &links[i];
    if (link->remote && (link->mtp3fd > -1))
      close(link->mtp3fd);
  }
}


static int ss7_reload_module(void) {
  ast_log(LOG_NOTICE, "SS7 reload not implemented.\n");
  return AST_MODULE_LOAD_SUCCESS;
}


static int ss7_load_module(void)
{
  if(load_config(0)) {
    return AST_MODULE_LOAD_FAILURE;
  }

  if (timers_init()) {
    ast_log(LOG_ERROR, "Unable to initialize timers.\n");
    return AST_MODULE_LOAD_FAILURE;
  }
  if (isup_init()) {
    ast_log(LOG_ERROR, "Unable to initialize ISUP.\n");
    return AST_MODULE_LOAD_FAILURE;
  }
#ifdef SCCP
  if (sccp_init()) {
    ast_log(LOG_ERROR, "Unable to initialize SCCP.\n");
    return AST_MODULE_LOAD_FAILURE;
  }
#endif

  if(mtp_init()) {
    ast_log(LOG_ERROR, "Unable to initialize MTP.\n");
    return AST_MODULE_LOAD_FAILURE;
  }
  if(start_mtp_thread()) {
    ast_log(LOG_ERROR, "Unable to start MTP thread.\n");
    return AST_MODULE_LOAD_FAILURE;
  }
  monitor_running = 1;          /* Otherwise there is a race, and
                                   monitor may exit immediately */
  if(ast_pthread_create(&monitor_thread, NULL, monitor_main, NULL) < 0) {
    ast_log(LOG_ERROR, "Unable to start monitor thread.\n");
    monitor_running = 0;
    return AST_MODULE_LOAD_FAILURE;
  }


  cli_register();

  ast_verbose(VERBOSE_PREFIX_3 "SS7 channel loaded successfully.\n");
  return AST_MODULE_LOAD_SUCCESS;
}


static int ss7_unload_module(void)
{
  cli_unregister();

#ifdef SCCP
  sccp_cleanup();
#endif
  isup_cleanup();

  cleanup_dump(0, 1, 1);
  if(monitor_running) {
    stop_monitor();
  }
  stop_mtp_thread();
  mtp_cleanup();
  timers_cleanup();


  destroy_config();
  ast_verbose(VERBOSE_PREFIX_3 "SS7 channel unloaded.\n");
  return AST_MODULE_LOAD_SUCCESS;
}


#ifdef USE_ASTERISK_1_2
int reload(void)
{
  return ss7_reload_module();
}
int load_module(void)
{
  return ss7_load_module();
}
int unload_module(void)
{
  return ss7_unload_module();
}
char *description() {
  return (char *) desc;
}

char *key() {
  return ASTERISK_GPL_KEY;
}
#else
AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, desc,
                .load = ss7_load_module,
                .unload = ss7_unload_module,
                .reload = ss7_reload_module,
);
#endif
