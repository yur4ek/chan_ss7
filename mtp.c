/* mtp.c - MTP2 and MTP3 functionality.
 *
 * Copyright (C) 2005-2011 Netfors ApS.
 *
 * Author: Kristian Nielsen <kn@sifira.dk>
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

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#ifdef USE_ZAPTEL
#include "zaptel.h"
#define FAST_HDLC_NEED_TABLES
#include "fasthdlc.h"
#define DAHDI_EVENT_DIALCOMPLETE ZT_EVENT_DIALCOMPLETE
#define DAHDI_DIALING ZT_DIALING
#define DAHDI_GETGAINS ZT_GETGAINS
#define DAHDI_SETGAINS ZT_SETGAINS
#define DAHDI_LAW_ALAW ZT_LAW_ALAW
#define DAHDI_LAW_MULAW ZT_LAW_MULAW
#define DAHDI_SIG_MTP2 ZT_SIG_MTP2
#define DAHDI_SIG_HDLCFCS ZT_SIG_HDLCFCS
#else
#include <dahdi/user.h>
#define FAST_HDLC_NEED_TABLES
#include <dahdi/fasthdlc.h>
#endif

#include "config.h"
#include "mtp3io.h"
#include "mtp.h"
#include "transport.h"
#include "lffifo.h"
#include "cluster.h"
#include "utils.h"

#ifdef MTP_STANDALONE
#include "aststubs.h"
#define cluster_mtp_received(link, event) {}
#define cluster_mtp_forward(req) {}
#define cluster_receivers_alive(linkset) (0)
#define ast_mutex_destroy pthread_mutex_destroy
#define ast_mutex_lock pthread_mutex_lock
#define ast_mutex_unlock pthread_mutex_unlock
#else
#include "asterisk.h"
#include "asterisk/options.h"
#include "asterisk/logger.h"
#include "asterisk/sched.h"
#include "asterisk/lock.h"
#define mtp_sched_add ast_sched_add
#define mtp_sched_del ast_sched_del
#define mtp_sched_runq ast_sched_runq
#define mtp_sched_context_create sched_context_create
#define mtp_sched_context_destroy sched_context_destroy
#endif

/* NOTE: most of this code is run in the MTP thread, and has realtime
   constraints because of the need to constantly feed/read the
   signalling link with low latence and no frame drop.

   The thread runs with high realtime priority, and any kind of
   locking should generally be avoided. This includes ast_log() (use
   fifo_log() instead), and malloc()/free()!
*/


/* For testing failover mechanism */
int testfailover = 0;

/* #define DROP_PACKETS_PCT 66 */
/* #define DO_RAW_DUMPS */

/* Scheduling context for MTP2. */
/* This should ONLY be used by the MTP2 thread, otherwise the locking done
   by the sched operations may fatally delay the MTP2 thread because of
   priority inversion. */
static struct sched_context *mtp2_sched = NULL;

/* Set true to ask mtp thread to stop */
static int stop_mtp_thread;
static int receivepipe[2] = {-1, -1};
/* Lock-free FIFOs for communication with the MTP thread.
   The sendbuf is polled by the MTP thread whenever the link is ready to
   transmit data (every 2msec). It contains struct mtp_req entries for
   the higher level protocol layers (currently only ISUP).
   The receivebuf has an associated event pipe, and the MTP thread do
   non-blocking dummy writes to it whenever blocks are put in the buffer.
   The SS7 monitor thread can then wait for new data in poll(). The
   receivebuf contains struct mtp_event entries.
   The controlbuf is polled by the MTP thread, it contains struct mtp_req
   entries for control purposes only.
 */
struct lffifo *sendbuf[MAX_LINKSETS];
struct lffifo *receivebuf;
struct lffifo *controlbuf;


typedef struct mtp2_state {

  /* MTP2 stuff. */

  enum {
    /* Link is stopped by management command, will not go up until
       started explicitly. */
    MTP2_DOWN,
    /* Initial alignment has started, link is transmitting 'O', but no 'O',
       'N', or 'E' has been received. */
    MTP2_NOT_ALIGNED,
    /* 'O' has been received, 'N' or 'E' is transmitted. */
    MTP2_ALIGNED,
    /* 'N' or 'E' is transmitted and received. Runs for the duration of T4 to
       check that the link is of sufficient quality in terms of error rate. */
    MTP2_PROVING,
    /* Local T4 expired, and we are sending FISU, but remote is still
       proving. */
    MTP2_READY,
    /* The link is active sending and receiving FISU and MSU. */
    MTP2_INSERVICE,
  } state;

  /* Counts of raw bytes read and written, used to timestamp raw dumps.
     Make them long long to avoid overflow for quite a while. */
  long long readcount, writecount;

  /* Sequence numbers and indicator bits to be sent in signalling units. */
  int send_fib;
  int send_bsn, send_bib;

  /* Send initial SLTM? */
  int send_sltm;

  /* Timeslot for signalling channel */
  int schannel;
  struct link* link;
  int sls;
  int subservice;
  /* logical link name */
  char* name;
  /* Open fd for signalling link dahdi device. */
  int fd;
  int hwmtp2;
  int hwhdlcfcs;

  /* Receive buffer. */
  unsigned char rx_buf[272 + 7];
  int rx_len;
  unsigned short rx_crc;

  /* Transmit buffer. */
  unsigned char tx_buffer[272 + 7 + 5];
  int tx_len;
  int tx_sofar;
  int tx_do_crc;                /* Flag used to handle writing CRC bytes */
  unsigned short tx_crc;

  /* Dahdi transmit buffer. */
  unsigned char zap_buf[ZAP_BUF_SIZE];
  int zap_buf_full;

  /* HDLC encoding and decoding state. */
  struct fasthdlc_state h_rx;
  struct fasthdlc_state h_tx;

  /* Last few raw bytes received, for debugging link errors. */
  unsigned char backbuf[36];
  int backbuf_idx;

  /* Retransmit buffer. */
  struct { int len; unsigned char buf[MTP_MAX_PCK_SIZE]; } retrans_buf[128];
  /* Retransmit counter; if this is != -1, it means that retransmission is
     taking place, with this being the next sequence number to retransmit. */
  int retrans_seq;
  /* Last sequence number ACK'ed by peer. */
  int retrans_last_acked;
  /* Last sequence number sent to peer. */
  int retrans_last_sent;
  /* Counter for signal unit/alignment error rate monitors (Q.703 (10)). */
  int error_rate_mon;
  /* Counters matching the D and N values of the error rate monitors. */
  int emon_ncount, emon_dcount;
  /* Counter for bad BSN */
  int bsn_errors;
  /* Q.703 timer T1 "alignment ready" (waiting for peer to end initial
     alignment after we are done). */
  int mtp2_t1;
  /* Q.703 timer T2 "not aligned" (waiting to receive O, E, or N after sending
     O). */
  int mtp2_t2;
  /* Q.703 timer T3 "aligned" (waiting to receive E or N after sending E or
     N). */
  int mtp2_t3;
  /* Q.703 timer T4 "proving period" - proving time before ending own initial
     alignment. */
  int mtp2_t4;
  /* Q.703 timer T7 "excessive delay of acknowledgement" . */
  int mtp2_t7;

  /* Set true when SLTA is received and User Parts (ie. ISUP) is notified that
     the link is now in service. */
  int level4_up;

  /* Hm, the rest is actually MTP3 state. Move to other structure, or
     rename this structure. */
  int sltm_t1;                  /* Timer T1 for SLTM (Q.707) */
  int sltm_t2;                  /* Timer T2 for SLTM (Q.707) */
  int sltm_tries;               /* For SLTM retry (Q.707 (2.2)) */

  /* Q.704 timer T17, "initial alignment restart delay". */
  int mtp3_t17;
} mtp2_t;

/* ToDo: Support more than one signalling link ... */
/* ToDo: Need real initialization, that doesn't depend on linker. */
mtp2_t mtp2_state[MAX_SCHANNELS];
int n_mtp2_state;

/* Get the next sequence number, modulo 128. */
#define MTP_NEXT_SEQ(x) (((x) + 1) % 128)

/* Forward declaration, needed because of cyclic reference graph. */
static void start_initial_alignment(mtp2_t *m, char* reason);
static void abort_initial_alignment(mtp2_t *m);
static void mtp2_cleanup(mtp2_t *m);
static void mtp2_queue_msu(mtp2_t *m, int sio, unsigned char *sif, int len);
static void deliver_l4(mtp2_t *m, int opc, int dpc, short slc, unsigned char *sif, int len, unsigned char sio);
static void l4up(mtp2_t* m);
static void l4down(mtp2_t* m);
static void t7_stop(mtp2_t *m);
static void fifo_log(mtp2_t *m, int level, const char *file, int line,
		     const char *function, const char *format, ...)
     __attribute__ ((format (printf, 6, 7)));
static void process_msu(struct mtp2_state* m, unsigned char* buf, int len);


/* Send fifo for sending control requests to the MTP thread.
   The fifo is lock-free (one thread may put and another get simultaneously),
   but multiple threads doing put must be serialized with this mutex. */
AST_MUTEX_DEFINE_STATIC(mtp_control_mutex);
/* Queue a request to the MTP thread. */
void mtp_enqueue_control(struct mtp_req *req) {
  int res;

  ast_mutex_lock(&mtp_control_mutex);
  res = lffifo_put(controlbuf, (unsigned char *)req, sizeof(struct mtp_req) + req->len);
  ast_mutex_unlock(&mtp_control_mutex);
  if(res != 0) {
    ast_log(LOG_WARNING, "MTP control fifo full (MTP thread hanging?).\n");
  }
}


static void delete_timer(struct sched_context *con, int id)
{
  int res = mtp_sched_del(con, id);
  if (res) {
    ast_log(LOG_ERROR, "Failed to delete timer\n");
  }
}


static inline ss7_variant variant(mtp2_t* m)
{
  return m->link->linkset->variant;
}

int mtp2_slink_inservice(int ix) {
  struct mtp2_state* m = &mtp2_state[ix];
  return m->state == MTP2_INSERVICE;
}

int cmd_mtp_linkstatus(char* buff, int details, int slinkno)
{
  char* format;
  char r[1024];
  int i;

  char* s = "?";
  if (slinkno >= this_host->n_slinks)
    return -1;
  *buff = 0;
  for (i = 0; i < n_mtp2_state; i++) {
    if (mtp2_state[i].link != this_host->slinks[slinkno])
      continue;
    struct mtp2_state* m = &mtp2_state[i];
    switch (m->state) {
    case MTP2_DOWN: s = "DOWN"; break;
    case MTP2_NOT_ALIGNED: s = "NOT_ALIGNED"; break;
    case MTP2_ALIGNED: s = "ALIGNED"; break;
    case MTP2_PROVING: s = "PROVING"; break;
    case MTP2_READY: s = "READY"; break;
    case MTP2_INSERVICE: s = "INSERVICE"; break;
    default: s = "UNKNOWN";
    }
    format = "linkset:%s, link:%s/%d, state:%s, sls:%d, total: %6llu/%6llu\n";
    sprintf(r, format, m->link->linkset->name, m->link->name, m->schannel+1, s, m->sls, m->readcount, m->writecount);
    strcat(buff, r);
  }
  return 0;
}

int cmd_mtp_data(int fd, int argc, argv_type argv)
{
  unsigned char buf[MTP_EVENT_MAX_SIZE];
  int len = 0;
  int i;
  mtp2_t* m = &mtp2_state[0];

  for (i = 3; i < argc; i++) {
    char* p = argv[i];
    while (*p) {
      char b[3];
      unsigned int v;
      if (*p == ' ') {
	p++;
	continue;
      }
      b[0] = *p++;
      b[1] = *p++;
      b[2] = 0;
      sscanf(b, "%x", &v);
      buf[len++] = v;
    }
  }
  mtp2_queue_msu(m, 3, buf, len);
  deliver_l4(m, 0, 0, 0, &buf[0], len, MTP_EVENT_SCCP);
  return 0;
}


static inline int peeropc(mtp2_t* m)
{
  return m->link->linkset->opc;
}


static inline int peerdpc(mtp2_t* m)
{
  return m->link->linkset->dpc;
}

static inline int linkpeerdpc(mtp2_t* m)
{
  if (m->link->dpc)
    return m->link->dpc;
  return m->link->linkset->dpc;
}


static mtp2_t* findtargetslink(mtp2_t *originalm, int sls)
{
  int i;
  struct link* link = originalm->link;
  struct mtp2_state* bestm = NULL;

  for (i = 0; i < n_mtp2_state; i++) {
    struct mtp2_state* m = &mtp2_state[i];
    struct link* slink = m->link;
    if (m->sls == sls) {
      if (link->linkset == slink->linkset) {
	fifo_log(m, LOG_DEBUG, "Target slink %s %d -> %s\n", originalm->name, sls, m->name);
        return m;
      }
      if (is_combined_linkset(link->linkset, slink->linkset))
        bestm = m;
    }
  }
  fifo_log(originalm, LOG_DEBUG, "Target slink %s %d -> %s\n", originalm->name, sls, bestm ? bestm->name : "(none)");
  return bestm;
}


static void mtp_put(mtp2_t *m, struct mtp_event *event) {
  static int log_safe_count = 0;
  int res;

  res = lffifo_put(receivebuf, (unsigned char *)event,
                   sizeof(*event) + event->len);
  if(res) {
    /* Can't fifo_log() here, or we would get an infinite loop. */
    /* Still, avoid excessive logging if the other thread gets long behind. */
    if(log_safe_count == 0) {
      ast_log(LOG_NOTICE, "Full MTP receivebuf, event lost, type=%d.\n", event->typ);
      log_safe_count = 2000;
    }
  } else {
    /* Wake up the other end. */
    res = write(receivepipe[1], "\0", 1);
  }
  if ((event->typ == MTP_EVENT_ISUP) || (event->typ == MTP_EVENT_STATUS)) {
    cluster_mtp_received(m ? m->link : NULL, event);
  }

  if(log_safe_count > 0) {
    log_safe_count--;
  }
}

/* Use this instead of ast_log() in the MTP thread, to avoid locking
   issues interupting the link timing.
   Note that LOG_WHATEVER includes all of (level, file, line, function), thanks
   to #define trickery in asterisk/logger.h! */

/* Grmble... stupid GCC allows the __attribute__ only in a
   declaration, not definition. */
static void fifo_log(mtp2_t *m, int level, const char *file, int line,
		     const char *function, const char *format, ...)
{
  va_list arg;
  unsigned char buf[MTP_EVENT_MAX_SIZE];
  struct mtp_event *event = (struct mtp_event *)buf;

  memset(event, 0, sizeof(*event));
  event->typ = MTP_EVENT_LOG;
  event->log.level = level;
  event->log.file = file;
  event->log.line = line;
  event->log.function = function;
  va_start(arg, format);
  vsnprintf((char*)event->buf, sizeof(buf) - sizeof(struct mtp_event), format, arg);
  va_end(arg);
  event->len = strlen((char*)event->buf) + 1;
  mtp_put(m, event);
}

static void log_frame(mtp2_t *m, int out, unsigned char *buf, int len) {
  unsigned char ebuf[MTP_EVENT_MAX_SIZE];
  struct mtp_event *event = (struct mtp_event *)ebuf;

  memset(event, 0, sizeof(*event));
  event->typ = MTP_EVENT_DUMP;
  event->dump.out = out;
  gettimeofday(&event->dump.stamp, NULL);
  event->dump.sls = m->sls;
  if(sizeof(struct mtp_event) + len > MTP_MAX_PCK_SIZE) {
    len = MTP_MAX_PCK_SIZE - sizeof(struct mtp_event);
  }
  event->len = len;
  memcpy(event->buf, buf, len);
  mtp_put(m, event);
}

#ifdef DO_RAW_DUMPS
static void mtp2_dump_raw(mtp2_t *m, unsigned char *buf, int len, int out) {
  unsigned char ebuf[MTP_EVENT_MAX_SIZE];
  struct mtp_event *event = (struct mtp_event *)ebuf;

  memset(event, 0, sizeof(*event));
  event->typ = MTP_EVENT_RAWDUMP;
  event->rawdump.out = out;
  if(sizeof(struct mtp_event) + len > MTP_MAX_PCK_SIZE) {
    len = MTP_MAX_PCK_SIZE - sizeof(struct mtp_event);
  }
  event->len = len;
  memcpy(event->buf, buf, len);
  mtp_put(m, event);
}
#endif

static int t17_timeout(const void *data) {
  mtp2_t *m = (mtp2_t*) data;
  fifo_log(m, LOG_DEBUG, "link %s\n", m->name);
  m->mtp3_t17 = -1;
  start_initial_alignment(m, "t17_timeout");
  return 0;                     /* Do not re-schedule */
}

static void t17_stop(mtp2_t *m)
{
  if(m->mtp3_t17 != -1) {
    delete_timer(mtp2_sched, m->mtp3_t17);
    m->mtp3_t17 = -1;
  }
}

static void t17_start(mtp2_t *m) {
  t17_stop(m);
  m->mtp3_t17 = mtp_sched_add(mtp2_sched, 1200, t17_timeout, m);
}

static int t1_timeout(const void *data) {
  mtp2_t *m = (mtp2_t*) data;
  fifo_log(m, LOG_WARNING, "MTP2 timer T1 timeout (peer failed to complete "
	   "initial alignment), initial alignment failed on link '%s'.\n", m->name);
  m->mtp2_t1 = -1;
  abort_initial_alignment(m);
  return 0;                     /* Do not re-schedule */
}

static void t1_stop(mtp2_t *m)
{
  if(m->mtp2_t1 != -1) {
    delete_timer(mtp2_sched, m->mtp2_t1);
    m->mtp2_t1 = -1;
  }
}

static void t1_start(mtp2_t *m)
{
  int v;
  t1_stop(m);
  switch (variant(m)) {
  case ITU_SS7: v = 45000; break;
  case ANSI_SS7: v = 16000; break;
  case CHINA_SS7: v = 45000; break;
  }
  m->mtp2_t1 = mtp_sched_add(mtp2_sched, v, t1_timeout, m);
}

static int t2_timeout(const void *data) {
  mtp2_t *m = (mtp2_t*) data;
  fifo_log(m, LOG_WARNING, "MTP2 timer T2 timeout (failed to receive 'O', 'N', "
	   "or 'E' after sending 'O'), initial alignment failed on link '%s'.\n", m->name);
  m->mtp2_t2 = -1;
  abort_initial_alignment(m);
  return 0;                     /* Do not re-schedule */
}

static void t2_stop(mtp2_t *m)
{
  if(m->mtp2_t2 != -1) {
    delete_timer(mtp2_sched, m->mtp2_t2);
    m->mtp2_t2 = -1;
  }
}

static void t2_start(mtp2_t *m)
{
  int v;
  t2_stop(m);
  switch (variant(m)) {
  case ITU_SS7: v = 75000; break;
  case ANSI_SS7: v = 11500; break;
  case CHINA_SS7: v = 75000; break;
  }
  m->mtp2_t2 = mtp_sched_add(mtp2_sched, v, t2_timeout, m);
}

static int t3_timeout(const void *data) {
  mtp2_t *m = (mtp2_t*) data;
  fifo_log(m, LOG_WARNING, "MTP2 timer T3 timeout (failed to receive 'N', "
	   "or 'E' after sending 'O'), initial alignment failed on link '%s'.\n", m->name);
  m->mtp2_t3 = -1;
  abort_initial_alignment(m);
  return 0;                     /* Do not re-schedule */
}

static void t3_stop(mtp2_t *m)
{
  if(m->mtp2_t3 != -1) {
    delete_timer(mtp2_sched, m->mtp2_t3);
    m->mtp2_t3 = -1;
  }
}

static void t3_start(mtp2_t *m)
{
  int v;
  t3_stop(m);
  switch (variant(m)) {
  case ITU_SS7: v = 1500; break;
  case ANSI_SS7: v = 11500; break;
  case CHINA_SS7: v = 1500; break;
  }
  m->mtp2_t3 = mtp_sched_add(mtp2_sched, v, t3_timeout, m);
}

static int t4_timeout(const void *data) {
  mtp2_t *m = (mtp2_t*) data;
  fifo_log(m, LOG_DEBUG, "Proving successful on link '%s'.\n", m->name);
  m->state = MTP2_READY;
  m->mtp2_t4 = -1;
  t1_start(m);
  return 0;                     /* Do not re-schedule */
}

static void t4_stop(mtp2_t *m)
{
  if(m->mtp2_t4 != -1) {
    delete_timer(mtp2_sched, m->mtp2_t4);
    m->mtp2_t4 = -1;
  }
}

static void t4_start(mtp2_t *m)
{
  int v;
  t4_stop(m);
  switch (variant(m)) {
  case ITU_SS7: v = 500; break;
  case ANSI_SS7: v = 600; break;
  case CHINA_SS7: v = 500; break;
  }
  m->mtp2_t4 = mtp_sched_add(mtp2_sched, v, t4_timeout, m);
}

static struct mtp2_state* get_inservice_schannel(struct link* link)
{
  int i;
   for (i = 0; i < n_mtp2_state; i++) {
    struct mtp2_state* m = &mtp2_state[i];
    if (m->state == MTP2_INSERVICE) {
      struct link* slink = m->link;
      if (link->linkset == slink->linkset ||
	  is_combined_linkset(link->linkset, slink->linkset))
	return m;
    }
  }
  return NULL;
}

int mtp_has_inservice_schannels(struct link* link)
{
  return (get_inservice_schannel(link) != NULL);
}


/* Flush MTP transmit buffer to other link or host */
static void mtp_changeover(mtp2_t *m) {
  struct mtp2_state* newm = NULL;
  int i;
  int do_forward = 1;

  for (i = 0; i < n_mtp2_state; i++) {
    struct mtp2_state* newm = &mtp2_state[i];
    if (&mtp2_state[i] == m)
      continue;
    if (m->link->linkset != newm->link->linkset)
      continue;
    if (mtp2_state[i].state == MTP2_INSERVICE) {
      newm = &mtp2_state[i];
      break;
    }
  }
  if (!newm) {
    fifo_log(m, LOG_NOTICE, "MTP changeover last_ack=%d, last_sent=%d, from schannel %d, no INSERVICE schannel found\n", m->retrans_last_acked, m->retrans_last_sent, m->schannel+1);
    if (this_host->has_signalling_receivers)
      fifo_log(m, LOG_NOTICE, "Failover, using another host for signalling.\n");
    if (!cluster_receivers_alive(m->link->linkset)) {
      fifo_log(m, LOG_NOTICE, "Failover not possible, no other signalling link and no other host available.\n");
#if 1
      /* Remove all MSU's - the user parts must deal with lost PDU's */
      m->retrans_last_acked = MTP_NEXT_SEQ(m->retrans_last_sent);
      m->retrans_seq = -1;
#endif
      return;
    }
  }
  fifo_log(m, LOG_NOTICE, "MTP changeover last_ack=%d, last_sent=%d, from schannel %d, to schannel %d\n", m->retrans_last_acked, m->retrans_last_sent, m->schannel+1, newm ? newm->schannel+1 : -1);
  i = MTP_NEXT_SEQ(m->retrans_last_acked);
  while (i != MTP_NEXT_SEQ(m->retrans_last_sent)) {
    int sio = m->retrans_buf[i].buf[3];
    int len = m->retrans_buf[i].len-4;
    unsigned char* buf = &m->retrans_buf[i].buf[4];
    fifo_log(m, LOG_DEBUG, "MTP changeover seqno=%d, sio=%d, len=%d, is_moved=%d\n", i, sio, len, (sio & 0xf) > 3);
    if (do_forward && ((sio & 0xf) >= 3)) { /* User and application parts */
      if (newm) {
	mtp2_queue_msu(newm, sio, buf, len);
      }
      else {
	if ((sio & 0xf) == 0x5 /* ISUP */) {
	  unsigned char reqbuf[MTP_REQ_MAX_SIZE];
	  struct mtp_req *req = (struct mtp_req*) &reqbuf;
	  memcpy(req->buf, buf, len);
	  req->len = len;
	  req->typ = MTP_REQ_ISUP;
	  cluster_mtp_forward(req);
	}
      }
      m->retrans_buf[i].buf[3] = 0;
      m->retrans_buf[i].len = 5; /* Is now a LSSU */
      m->retrans_buf[i].buf[3] = 2;
      i = MTP_NEXT_SEQ(i);
    }
  }
}

/* Called on link errors that occur during initial alignment (before the link
   is in service), and which should cause initial alignment to be aborted. The
   initial alignment to be re-tried after a short delay (MTP3 T17). */
static void abort_initial_alignment(mtp2_t *m)
{
  mtp2_cleanup(m);
  m->state = MTP2_DOWN;
  /* Retry the initial alignment after a small delay. */
  t17_start(m);
  fifo_log(m, LOG_DEBUG, "Aborted initial alignment on link '%s'.\n", m->name);
}

/* Called on link errors that occur after the link is brought into service and
   which must cause the link to be brought out of service. This entails
   notifying user-parts of the failure and initiating MTP3 link failover, when
   that is implemented. */
static void mtp3_link_fail(mtp2_t *m, int down) {
  struct mtp_event link_up_event;
  int old_state = m->state;

  mtp2_cleanup(m);

  /* Notify user-parts. */
  if(old_state == MTP2_INSERVICE) {
    memset(&link_up_event, 0, sizeof(link_up_event));
    link_up_event.typ = MTP_EVENT_STATUS;
    link_up_event.status.link_state = MTP_EVENT_STATUS_LINK_DOWN;
    link_up_event.status.link = m->link;
    link_up_event.len = 0;
    mtp_put(m, &link_up_event);
    mtp_changeover(m);
  }

  /* For now, restart initial alignment after a small delay. */
  if (down) {
    m->state = MTP2_DOWN;
    t17_start(m);
  }
  else
    m->state = MTP2_NOT_ALIGNED;

  l4down(m);
  fifo_log(m, LOG_DEBUG, "Fail on link '%s'.\n", m->name);
}

static void start_initial_alignment(mtp2_t *m, char* reason) {
  m->state = MTP2_NOT_ALIGNED;
  m->send_fib = 1;
  m->send_bsn = 0x7f;
  m->send_bib = 1;
  m->tx_len = 0;
  m->tx_sofar = 0;
  m->retrans_seq = -1;
  m->retrans_last_acked = 0x7f;
  m->retrans_last_sent = 0x7f;
  m->error_rate_mon = 0;
  m->emon_dcount = 0;
  m->emon_ncount = 0;
  m->bsn_errors = 0;

  fifo_log(m, LOG_DEBUG, "Starting initial alignment on link '%s', reason: %s.\n", m->name, reason);
  t2_start(m);
}

static void t7_stop(mtp2_t *m)
{
  if(m->mtp2_t7 != -1) {
    delete_timer(mtp2_sched, m->mtp2_t7);
    m->mtp2_t7 = -1;
  }
}

static void mtp2_cleanup(mtp2_t *m)
{
  /* Stop SLTA response timeout. */
  if(m->sltm_t1 != -1) {
    delete_timer(mtp2_sched, m->sltm_t1);
    m->sltm_t1 = -1;
  }

  /* Stop sending SLTM. */
  if(m->sltm_t2 != -1) {
    delete_timer(mtp2_sched, m->sltm_t2);
    m->sltm_t2 = -1;
  }

  t1_stop(m);
  t2_stop(m);
  t3_stop(m);
  t4_stop(m);
  t7_stop(m);

  t17_stop(m);
}

static void deliver_l4(mtp2_t *m, int opc, int dpc, short slc, unsigned char *sif, int len, unsigned char sio)
{
  unsigned char ebuf[MTP_EVENT_MAX_SIZE];
  struct mtp_event *event = (struct mtp_event *)ebuf;

  memset(event, 0, sizeof(*event));
  if (sio == MTP_EVENT_ISUP) {
    event->isup.opc = opc;
    event->isup.dpc = dpc;
    event->isup.slc = slc;
    event->isup.link = NULL;
    event->isup.slink = m->link;
    event->isup.slinkix = m->link->linkix;
  }
  else{
    event->sccp.opc = opc;
    event->sccp.dpc = dpc;
    event->sccp.slc = slc;
    event->sccp.slink = m->link;
    event->sccp.slinkix = m->link->linkix;
  }
  event->typ = sio;
  event->len = len;
  memcpy(event->buf, sif, len);
  mtp_put(m, event);
}

static int timeout_t7(const void *data) {
  mtp2_t *m = (mtp2_t*) data;

  m->mtp2_t7 = -1;
  fifo_log(m, LOG_WARNING, "T7 timeout (excessive delay of acknowledgement) on link '%s', state=%d.\n", m->name, m->state);
  mtp3_link_fail(m, 1);

  return 0;                     /* Do not schedule us again. */
}

static void mtp2_t7_start(mtp2_t *m)
{
  int v;
  t7_stop(m);
  switch (variant(m)) {
  case ITU_SS7: v = 1500; break;
  case ANSI_SS7: v = 1400; break;
  case CHINA_SS7: v = 1500; break;
  }
  m->mtp2_t7 = mtp_sched_add(mtp2_sched, v, timeout_t7, m);
}

/* Signal unit error rate monitor (Q.703 (10.2)) */
static void mtp2_error_mon_count_frame(mtp2_t *m) {
  if(m->state == MTP2_READY || m->state == MTP2_INSERVICE) {
    m->emon_dcount = (m->emon_dcount + 1) % 256;
    if(m->emon_dcount == 0 && m->error_rate_mon > 0) {
      (m->error_rate_mon)--;
    }
  }
}

static void mtp2_octet_counting(mtp2_t *m) {
  m->emon_ncount = 0;
}

static void mtp2_emon_count_error(mtp2_t *m) {
  if(m->state == MTP2_READY || m->state == MTP2_INSERVICE) {
    if(m->error_rate_mon < 64) {
      (m->error_rate_mon)++;
      if(m->error_rate_mon == 64) {
        fifo_log(m, LOG_WARNING, "Excessive errors detected in signalling unit "
		 "error rate monitor, link failed on link '%s'.\n", m->name);
        mtp3_link_fail(m, 0);
      }
    }
  } else if(m->state == MTP2_PROVING) {
    (m->error_rate_mon)++;
    /* ToDo: For now we are always in emergency, but for non
       emergency, proving is not aborted until error_rate_mon reaches
       the value of 4 (Q.703 (10.3.4)). */
    if(m->error_rate_mon >= 1) {
      fifo_log(m, LOG_WARNING, "Excessive errors detected in alignment "
	       "error rate monitor, link failed on link '%s'.\n", m->name);
      abort_initial_alignment(m);
      /* ToDo: Abort the entire initial alingment, if proving is aborted for
         the fifth time. */
    }
  }
}

static void mtp2_bad_frame(mtp2_t *m, char* msg) {
  char buf[3 * sizeof(m->backbuf) + 1];
  int i;
  struct timeval now;
  static struct timeval last = {0, 0};
  static int badcount = 0;

  gettimeofday(&now, NULL);
  if (last.tv_sec) {
    int tdiff = (now.tv_sec - last.tv_sec) * 1000000 + (now.tv_usec - last.tv_usec);
    if (tdiff < 10*1000000 && badcount < 10000) {
      badcount++;
      return;
    }
    else {
      if (badcount) {
	fifo_log(m, LOG_DEBUG, "Suppressed %d bad frame debug log messages on link '%s'\n", badcount, m->name);
	badcount = 0;
      }
    }
  }
  last = now;
  strcpy(buf, "");
  for(i = 0; i < sizeof(m->backbuf); i++) {
    int byte = m->backbuf[(m->backbuf_idx + i) % sizeof(m->backbuf)];
    sprintf(&buf[i*3], " %02x", byte);
  }
  fifo_log(m, LOG_DEBUG, "%s on link '%s'. Last raw bits':%s\n", msg, m->name, buf);
  mtp2_error_mon_count_frame(m);
  mtp2_emon_count_error(m);
}

/* This MTP2 check bits calculation was nicked from zaptel.c, courtesy of
   the GPL.
*/
#define PPP_FCS(fcs, c) (((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff])
static unsigned short fcstab[256] =
{
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

/* Queue an MSU (in the retransmit buffer) for sending down the link. */
static void mtp2_queue_msu(mtp2_t *m, int sio, unsigned char *sif, int len) {
  int i;

  if(m->state != MTP2_INSERVICE) {
    if(m->state != MTP2_READY) {
      fifo_log(m, LOG_DEBUG, "Got MSU (sio=%d), but link not in service, discarding on link '%s'.\n", sio, m->name);
      return;
    }
  }
  if(len < 2) {
    fifo_log(m, LOG_ERROR, "Got illegal MSU length %d < 2, dropping frame on link '%s'.\n", len, m->name);
    return;
  }

  i = MTP_NEXT_SEQ(m->retrans_last_sent);
  if(i == m->retrans_last_acked) {
    fifo_log(m, LOG_WARNING, "MTP retransmit buffer full, MSU lost on link '%s'.\n", m->name);
    return;
  }

  m->retrans_buf[i].buf[0] = 0; /* BSN Will be set correctly when transmitted */
  m->retrans_buf[i].buf[1] = 0; /* FSN Will be set correctly when transmitted */
  m->retrans_buf[i].buf[2] = (len >= 62 ? 63 : 1 + len);
  m->retrans_buf[i].buf[3] = sio;
  memcpy(&(m->retrans_buf[i].buf[4]), sif, len);
  m->retrans_buf[i].len = len + 4;
  m->retrans_last_sent = i;
  /* Start transmitting the new SU, unless we were already (re-)transmitting. */
  if(m->retrans_seq == -1) {
    m->retrans_seq = i;
    /* Start timer T7 "excessive delay of acknowledgement". */
    mtp2_t7_start(m);
  }
}

void mtp3_put_label(int sls, ss7_variant variant, int opc, int dpc, unsigned char *buf)
{
  switch (variant) {
  case ITU_SS7:
    buf[0] = dpc & 0xff;
    buf[1] = ((dpc & 0x3f00) >> 8) | ((opc & 0x0003) << 6);
    buf[2] = ((opc & 0x03fc) >> 2);
    buf[3] = ((opc & 0x3c00) >> 10) | (sls << 4);
    break;
  case ANSI_SS7:
  case CHINA_SS7:
    buf[0] = dpc & 0xff;
    buf[1] = (dpc & 0xff00) >> 8;
    buf[2] = (dpc & 0xff0000) >> 16;
    buf[3] = opc & 0xff;
    buf[4] = (opc & 0xff00) >> 8;
    buf[5] = (opc & 0xff0000) >> 16;
    buf[6] = sls & 0x0f;
    break;
  }
}

static void mtp3_set_sls(ss7_variant variant, int sls, unsigned char *buf)
{
  switch (variant) {
  case ITU_SS7:
    buf[3] = (buf[3] & 0xff0f) | (sls << 4);
    break;
  case ANSI_SS7:
  case CHINA_SS7:
    buf[6] = sls & 0x0f;
  }
}

/* Handle Q.707 test-and-maintenance procedure.
   Send a periodic SLTM message, listen for SLTA.
*/
static int mtp3_send_sltm(const void *data); /* For mutual recursion */
static int timeout_sltm_t1(const void *data) {
  mtp2_t *m = (mtp2_t*) data;

  if(m->sltm_tries == 1) {
    fifo_log(m, LOG_WARNING, "No SLTA received within Q.707 timer T1, trying again on link '%s'.\n", m->name);
    mtp3_send_sltm(m);
    m->sltm_tries = 2;
    return 1;                   /* Ask to run again on next timer expire */
  } else  {
    fifo_log(m, LOG_ERROR, "No SLTA received within Q.707 timer T1, faulting link on link '%s'.\n", m->name);
    m->sltm_t1 = -1;
    mtp3_link_fail(m, 0);
    return 0;                   /* Do not re-schedule */
  }
}

static unsigned char sltm_pattern[15] =
  { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

static int mtp3_send_sltm(const void *data) {
  unsigned char message_sltm[24];
  mtp2_t *m = (mtp2_t*) data;
  int subservice = m->subservice;

  if (subservice == -1)
    subservice = 0x8;

  fifo_log(m, LOG_NOTICE, "Sending SLTM to peer on link '%s'....\n", m->name);
  mtp3_put_label(m->sls, variant(m), peeropc(m), linkpeerdpc(m), message_sltm);
  switch (variant(m)) {
  case ITU_SS7:
    message_sltm[4] = 0x11;       /* SLTM */
    message_sltm[5] = 0xf0;       /* Length: 15 */
    memcpy(&(message_sltm[6]), sltm_pattern, sizeof(sltm_pattern));
    mtp2_queue_msu(m, (subservice << 4) | 1, message_sltm, 6 + sizeof(sltm_pattern));
    break;
  case ANSI_SS7:
  case CHINA_SS7:
    message_sltm[7] = 0x11;       /* SLTM */
    message_sltm[8] = 0xf0;       /* Length: 15 */
    memcpy(&(message_sltm[9]), sltm_pattern, sizeof(sltm_pattern));
    mtp2_queue_msu(m, (subservice << 4) | 1, message_sltm, 9 + sizeof(sltm_pattern));
    break;
  }

  /* Set up a timer to wait for SLTA. */
  if(m->sltm_t1 == -1) {        /* Only if it is not already running */
    m->sltm_t1 = mtp_sched_add(mtp2_sched, 9000, timeout_sltm_t1, m);
    m->sltm_tries = 1;
  }

  return 1;                     /* Ask to be run again on next timer expire */
}

/* Process a received link status signal unit. */
static void mtp2_process_lssu(mtp2_t *m, unsigned char *buf, int fsn, int fib) {
  int typ;

  typ = buf[3] & 0x07;
  switch(typ) {
    case 0:                   /* Status indication 'O' */
      if(m->state == MTP2_NOT_ALIGNED) {
        t2_stop(m);
        t3_start(m);
        m->state = MTP2_ALIGNED;
      } else if(m->state == MTP2_PROVING) {
        t4_stop(m);
        m->state = MTP2_ALIGNED;
      } else if(m->state == MTP2_READY) {
        abort_initial_alignment(m);
      } else if(m->state == MTP2_INSERVICE) {
	fifo_log(m, LOG_NOTICE, "Got status indication 'O' while INSERVICE on link %s.\n", m->name);
        mtp3_link_fail(m, 0);
      }
      break;

    case 1:                   /* Status indication 'N' */
    case 2:                   /* Status indication 'E' */
      /* ToDo: This shouldn't really be here, I think. */
      m->send_bsn = fsn;
      m->send_bib = fib;

      if(m->hwmtp2 && (m->state == MTP2_NOT_ALIGNED)) {
	t2_stop(m);
	t3_start(m);
	m->state = MTP2_ALIGNED;
      }
      if(m->state == MTP2_NOT_ALIGNED) {
        t2_stop(m);
        t3_start(m);
        m->state = MTP2_ALIGNED;
      } else if(m->state == MTP2_ALIGNED) {
	fifo_log(m, LOG_DEBUG, "Entering proving state for link '%s'.\n", m->name);
        t3_stop(m);
        t4_start(m);
        m->state = MTP2_PROVING;
        m->error_rate_mon = 0;
        m->emon_ncount = 0;
      } else if(m->state == MTP2_INSERVICE) {
	fifo_log(m, LOG_NOTICE, "Got status indication 'N' or 'E' while INSERVICE on link '%s'.\n", m->name);
        mtp3_link_fail(m, 0);
      }
      break;

    case 3:                   /* Status indication 'OS' */
      if(m->state == MTP2_ALIGNED || m->state == MTP2_PROVING) {
        abort_initial_alignment(m);
      } else if(m->state == MTP2_READY) {
	fifo_log(m, LOG_NOTICE, "Got status indication 'OS' while READY on link '%s'.\n", m->name);
	mtp3_link_fail(m, 1);
      } else if(m->state == MTP2_INSERVICE) {
	fifo_log(m, LOG_NOTICE, "Got status indication 'OS' while INSERVICE on link '%s'.\n", m->name);
        mtp3_link_fail(m, 1);
      }
      break;

    case 4:                   /* Status indication 'PO' */
      /* ToDo: Not implemented. */
/* Don't do this, as the log would explode should this actually happen
   fifo_log(LOG_NOTICE, "Status indication 'PO' not implemented.\n");
*/
      break;

    case 5:                   /* Status indication 'B' */
      /* ToDo: Not implemented. */
      fifo_log(m, LOG_NOTICE, "Status indication 'B' not implemented.\n");
      break;

    default:                  /* Illegal status indication. */
      fifo_log(m, LOG_WARNING, "Got undefined LSSU status %d on link '%s'.\n", typ, m->name);
      mtp3_link_fail(m, 0);
  }
}

static void l4up(mtp2_t* m)
{
  struct mtp_event link_up_event;
  if (m->level4_up)
    return;
  m->level4_up = 1;
  if (m->state == MTP2_INSERVICE) {
    /* Tell user part about the successful link activation. */
    memset(&link_up_event, 0, sizeof(link_up_event));
    link_up_event.typ = MTP_EVENT_STATUS;
    link_up_event.status.link_state = MTP_EVENT_STATUS_LINK_UP;
    link_up_event.status.link = m->link;
    link_up_event.len = 0;
    mtp_put(m, &link_up_event);
  }
}

static void l4down(mtp2_t* m)
{
  struct mtp_event link_down_event;
	/* Notify user-parts. */
  if (!m->level4_up)
    return;
  m->level4_up = 0;
  memset(&link_down_event, 0, sizeof(link_down_event));
  link_down_event.typ = MTP_EVENT_STATUS;
  link_down_event.status.link_state = MTP_EVENT_STATUS_LINK_DOWN;
  link_down_event.status.link = m->link;
  link_down_event.len = 0;
  mtp_put(m, &link_down_event);
}

/* Process a received frame.

   The frame has already been checked for correct crc and for being at least
   5 bytes long.
*/
static void mtp2_good_frame(mtp2_t *m, unsigned char *buf, int len) {
  int fsn, fib, bsn, bib;
  int li;

  /* Count this frame into the error rate monitor counters. */
  mtp2_error_mon_count_frame(m);

#ifdef DROP_PACKETS_PCT
  if(rand() <= DROP_PACKETS_PCT/100.0*RAND_MAX) {
    return;
  }
#endif

  if(m->state == MTP2_DOWN) {
    return;
  }

  log_frame(m, 0, buf, len);

  bsn = buf[0] & 0x7f;
  bib = buf[0] >> 7;
  fsn = buf[1] & 0x7f;
  fib = buf[1] >> 7;

  li = buf[2] & 0x3f;

  if (option_debug > 2) {
    if (m->hwmtp2 || m->hwhdlcfcs || (li > 2)) {
      char pbuf[1000], hex[30];
      int i;
      int slc;

  if(variant(m) == ITU_SS7)
    slc = (buf[7] & 0xf0) >> 4;
  else if(variant(m) == CHINA_SS7)
    slc = (buf[10] & 0xf0) >> 4;
  else
    slc = (buf[10] & 0xf0) >> 4;

      strcpy(pbuf, "");
      for(i = 0; i < li - 1 && i + 4 < len; i++) {
	sprintf(hex, " %02x", buf[i + 4]);
	strcat(pbuf, hex);
      }
      fifo_log(m, LOG_DEBUG, "Got MSU on link '%s/%d' sio=%d slc=%d m.sls=%d bsn=%d/%d, fsn=%d/%d, sio=%02x, len=%d:%s\n", m->name, m->schannel+1, buf[3] & 0xf, slc, m->sls, bib, bsn, fib, fsn, buf[3], li, pbuf);
    }
  }

  if(li + 3 > len) {
    fifo_log(m, LOG_NOTICE, "Got unreasonable length indicator %d (len=%d) on link '%s'.\n",
	     li, len, m->name);
    return;
  }

  if(li == 1 || li == 2) {
    /* Link status signal unit. */
    mtp2_process_lssu(m, buf, fsn, fib);
    return;
  }

  /* Process the BSN of the signal unit.
     According to Q.703 (5), only FISU and MSU should have FSN and BSN
     processing done. */
  if(m->state != MTP2_INSERVICE) {
    if(m->state == MTP2_READY) {
      t1_stop(m);
      t7_stop(m);
      m->send_fib = bib;
      m->send_bsn = fsn;
      m->send_bib = fib;
      //      m->retrans_last_acked = fsn;xxx
      //      m->retrans_last_sent = fsn;xxx
      m->retrans_last_acked = bsn;//xxx
      m->error_rate_mon = 0;
      m->emon_dcount = 0;
      m->emon_ncount = 0;
      m->level4_up = 0;

      /* Send TRA (traffic restart allowed) immediately, since we have no
         routing capabilities that could be prohibited/restricted. */
      m->state = MTP2_INSERVICE;
      unsigned char message_tra[8];
      int subservice = m->subservice;

      if (subservice == -1)
        subservice = 0x8;

      l4up(m);
      fifo_log(m, LOG_NOTICE, "Sending TRA to peer on link '%s'....\n", m->name);
      mtp3_put_label(m->sls, variant(m), peeropc(m), linkpeerdpc(m), message_tra);
      switch (variant(m)) {
      case ITU_SS7:
        message_tra[4] = 0x17; /* TRA */
        mtp2_queue_msu(m, (subservice << 4) | 0, message_tra, 5);
	break;
      case ANSI_SS7:
      case CHINA_SS7:
        message_tra[7] = 0x17; /* TRA */
        mtp2_queue_msu(m, (subservice << 4) | 0, message_tra, 8);
	break;
      }

      /* Send an initial SLTM message, and send it periodic afterwards. */
      if (m->send_sltm) {
	mtp3_send_sltm(m);
	if(m->sltm_t2 != -1) {
	  fifo_log(m, LOG_DEBUG, "SLTM timer T2 not cleared, restarted (%d)\n", m->sltm_t2);
	  delete_timer(mtp2_sched, m->sltm_t2);
	}

	m->sltm_t2 = mtp_sched_add(mtp2_sched, 61000, mtp3_send_sltm, m);
      }
    } else {
      return;
    }
  }
  else if(m->state == MTP2_READY) {
    t1_stop(m);
    t7_stop(m);
  }

  /* ToDo: Check for FIB flipover when we haven't requested retransmission,
     and fault the frame if so. See last part of Q.703 (5.3.2). */

  /* Process the BSN of the received frame. */
  if((m->retrans_last_acked <= m->retrans_last_sent &&
      (bsn < m->retrans_last_acked || bsn > m->retrans_last_sent)) ||
     (m->retrans_last_acked > m->retrans_last_sent &&
      (bsn < m->retrans_last_acked && bsn > m->retrans_last_sent))) {
    /* They asked for a retransmission of a sequence number not available. */
    fifo_log(m, LOG_DEBUG, "Received illegal BSN=%d (retrans=%d,%d) on link '%s', len=%d, si=02%02x, state=%d, count=%d.\n",
	     bsn, m->retrans_last_acked, m->retrans_last_sent, m->name, len, m->tx_buffer[3] & 0xf, m->state, m->bsn_errors);
    /* ToDo: Fault the link if this happens again within the next
       two SUs, see second last paragraph of Q.703 (5.3.1). */
    if (m->bsn_errors++ > 2) {
      m->bsn_errors = 0;
      mtp3_link_fail(m, 1);
    }
    return;
  }
  m->bsn_errors = 0;

  /* Reset timer T7 if new acknowledgement received (Q.703 (5.3.1) last
     paragraph). */
  if(m->retrans_last_acked != bsn) {
    t7_stop(m);
    m->retrans_last_acked = bsn;
    if(m->retrans_last_acked != m->retrans_last_sent) {
      mtp2_t7_start(m);
    }
  }

  if(bib != m->send_fib) {
    /* Received negative acknowledge, start re-transmission. */
    m->send_fib = bib;
    if(bsn == m->retrans_last_sent) {
      /* Nothing to re-transmit. */
      m->retrans_seq = -1;
    } else {
      m->retrans_seq = MTP_NEXT_SEQ(bsn);
    }
  }

  /* Process the signal unit content. */
  if(li == 0) {
    /* Fill-in signal unit. */

    /* Process the FSN of the received frame. */
    if(fsn != m->send_bsn) {
      /* This indicates the loss of a message. */
      if(fib == m->send_bib) {
        /* Send a negative acknowledgement, to request retransmission. */
        m->send_bib = !m->send_bib;
      }
    }
  } else {
    /* Message signal unit. */
    /* Process the FSN of the received frame. */
    if(fsn == m->send_bsn) {
      /* Q.703 (5.2.2.c.i): Redundant retransmission. */
      return;
    } else if(fsn == MTP_NEXT_SEQ(m->send_bsn)) {
      /* Q.703 (5.2.2.c.ii). */
      if(fib == m->send_bib) {
        /* Successful frame reception. Do explicit acknowledge on next frame. */
        m->send_bsn = fsn;
      } else {
        /* Drop frame waiting for retransmissions to arrive. */
        return;
      }
    } else {
      /* Q.703 (5.2.2.c.iii). Frame lost before this frame, discart it
         (will be retransmitted in-order later). */
      if(fib == m->send_bib) {
        /* Send a negative acknowledgement, to request retransmission. */
        m->send_bib = !m->send_bib;
      }
      return;
    }

    /* Length indicator (li) is number of bytes in MSU after LI, so the valid
       bytes are buf[0] through buf[(li + 3) - 1]. */
    if(li < 5) {
      fifo_log(m, LOG_NOTICE, "Got short MSU (no label), li=%d on link '%s'.\n", li, m->name);
      return;
    }
    {
      char pbuf[1000], hex[30];
      int i;
      int slc;

      switch (variant(m)) {
      case ITU_SS7:
	slc = (buf[7] & 0xf0) >> 4;
	break;
      case ANSI_SS7:
      case CHINA_SS7:
	slc = (buf[10] & 0xf0) >> 4;
	break;
      }
      strcpy(pbuf, "");
      for(i = 0; i < li - 1 && i + 4 < len; i++) {
	sprintf(hex, " %02x", buf[i + 4]);
	strcat(pbuf, hex);
      }
      fifo_log(m, LOG_DEBUG, "Got MSU on link '%s' sio=%d slc=%d m.sls=%d bsn=%d/%d, fsn=%d/%d, sio=%02x, len=%d:%s\n", m->name, buf[3] & 0xf, slc, m->sls, bib, bsn, fib, fsn, buf[3], li, pbuf);
    }
    process_msu(m, buf, len);
  }
}

static void process_msu(struct mtp2_state* m, unsigned char* buf, int len)
{
  mtp2_t* tm;
  int service_indicator, subservice_field;
  int h0, h1;
  int slt_pattern_len;
  int dpc, opc, slc;
  int li;
  int i;

  li = buf[2] & 0x3f;
  service_indicator = buf[3] & 0xf;
  subservice_field = (buf[3] & 0xf0) >> 4;
  switch (variant(m)) {
  case ITU_SS7:
    dpc = buf[4] | ((buf[5] & 0x3f) << 8);
    opc = ((buf[5] & 0xc0) >> 6) | (buf[6] << 2) | ((buf[7] & 0x0f) << 10);
    slc = (buf[7] & 0xf0) >> 4;
    break;
  case ANSI_SS7:
  case CHINA_SS7:
    dpc = buf[4] | ((buf[5] & 0xff) << 8) | ((buf[6] & 0xff) << 16);
    opc = buf[7] | ((buf[8] & 0xff) << 8) | ((buf[9] & 0xff) << 16);
    slc = buf[10] & 0x0f;
    break;
  }
  
  if (m->subservice == -1) {
    m->subservice = subservice_field;
    fifo_log(m, LOG_NOTICE, " Using subservice field from incoming MSU: 0x%x\n", subservice_field);
  }

  switch(service_indicator) {
  case 0x0:
    /* Signalling network management messages. */
    switch (variant(m)) {
    case ITU_SS7:
      h0 = buf[8] & 0xf;
      h1 = (buf[8] & 0xf0) >> 4;
      break;
    case ANSI_SS7:
    case CHINA_SS7:
      h0 = buf[11] & 0xf;
      h1 = (buf[11] & 0xf0) >> 4;
      break;
    }
    	
    tm = findtargetslink(m, slc);
    fifo_log(m, LOG_DEBUG, "Signalling network management, h0=%d, h1=%d, targetslink '%s'\n", h0, h1, tm ? tm->name : "(unknown)");
    if (!tm) {
      fifo_log(m, LOG_DEBUG, "Target signalling link %d not found, received on '%s'\n", slc, m->name);
      break;
    }
    if (h0 == 1) { /* CHM - changeover management */
    }
    else if (h0 == 7 && h1 == 1) {
      fifo_log(m, LOG_DEBUG, "Received tra on '%s', sls %d\n", m->name, slc);
    }
    break;

  case 0x1: /* maintenance regular message */
  case 0x2: /* maintenance special message */
    if(li < 7) {
      fifo_log(m, LOG_NOTICE, "Got short SLTM/SLTA (no h0/h1/len), li=%d on link '%s'.\n", li, m->name);
      return;
    }
    switch (variant(m)) {
    case ITU_SS7:
      h0 = buf[8] & 0xf;
      h1 = (buf[8] & 0xf0) >> 4;
      slt_pattern_len = (buf[9] & 0xf0) >> 4;
      break;
    case ANSI_SS7:
    case CHINA_SS7:
      h0 = buf[11] & 0xf;
      h1 = (buf[11] & 0xf0) >> 4;
      slt_pattern_len = (buf[12] & 0xf0) >> 4;
      break;
    }
    fifo_log(m, LOG_DEBUG, "Received MTN on '%s/%d', h0=%d, h1=%d, sls %d\n", m->name, m->schannel+1, h0, h1, slc);

    if(li < 7 + slt_pattern_len) {
      fifo_log(m, LOG_NOTICE, "Got short SLTM/SLTA (short pattern), li=%d, "
	       "slt_len=%d on link '%s'.\n", li, slt_pattern_len, m->name);
      return;
    }
    if(h0 == 0x1 && h1 == 0x1) {
      /* signalling link test message. */
      /* Queue a signalling link test acknowledgement message. (SLTA) */

      unsigned char message_slta[21];
      int subservice = m->subservice;

      if (subservice == -1)
	      subservice = 0x8;

      mtp3_put_label(slc, variant(m), dpc, opc, message_slta);
      if (slc != m->sls) {
	fifo_log(m, LOG_WARNING, "Got SLTM with unexpected sls=%d, OPC=%d DPC=%d on '%s/%d' sls=%d, state=%d.\n", slc, opc, dpc, m->name, m->schannel+1, m->sls, m->state);
	//m->sls = slc;
      }
      fifo_log(m, LOG_DEBUG, "Got SLTM, OPC=%d DPC=%d, sending SLTA '%s', state=%d.\n", opc, dpc, m->name, m->state);
      switch (variant(m)) {
      case ITU_SS7:
        message_slta[4] = 0x21;
        message_slta[5] = slt_pattern_len << 4;
        memcpy(&(message_slta[6]), &(buf[10]), slt_pattern_len);
        mtp2_queue_msu(m, (subservice << 4) | 1, message_slta, 6 + slt_pattern_len);
	break;
      case ANSI_SS7:
      case CHINA_SS7:
        message_slta[7] = 0x21;
        message_slta[8] = slt_pattern_len << 4;
        memcpy(&(message_slta[9]), &(buf[13]), slt_pattern_len);
        mtp2_queue_msu(m, (subservice << 4) | 1, message_slta, 9 + slt_pattern_len);
	break;
      }
    } else if(h0 == 0x1 && h1 == 0x2) {
      /* signalling link test acknowledgement message. */

      /* Clear the Q.707 timer T1, since the SLTA was received. */
      if(m->sltm_t1 != -1) {
	delete_timer(mtp2_sched, m->sltm_t1);
	m->sltm_t1 = -1;
      }

      /* Q.707 (2.2) conditions for acceptance of SLTA. */
      switch (variant(m)) {
      case ITU_SS7:
        i = memcmp(sltm_pattern, &(buf[10]), sizeof(sltm_pattern));
	break;
      case ANSI_SS7:
      case CHINA_SS7:
        i = memcmp(sltm_pattern, &(buf[13]), sizeof(sltm_pattern));
	break;
      }

      if(slc == m->sls &&
	 opc == linkpeerdpc(m) && dpc == peeropc(m) &&
	 0 == i ) {
	fifo_log(m, LOG_DEBUG, "Got valid SLTA response on link '%s', state=%d.\n", m->name, m->state);
	l4up(m);
      } else {
	if(m->sltm_tries == 1) {
	  fifo_log(m, LOG_WARNING, "Received invalid SLTA response (slc=%d,opc=%d,dpc=%d), trying again on link '%s'.\n", slc, opc, dpc, m->name);
	  mtp3_send_sltm(m);
	  m->sltm_tries = 2;
	} else {
	  fifo_log(m, LOG_ERROR, "Received invalid SLTA response, faulting link on link '%s'.\n", m->name);
	  mtp3_link_fail(m, 0);
	}
      }
    } else {
      /* Spare. */
      fifo_log(m, LOG_NOTICE, "Got unknown/spare signalling network testing "
	       "and maintenance message code H0=0x%x/H1=0x%x on link '%s'.\n", h0, h1, m->name);
    }
    break;

  case SS7_PROTO_SCCP:
    deliver_l4(m, opc, dpc, slc, &(buf[4]), (li == 63 ? len - 4 : li - 1), MTP_EVENT_SCCP);
    break;
  case SS7_PROTO_ISUP:
    deliver_l4(m, opc, dpc, slc, &(buf[4]), (li == 63 ? len - 4 : li - 1), MTP_EVENT_ISUP);
    break;
  }
}


/* MTP2 reading of signalling units.
 * The buffer pointer is only valid until return from this function, so
 * the data must be copied out as needed.
 */
static void mtp2_read_su(mtp2_t *m, unsigned char *buf, int len) {
  int i = 0;
  int res;
  unsigned char nextbyte;

  if (m->hwmtp2 || m->hwhdlcfcs) {
    fifo_log(m, LOG_DEBUG, "Got su on link '%s/%d': len %d buf[3] 0x%02x\n", m->name, m->schannel+1, len, (unsigned int)buf[3]);
    if((len-2 > MTP_MAX_PCK_SIZE-8) || (len < 3)) {
      char msg[80];
      sprintf(msg, "Overlong/too short MTP2 frame %d, dropping\n", len-2);
      mtp2_bad_frame(m, msg);
      return;
    }
    mtp2_good_frame(m, buf, len-2);
    m->readcount += len;
    return;
  }
  for(;;) {
    while(m->h_rx.bits <= 24 && i < len) {
      nextbyte = buf[i++];
      /* Log the byte for debugging link errors. */
      m->backbuf[m->backbuf_idx] = nextbyte;
      m->backbuf_idx = (m->backbuf_idx + 1) % sizeof(m->backbuf);
      fasthdlc_rx_load_nocheck(&(m->h_rx), nextbyte);
      m->readcount++;
      if(m->h_rx.state == 0) {
        /* Q.703 (10.2.3): Octet counting mode. */
        m->emon_ncount = (m->emon_ncount + 1) % 16;
        if(m->emon_ncount == 0) {
          mtp2_emon_count_error(m);
        }
      }
    }

    res = fasthdlc_rx_run(&(m->h_rx));
    if(res & RETURN_DISCARD_FLAG) {
      /* Some problem, like 7 one-bits in a row, or framesize not dvisible by
         8 bits. The fasthdlc now enters a state looking for the next flag
         (octet counting mode). */
      char msg[80];
      sprintf(msg, "MTP2 bitstream frame format error, entering octet counting mode");
      mtp2_bad_frame(m, msg);
      mtp2_octet_counting(m);
      m->rx_len = 0;
      m->rx_crc = 0xffff;
    } else if(res & RETURN_EMPTY_FLAG) {
      if(i >= len) {
        /* No more data for now. */
        break;
      }
      /* Else we are skipping bits looking for a flag (Q.703 "octet counting
         mode"). */
    } else if(res & RETURN_COMPLETE_FLAG) {
      if(m->rx_len == 0) {
        /* Q.703: Multiple flags in sequence are allowed (though
           discouraged). */
      } else if(m->rx_len < 5) {
        /* Q.703: A frame must be at least 5 bytes (plus one for the flag). If
           not, the frame is in error. */
	char msg[80];
	sprintf(msg, "Short MTP2 frame len %d < 5", m->rx_len);
        mtp2_bad_frame(m, msg);
      } else {
        if(m->rx_crc == 0xf0b8) {
          mtp2_good_frame(m, m->rx_buf, m->rx_len-2);
        } else {
	  char msg[80];
	  sprintf(msg, "MTP2 CRC error (CRC=0x%x != 0xf0b8)", m->rx_crc);
          mtp2_bad_frame(m, msg);
        }
      }
      m->rx_len = 0;
      m->rx_crc = 0xffff;
    } else {
      /* Got a data byte. */
      /* Q.703: If more than 272+7 bytes are seen in a frame, discard it and
         enter "octet counting mode". */
      if(m->rx_len >= 272 + 7) {
        /* Switch state into "looking for a frame". */
	char msg[80];
	sprintf(msg, "Overlong MTP2 frame, entering octet counting mode");
        m->h_rx.state = 0;
        mtp2_bad_frame(m, msg);
        mtp2_octet_counting(m);
        m->rx_len = 0;
        m->rx_crc = 0xffff;
      } else {
        m->rx_buf[m->rx_len++] = res;
        m->rx_crc = PPP_FCS(m->rx_crc, res);
      }
    }
  }
}

static void mtp2_fetch_zap_event(mtp2_t *m) {
  int x = 0;
  int res;

  res = io_get_dahdi_event(m->fd, &x);
  fifo_log(m, LOG_NOTICE, "Got event on link '%s': %d (%d/%d).\n", m->name, x, res, errno);
}

/* Find a frame to transmit and put it in the transmit buffer.

   Q.703 (11.2.2): Pick a frame in descending priority as
   1. Link status signal unit.
   2. Requested retransmission of message signal unit.
   3. New message signal unit.
   4. Fill-in signal unit.
   5. Flag [but we can always send fill-in signal unit].
*/
static void mtp2_pick_frame(mtp2_t *m)
{
  switch(m->state) {
    case MTP2_DOWN:
      /* Send SIOS. */
      m->tx_len = 4;
      m->tx_buffer[0] = m->send_bsn | (m->send_bib << 7);
      m->tx_buffer[1] = m->retrans_last_sent | (m->send_fib << 7);
      m->tx_buffer[2] = 1;      /* Length 1, meaning LSSU. */
      m->tx_buffer[3] = 3;      /* 3 is indication 'SIOS'. */
      return;

    case MTP2_NOT_ALIGNED:
      /* Send SIO. */
      m->tx_len = 4;
      m->tx_buffer[0] = m->send_bsn | (m->send_bib << 7);
      m->tx_buffer[1] = m->retrans_last_sent | (m->send_fib << 7);
      m->tx_buffer[2] = 1;      /* Length 1, meaning LSSU. */
      m->tx_buffer[3] = 0;      /* 0 is indication 'SIO'. */
      return;

    case MTP2_ALIGNED:
    case MTP2_PROVING:
      /* Send SIE or SIN. */
      m->tx_len = 4;
      m->tx_buffer[0] = m->send_bsn | (m->send_bib << 7);
      m->tx_buffer[1] = m->retrans_last_sent | (m->send_fib << 7);
      m->tx_buffer[2] = 1;      /* Length 1, meaning LSSU. */
      m->tx_buffer[3] = 2;
      return;

    case MTP2_READY:
    case MTP2_INSERVICE:
      /* Frame selection. */

      /* If we have something in the retransmission buffer, send it. This
         also handles sending new MSUs, as they are simply appended to the
         retransmit buffer. */
      if(m->retrans_seq != -1) {
        /* Send retransmission. */
        memcpy(m->tx_buffer,
               m->retrans_buf[m->retrans_seq].buf,
               m->retrans_buf[m->retrans_seq].len);
        m->tx_len = m->retrans_buf[m->retrans_seq].len;
        m->tx_buffer[0] = m->send_bsn | (m->send_bib << 7);
        m->tx_buffer[1] = m->retrans_seq | (m->send_fib << 7);

        if(m->retrans_seq == m->retrans_last_sent) {
          /* Retransmission done. */
          m->retrans_seq = -1;
        } else {
          /* Move to the next one. */
          m->retrans_seq = MTP_NEXT_SEQ(m->retrans_seq);
        }

        return;
      }

      /* Send Fill-in signalling unit (FISU) if nothing else is pending. */
      m->tx_len = 3;
      m->tx_buffer[0] = m->send_bsn | (m->send_bib << 7);
      m->tx_buffer[1] = m->retrans_last_sent | (m->send_fib << 7);
      m->tx_buffer[2] = 0;      /* Length 0, meaning FISU. */
      return;

    default:
      fifo_log(m, LOG_ERROR, "Internal: Unknown MTP2 state %d on link '%s'?!?\n", m->state, m->name);
  }
}

/* Fill in a buffer for Dahdi transmission, picking frames as necessary.
   The passed buffer is of size ZAP_BUF_SIZE.
*/
static void mtp2_fill_dahdi_buf(mtp2_t *m, unsigned char *buf) {
  int i;

  for(i = 0; i < ZAP_BUF_SIZE; i++) {
    if(m->h_tx.bits < 8) {
      /* Need some more bits. */
      if(m->tx_do_crc == 1) {
        /* Put first byte of CRC. */
        fasthdlc_tx_load_nocheck(&(m->h_tx), m->tx_crc & 0xff);
        m->tx_do_crc = 2;
      } else if(m->tx_do_crc == 2) {
        /* Put second byte of CRC. */
        fasthdlc_tx_load_nocheck(&(m->h_tx), (m->tx_crc >> 8) & 0xff);
        m->tx_do_crc = 0;
      } else if(m->tx_sofar >= m->tx_len) {
        /* Fetch a new frame. */
#ifdef DROP_PACKETS_PCT
        do {
#endif
        mtp2_pick_frame(m);
#ifdef DROP_PACKETS_PCT
        } while(rand() <= DROP_PACKETS_PCT/100.0*RAND_MAX);
#endif
	if (m->tx_len > 4)
	  fifo_log(m, LOG_DEBUG, "Sending buffer to dahdi len=%d, on link '%s' bsn=%d, fsn=%d.\n", m->tx_len, m->name, m->tx_buffer[0]&0x7f,  m->tx_buffer[1]&0x7f);
        log_frame(m, 1, m->tx_buffer, m->tx_len);
        m->tx_sofar = 0;
        m->tx_crc = 0xffff;
        fasthdlc_tx_frame_nocheck(&(m->h_tx));
        /* A zero-length frame from mtp2_pick_frame() will cause
           sending of a single flag, without crc check bits.
        */
      } else {
        unsigned char data = m->tx_buffer[m->tx_sofar++];
        fasthdlc_tx_load_nocheck(&(m->h_tx), data);
        m->tx_crc = PPP_FCS(m->tx_crc, data);
        if(m->tx_sofar == m->tx_len) {
          /* At frame end, also push the crc bits into the fasthdlc buffer.
             Because of bit stuffing, we might not have room in the buffer for
             8 bits of data + 16 bits of crc, so set a flag to do it later. */
          m->tx_crc ^= 0xffff;
          m->tx_do_crc = 1;
        }
      }
    }

    buf[i] = fasthdlc_tx_run_nocheck(&(m->h_tx));
    m->writecount++;
  }
}

void *mtp_thread_main(void *data) {
  struct mtp2_state *m = NULL;
  int i, lsi;
  int res;
  struct pollfd fds[MAX_SCHANNELS];
  unsigned char fifobuf[MTP_REQ_MAX_SIZE];
  struct mtp_req *req;
  int last_send_ix = 0;
#ifdef MTP_OVER_UDP
  int sent_fisu[MAX_SCHANNELS] = {0,};
  int sent_bsn[MAX_SCHANNELS] = {0,};
#endif
  ast_verbose(VERBOSE_PREFIX_3 "Starting MTP thread, pid=%d.\n", getpid());

  /* These counters are used to generate timestamps for raw dumps.
     The write count is offset with one dahdi buffer size to account for
     the buffer-introduced write latency. This way the dump timings should
     approximately reflect the time that the last byte of the frame went
     out on the wire. */
  for (i = 0; i < n_mtp2_state; i++) {
    m = &mtp2_state[i];
    m->readcount = 0;
    m->writecount = ZAP_BUF_SIZE;

    fds[i].fd = m->fd;
    fds[i].events = POLLIN|POLLPRI|POLLOUT;
  }
  while(!stop_mtp_thread) {
    struct timeval now;
    struct timeval last;
    int tdiff;

    for (i = 0; i < n_mtp2_state; i++) {
      m = &mtp2_state[i];
#ifdef MTP_OVER_UDP
      if (0)
	if (((m->state == MTP2_READY || m->state == MTP2_INSERVICE)))
	  ast_log(LOG_DEBUG, "Poll2, state=%d, retrans_seq=%d last_sent=%d last_ack=%d, send_bsn=%d sent_bsn=%d sent_fisu=%d\n", m->state, m->retrans_seq, m->retrans_last_sent, m->retrans_last_acked, m->send_bsn, sent_bsn[i], sent_fisu[i]);
      if (((m->state == MTP2_READY || m->state == MTP2_INSERVICE) && ((m->retrans_seq != -1) || (m->retrans_last_acked != m->retrans_last_sent))) ||
	  ((m->state != MTP2_READY && m->state != MTP2_INSERVICE)) ||
	  (m->send_bsn != sent_bsn[i])) {
	/* avoid sending FISU */
	fds[i].events = POLLIN|POLLPRI|POLLOUT;
	sent_fisu[i] = 0;
	sent_bsn[i] = m->send_bsn;
      }
      else {
	if (sent_fisu[i] < 100) {
	  fds[i].events = POLLIN|POLLPRI|POLLOUT;
	  sent_fisu[i]++;
	  sent_bsn[i] = m->send_bsn;
	}
	else
	  fds[i].events = POLLIN|POLLPRI;
      }
#endif
    }
#ifdef TESTINPUT
    {
      int cmdfd = open("/tmp/mtp3d.sock", O_RDONLY | O_NONBLOCK);

      if (cmdfd != -1) {
	struct pollfd cmdfds[1];
	cmdfds[0].fd = cmdfd;
	cmdfds[0].events = POLLIN;
	res = poll(cmdfds, 1, 100);
	if (res > 0) {
	  unsigned char buf[1024];
	  res = read(cmdfd, buf, sizeof(buf));
	  if (res > 0) {
	    m = &mtp2_state[0];
	    log_frame(m, 0, buf, res);
	    process_msu(m, buf, res);
	  }
	}
	close(cmdfd);
      }
    }
#endif

    /* No need to calculate timeout with ast_sched_wait, as we will be
       woken up every 2 msec. anyway to read/write dahdi buffers. */
    gettimeofday(&last, NULL);
    res = poll(fds, n_mtp2_state, 20);

    gettimeofday(&now, NULL);
    tdiff = timediff_usec(now, last);
#ifndef MTP_OVER_UDP
    if (tdiff > 5000)
      if (n_mtp2_state)
	fifo_log(m, LOG_NOTICE, "Excessive poll delay %d!\n", tdiff);//xxxx
#endif

    if(res < 0) {
      if(errno == EINTR) {
        /* Just try again. */
      } else {
        fifo_log(m, LOG_NOTICE, "poll() failure, errno=%d: %s\n",
		 errno, strerror(errno));
      }
    } else if(res > 0) {

      for (i = 0; i < n_mtp2_state; i++) {
	if(fds[i].revents & POLLPRI) {
	  mtp2_fetch_zap_event(&mtp2_state[i]);
	}
      }
      /* Do the read before write, so that we can send any responses
         immediately (since we will usually/always also have a ready
         POLLOUT condition). */
      for (i = 0; i < n_mtp2_state; i++) {
	m = &mtp2_state[i];
	if(fds[i].revents & POLLIN) {
	  unsigned char buf[1024];
	  int count = 0;

	  for(;;) {
	    res = read(fds[i].fd, buf, sizeof(buf));
	    if(res == 0) {
	      /* EOF. */
	      break;
	    } else if(res < 0) {
	      if(errno == EAGAIN || errno == EWOULDBLOCK) {
		/* Done until next successful poll(). */
		break;
	      } else if(errno == EINTR) {
		/* Try again. */
	      } else if(errno == ELAST) {
		mtp2_fetch_zap_event(m);
	      } else {
		/* Some unexpected error. */
		fifo_log(m, LOG_DEBUG, "Error reading dahdi device '%s', errno=%d: %s.\n", m->name, errno, strerror(errno));
		break;
	      }
	    } else {
	      /* Got some data. */
	      count += res;
#ifdef DO_RAW_DUMPS
	      mtp2_dump_raw(m, buf, res, 0);
#endif
	      mtp2_read_su(m, buf, res);
	    }
	  }
	  //if(count > 2*ZAP_BUF_SIZE) fifo_log(m, LOG_NOTICE, "%d bytes read (%d buffers).\n", count, count/ZAP_BUF_SIZE);
#ifndef MTP_OVER_UDP
	  if(count >= NUM_ZAP_BUF*ZAP_BUF_SIZE) {
	    fifo_log(m, LOG_NOTICE, "Full dahdi input buffer detected, incoming "
		     "packets may have been lost on link '%s' (count=%d.\n", m->name, count);
	  }
#endif
	}
      }
      for (i = 0; i < n_mtp2_state; i++) {
	m = &mtp2_state[i];
	if(fds[i].revents & POLLOUT) {
	  unsigned char* buf;
	  unsigned int len;
	  int count = 0;

	  if (m->hwmtp2 || m->hwhdlcfcs) {
	    mtp2_pick_frame(m);
	    buf = m->tx_buffer;
	    len = m->tx_len+2;
	    buf[m->tx_len] = buf[m->tx_len+1] = 0;
	    log_frame(m, 1, m->tx_buffer, m->tx_len);
	  }
	  else {
	    /* We buffer an extra ZAP_BUF_SIZE bytes locally. This creates
	       extra latency, but it is necessary to be able to detect write()
	       buffer underrun by doing an extra write() to see the EAGAIN
	       return.
	    */
	    if(!m->zap_buf_full) {
	      mtp2_fill_dahdi_buf(m, m->zap_buf);
	      m->zap_buf_full = 1;
	    }
	    buf = m->zap_buf;
	    len = ZAP_BUF_SIZE;
	  }
	  for(;;) {
            res = write(fds[i].fd, buf, len);
	    if(res == 0) {
	      /* EOF. */
	      break;
	    } else if(res < 0) {
	      if(errno == EAGAIN || errno == EWOULDBLOCK) {
		/* Done until next successful poll(). */
		break;
	      } else if(errno == EINTR) {
		/* Try again. */
	      } else if(errno == ELAST) {
		mtp2_fetch_zap_event(m);
	      } else {
		/* Some unexpected error. */
		fifo_log(m, LOG_DEBUG, "Error writing dahdi device '%s', errno=%d: %s.\n", m->name, errno, strerror(errno));
		break;
	      }
	    } else {
	      /* Successful write. */
	      count += res;
	      if (m->hwmtp2 || m->hwhdlcfcs) {
		buf += res;
		len -= res;
		if (!len)
		  break;
	      }
#ifdef DO_RAW_DUMPS
	      mtp2_dump_raw(m, m->zap_buf, res, 1);
#endif
	      m->zap_buf_full = 0;
#ifdef MTP_OVER_UDP
	      break;
#endif
	    }
	  }
	  if(count >= NUM_ZAP_BUF*ZAP_BUF_SIZE) {
	    fifo_log(m, LOG_NOTICE, "Empty Dahdi output buffer detected, outgoing "
		     "packets may have been lost on link '%s'.\n", m->name);
	  }
#ifdef MTP_OVER_UDP
	  if ((m->state != MTP2_READY) && (m->state != MTP2_INSERVICE))
	    res = poll(fds, 0, 20); /* sending lssu, small delay */
	  else
	    res = poll(fds, 0, 10); /* sending msu or fisu */
#endif
	}
      }
    }

    for (lsi = 0; lsi < n_linksets; lsi++) {
      m = NULL;
      if (!linksets[lsi].enabled)
	continue;
#ifdef xxxx
      n_inservice = 0;
      for (i = 0; i < n_mtp2_state; i++) {
	struct mtp2_state* trym = &mtp2_state[last_send_ix];
	last_send_ix = (last_send_ix + 1) % n_mtp2_state;
	if (trym->link->linkset != &linksets[lsi])
	  continue;
	if (trym->state != MTP2_INSERVICE)
	  continue;
	m = trym;
	n_inservice += 1;

	/* Handle requests from the channel driver threads.
	   We don't pull in requests when the retransmit buffer is full (otherwise
	   we would loose messages as we cannot fetch from the lffifo
	   out-of-order). */
      }
      if (!n_inservice) {
	for (i = 0; i < n_mtp2_state; i++) {
	  struct mtp2_state* trym = &mtp2_state[last_send_ix];
	  last_send_ix = (last_send_ix + 1) % n_mtp2_state;
	  if (!is_combined_linkset(trym->link->linkset, &linksets[lsi]))
	    continue;
	  if (trym->state != MTP2_INSERVICE)
	    continue;
	  m = trym;
	  n_inservice += 1;
	}
      }
#endif
      m = get_inservice_schannel(linksets[lsi].links[0]);
      if (m) {
	while(MTP_NEXT_SEQ(m->retrans_last_sent) != m->retrans_last_acked &&
	      (res = lffifo_get(sendbuf[lsi], fifobuf, sizeof(fifobuf))) != 0) {
	  if(res < 0) {
	    fifo_log(m, LOG_ERROR, "Got oversize packet in MTP request buffer -> choking on link '%s'.\n", m->name);
	    break;
	  }
	  req = (struct mtp_req *)fifobuf;
	  switch(req->typ) {
	  case MTP_REQ_ISUP:
	  case MTP_REQ_ISUP_FORWARD: {
	    if (req->isup.slink) {
	      struct mtp2_state* targetm = req->isup.slink->mtp;
	      if (targetm && (targetm->state == MTP2_INSERVICE) &&
		  (MTP_NEXT_SEQ(targetm->retrans_last_sent) != targetm->retrans_last_acked)) /* Not full */
		m = targetm;
	    }
	    int subservice = SS7_PROTO_ISUP | (m->subservice << 4);
	    if ((req->typ != MTP_REQ_ISUP) && (req->typ != MTP_REQ_ISUP_FORWARD))
	      mtp3_set_sls(variant(m), m->sls, req->buf);
	    fifo_log(m, LOG_DEBUG, "Queue MSU, lsi=%d, last_send_ix=%d, linkset=%s, m->link=%s\n", lsi, last_send_ix, linksets[lsi].name, m->link->name);
	    mtp2_queue_msu(m, subservice, req->buf, req->len);
	  }
	    break;
	  case MTP_REQ_SCCP: {
	    if (req->sccp.slink) {
	      struct mtp2_state* targetm = req->sccp.slink->mtp;
	      if (targetm && (targetm->state == MTP2_INSERVICE) &&
		  (MTP_NEXT_SEQ(targetm->retrans_last_sent) != targetm->retrans_last_acked)) /* Not full */
		m = targetm;
	    }
	    int subservice = SS7_PROTO_SCCP | (m->subservice << 4);
	    fifo_log(m, LOG_DEBUG, "Queue MSU, lsi=%d, last_send_ix=%d, linkset=%s, m->link=%s\n", lsi, last_send_ix, linksets[lsi].name, m->link->name);
	    mtp2_queue_msu(m, subservice, req->buf, req->len);
	  }
	    break;
	  case MTP_REQ_LINK_DOWN:
	    fifo_log(m, LOG_ERROR, "Got MTP_REQ_LINK_DOWN packet in MTP send buffer???.\n");
	    break;
	  case MTP_REQ_LINK_UP:
	    fifo_log(m, LOG_ERROR, "Got MTP_REQ_LINK_UP packet in MTP send buffer???.\n");
	    break;
	  case MTP_REQ_REGISTER_L4:
	    break;
	  case MTP_REQ_CLI:
	    break;
	  }
	}
      }
      else if (cluster_receivers_alive(&linksets[lsi])) {
	while((res = lffifo_get(sendbuf[lsi], fifobuf, sizeof(fifobuf))) != 0) {
	  if(res < 0) {
	    fifo_log(m, LOG_ERROR, "Got oversize packet in MTP request buffer -> choking on link '%s'.\n", m->name);
	    break;
	  }
	  req = (struct mtp_req *)fifobuf;
	  switch(req->typ) {
	  case MTP_REQ_ISUP:
	    cluster_mtp_forward(req);
	    break;
	  case MTP_REQ_ISUP_FORWARD:
	    cluster_mtp_forward(req);
	    break;
	  default:;
	    /* Ignore other requests */
	  }
	}
      }
      else {
	res = lffifo_get(sendbuf[lsi], fifobuf, sizeof(fifobuf));
	if(res < 0) {
	  fifo_log(m, LOG_ERROR, "Got oversize packet in MTP request buffer -> choking on link '%s'.\n", m->name);
	  break;
	}
	if (res > 0)
	  fifo_log(m, LOG_WARNING, "No signalling links inservice and no cluster receivers alive, dropping packet!\n");
      }
    }
    while ((res = lffifo_get(controlbuf, fifobuf, sizeof(fifobuf))) != 0) {
      int linkix = 0;
      if (!n_mtp2_state)
	continue; // No MTP signalling channels available, ignore control requests
      m = &mtp2_state[0];
      if(res < 0) {
	fifo_log(m, LOG_ERROR, "Got oversize packet in MTP control buffer.\n");
	break;
      }
      req = (struct mtp_req *)fifobuf;
      switch(req->typ) {
      case MTP_REQ_ISUP:
	fifo_log(m, LOG_ERROR, "Got ISUP packet in MTP control buffer???.\n");
	break;
      case MTP_REQ_ISUP_FORWARD:
	fifo_log(m, LOG_ERROR, "Got MTP_REQ_ISUP_FORWARD packet in MTP send buffer???.\n");
	break;
      case MTP_REQ_LINK_DOWN:
	linkix = req->link.linkix;
	m = &mtp2_state[linkix];
	fifo_log(m, LOG_DEBUG, "Taking link down on request on link '%s'.\n", m->name);
	m->state = MTP2_DOWN;
	mtp2_cleanup(m);
	l4down(m);
	break;
      case MTP_REQ_LINK_UP:
	linkix = req->link.linkix;
	m = &mtp2_state[linkix];
	start_initial_alignment(m, "CLI link up");
	break;
      case MTP_REQ_SCCP:
	break;
      case MTP_REQ_REGISTER_L4:
	break;
      case MTP_REQ_CLI:
	break;
      }
    }
    mtp_sched_runq(mtp2_sched);
  }

  return NULL;
}

void mtp_thread_signal_stop(void) {
  /* No need for explicit thread wakeup; the mtp thread wakes up every
     2msec anyway on the dahdi device. */
  stop_mtp_thread = 1;
}

struct lffifo **mtp_get_send_fifo(void) {
  return sendbuf;
}

int get_receive_pipe(void) {
  return receivepipe[0];
}

struct lffifo *mtp_get_receive_fifo(void) {
  return receivebuf;
}

static void mtp_cleanup_link(struct mtp2_state* m) {
  if(m->fd != -1) {
    close(m->fd);
    m->fd = -1;
  }
}

void mtp_cleanup(void) {
  int i;
  if(mtp2_sched) {
    mtp_sched_context_destroy(mtp2_sched);
    mtp2_sched = NULL;
  }
  for (i = 0; i < n_linksets; i++) {
    if(sendbuf[i]) {
      lffifo_free(sendbuf[i]);
      sendbuf[i] = NULL;
    }
  }
  if(receivebuf) {
    lffifo_free(receivebuf);
    receivebuf = NULL;
  }
  if(controlbuf) {
    lffifo_free(controlbuf);
    controlbuf = NULL;
  }

  if(receivepipe[0] != -1) {
    close(receivepipe[0]);
    receivepipe[0] = -1;
  }
  if(receivepipe[1] != -1) {
    close(receivepipe[1]);
    receivepipe[1] = -1;
  }

  if (this_host)
    for (i = 0; i < n_mtp2_state; i++) {
      mtp_cleanup_link(&mtp2_state[i]);
    }
}

static void mtp_init_link_data(struct mtp2_state* m) {
  m->state = MTP2_DOWN;

  m->send_fib = 1;
  m->send_bsn = 0x7f;
  m->send_bib = 1;

  m->send_sltm = 0;

  m->schannel = -1;
  m->link = NULL;

  m->fd = -1;
  m->hwmtp2 = 0;
  m->hwhdlcfcs = 0;

  m->rx_len = 0;
  m->rx_crc = 0xffff;

  m->tx_len = 0;
  m->tx_sofar = 0;
  m->tx_do_crc = 0;
  m->tx_crc = 0xffff;

  m->retrans_seq = -1;
  m->retrans_last_acked = 0x7f;
  m->retrans_last_sent = 0x7f;

  m->error_rate_mon = 0;
  m->emon_ncount = 0;
  m->emon_dcount = 0;

  m->mtp2_t1 = -1;
  m->mtp2_t2 = -1;
  m->mtp2_t3 = -1;
  m->mtp2_t4 = -1;
  m->mtp2_t7 = -1;

  m->level4_up = 0;

  m->zap_buf_full = 0;

  m->sltm_t1 = -1;
  m->sltm_t2 = -1;

  m->mtp3_t17 = -1;
}

static int mtp_init_link(struct mtp2_state* m, struct link* link, int schannel, int sls) {
  int sigtype;
  int pcbits = (link->linkset->variant == ITU_SS7) ? 14 : 24;
  mtp_init_link_data(m);
  m->link = link;
  link->mtp = m;
  fifo_log(m, LOG_NOTICE, "Initialising link '%s/%d', linkset '%s', sls %d.\n", link->name, schannel+1, link->linkset->name, sls);
  if(peeropc(m) < 0 || peeropc(m) >= (1<<24)) { 
    ast_log(LOG_ERROR, "Invalid value 0x%x for OPC.\n", peeropc(m));
    return -1;
  }
  if(linkpeerdpc(m) < 0 || linkpeerdpc(m) >= (1<<pcbits)) {
    ast_log(LOG_ERROR, "Invalid value 0x%x for DPC.\n", linkpeerdpc(m));
    goto fail;
  }
  m->send_sltm = link->send_sltm;
  m->schannel = schannel;
  m->sls = sls;
  m->subservice = link->linkset->subservice;
  m->name = link->name;

  m->fd = openschannel(link, schannel, &sigtype);
  if (m->fd < 0)
    goto fail;
  fifo_log(m, LOG_NOTICE, "Signalling channel on link '%s/%d' has signalling type 0x%04x.\n", link->name, schannel+1, sigtype);
  memset(m->backbuf, 0, sizeof(m->backbuf));
  m->backbuf_idx = 0;
  m->rx_len = 0;
  m->hwmtp2 = (sigtype & DAHDI_SIG_MTP2) == DAHDI_SIG_MTP2;
  m->hwhdlcfcs = (sigtype & DAHDI_SIG_HDLCFCS) == DAHDI_SIG_HDLCFCS;
  if (m->hwmtp2 || m->hwhdlcfcs) {
    adjust_schannel_buffers(m->fd, link, m->schannel, 32, 280);
    if (link->initial_alignment)
      t17_start(m);
  }
  else {
    fasthdlc_precalc();
#ifdef USE_ZAPTEL
    fasthdlc_init(&m->h_rx);
    fasthdlc_init(&m->h_tx);
#else
    fasthdlc_init(&m->h_rx, FASTHDLC_MODE_64);
    fasthdlc_init(&m->h_tx, FASTHDLC_MODE_64);
#endif
    /* Fill in the fasthdlc transmit buffer with the opening flag. */
    fasthdlc_tx_frame_nocheck(&m->h_tx);
    if (link->initial_alignment)
      start_initial_alignment(m, "Initial");
  }
  return 0;
 fail:
  return -1;
}


int mtp_init(void) {
  int i, n;
  int flags;
  int res;

  stop_mtp_thread = 0;
  mtp2_sched = NULL;
  for (i = 0; i < n_linksets; i++)
    sendbuf[i] = NULL;
  receivebuf = NULL;
  controlbuf = NULL;
  receivepipe[0] = receivepipe[1] = -1;

  for (i = 0; i < n_linksets; i++) {
    sendbuf[i] = lffifo_alloc(64000);
    if(sendbuf[i] == NULL) {
      ast_log(LOG_ERROR, "Out of memory allocating MTP send fifo.\n");
      goto fail;
    }
  }
  /* Make the receivebuf larger, since it will also carry ast_log
     messages and raw dump data. */
  receivebuf = lffifo_alloc(200000);
  if(receivebuf == NULL) {
    ast_log(LOG_ERROR, "Out of memory allocating MTP receive fifo.\n");
    goto fail;
  }
  controlbuf = lffifo_alloc(64000);
  if(controlbuf == NULL) {
    ast_log(LOG_ERROR, "Out of memory allocating MTP control fifo.\n");
    goto fail;
  }
  res = pipe(receivepipe);
  if(res < 0) {
    ast_log(LOG_ERROR, "Unable to allocate MTP event pipe: %s.\n",
            strerror(errno));
    goto fail;
  }
  res = fcntl(receivepipe[0], F_GETFL);
  if(res < 0) {
    ast_log(LOG_ERROR, "Could not obtain flags for read end of "
            "MTP event pipe: %s.\n", strerror(errno));
    goto fail;
  }
  flags = res | O_NONBLOCK;
  res = fcntl(receivepipe[0], F_SETFL, flags);
  if(res < 0) {
    ast_log(LOG_ERROR, "Could not set read end of MTP event pipe "
            "non-blocking: %s.\n", strerror(errno));
    goto fail;
  }
  res = fcntl(receivepipe[1], F_GETFL);
  if(res < 0) {
    ast_log(LOG_ERROR, "Could not obtain flags for write end of "
            "MTP event pipe: %s.\n", strerror(errno));
    goto fail;
  }
  flags = res | O_NONBLOCK;
  res = fcntl(receivepipe[1], F_SETFL, flags);
  if(res < 0) {
    ast_log(LOG_ERROR, "Could not set write end of MTP event pipe "
            "non-blocking: %s.\n", strerror(errno));
    goto fail;
  }
  mtp2_sched = mtp_sched_context_create();
  if(!mtp2_sched) {
    ast_log(LOG_ERROR, "Unable to create MTP2 schedule context\n");
    goto fail;
  }

  ast_log(LOG_NOTICE, "Initialising %d signalling links\n", this_host->n_slinks);
  if (this_host->n_slinks) {
    for (i = 0; i < this_host->n_slinks; i++) {
      int j;
      n = 0;
      for (j = 0; j < 32; j++) {
	if (this_host->slinks[i]->schannel.mask & (1<<j)) {
	  if (n_mtp2_state >= MAX_SCHANNELS) {
	    ast_log(LOG_ERROR, "Too many signalling channels: %d, max %d\n", n_mtp2_state, MAX_SCHANNELS);
	    goto fail;
	  }
	  res = mtp_init_link(&mtp2_state[n_mtp2_state], this_host->slinks[i], j, this_host->slinks[i]->sls[n]);
	  n_mtp2_state++;
	  n++;
	  if (res)
	    goto fail;
	}
      }
    }
  }
  else {
    /* No signalling channels for this host, notify level 4 that we are INSERVICE */
    struct mtp_event link_up_event;
    int lsi;
    /* Tell user part MTP is now INSERVICE. */
    memset(&link_up_event, 0, sizeof(link_up_event));
    link_up_event.typ = MTP_EVENT_STATUS;
    link_up_event.status.link_state = MTP_EVENT_STATUS_INSERVICE;
    for (lsi = 0; lsi < n_linksets; lsi++) {
      struct linkset* linkset = &linksets[lsi];
      int i;
      for (i = 0; i < linkset->n_links; i++) {
	if (linkset->links[i]->on_host == this_host) {
	  link_up_event.status.link = linksets[lsi].links[i];
	  link_up_event.len = 0;
	  mtp_put(NULL, &link_up_event);
	}
      }
    }
  }
  return 0;
 fail:
  mtp_cleanup();
  return -1;
}

int cmd_testfailover(int fd, int argc, const char * const * argv) {
  testfailover = 1;
  return 0;
}
