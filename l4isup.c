/* l4isup.c - ISUP protocol
 *
 * Copyright (C) 2006-2011 Netfors ApS.
 *
 * Author: Anders Baekgaard <ab@netfors.com>
 * Based on work by: Kristian Nielsen <kn@sifira.dk>,
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

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <math.h>

#include "asterisk.h"
#include "asterisk/logger.h"
#include "asterisk/options.h"
#include "asterisk/channel.h"
#include "asterisk/frame.h"
#include "asterisk/utils.h"
#include "asterisk/sched.h"
#include "asterisk/cli.h"
#include "asterisk/lock.h"
#include "asterisk/causes.h"
#include "asterisk/pbx.h"
#include "asterisk/dsp.h"
#include "asterisk/callerid.h"
#include "asterisk/indications.h"
#include "asterisk/module.h"
#include "asterisk/alaw.h"
#include "asterisk/ulaw.h"

#ifdef USE_ZAPTEL
#include "zaptel.h"
#define DAHDI_DIALING ZT_DIALING
#define DAHDI_EVENT_DIALCOMPLETE ZT_EVENT_DIALCOMPLETE
#define DAHDI_GETGAINS ZT_GETGAINS
#define DAHDI_LAW_ALAW ZT_LAW_ALAW
#define DAHDI_LAW_MULAW ZT_LAW_MULAW
#define DAHDI_SETGAINS ZT_SETGAINS
#ifdef ZT_TONEDETECT
#define DAHDI_TONEDETECT ZT_TONEDETECT
#define DAHDI_TONEDETECT_ON ZT_TONEDETECT_ON
#define DAHDI_TONEDETECT_MUTE ZT_TONEDETECT_MUTE
#define DAHDI_EVENT_DTMFDOWN ZT_EVENT_DTMFDOWN
#define DAHDI_EVENT_DTMFUP ZT_EVENT_DTMFUP
#endif
#define dahdi_gains zt_gains
#else
#include <dahdi/user.h>
#endif

#ifndef DSP_FEATURE_DIGIT_DETECT
#define DSP_FEATURE_DIGIT_DETECT DSP_FEATURE_DTMF_DETECT
#endif

#include "astversion.h"
#include "config.h"
#include "lffifo.h"
#include "utils.h"
#include "mtp.h"
#include "transport.h"
#include "isup.h"
#include "l4isup.h"
#include "cluster.h"
#include "mtp3io.h"
#ifdef MODULETEST
#include "moduletest.h"
#endif

enum circuit_states {
  /* Circuit idle, ready to accept or initiate calls. */
  ST_IDLE,
  /* An IAM has been received, but no ACM or CON has been sent back yet. */
  ST_GOT_IAM,
  /* An IAM has been sent to initiate a call, but no ACM or CON has been
     received back yet. */
  ST_SENT_IAM,
  /* We have sent an ACM and have to send an ANM now */
  ST_SENT_ACM,
  /* We have sent IAM and received ACM, so waiting for ANM. */
  ST_GOT_ACM,
  /* A call is connected (incoming or outgoing). */
  ST_CONNECTED,
  /* A continuity check is ongoing */
  ST_CONCHECK,
  /* A REL message has been received, but RLC has not been sent
     yet. ast_softhangup() has been called on the channel.*/
  ST_GOT_REL,
  /* A REL has been sent (from ss7_hangup), and so the struct ast_channel *
     has been deallocated, but the circuit is still waiting for RLC to be
     received before being able to initiate new calls. If timer T16 or T17
     is running, this state instead means that a "circuit reset" has been
     sent, and we are waiting for RLC. If a REL is received in this state,
     send RLC and stay in this state, still waiting for RLC */
  ST_SENT_REL,
};

struct ss7_chan {
  /* The first few fields of this struct are protected by the global lock
     mutex, not by the ss7_chan->lock mutex embedded in the struct. This is
     necessary to preserve locking order and avoid deadlocks. */
  struct ast_channel *owner;
  struct ss7_chan *next_idle;   /* Linked list of idle CICs */
  struct link* link;		/* Link carrying circuit */
  int cic;
  int reset_done;               /* False until circuit has been init reset */
  int hangupcause;
  int dohangup;
  int has_inband_ind;
  int charge_indicator;
  int is_digital;
  block blocked;
  /* Circuit equipped */
  int equipped;

  ast_mutex_t lock;             /* Protects rest of this struct */
  enum circuit_states state;
  int zaptel_fd;
  int t1;
  int t2;
  int t5;
  int t6;
  int t7;
  int t9;
  int t12;
  int t14;
  int t16;
  int t17;
  int t18;
  int t19;
  int t20;
  int t21;
  int t22;
  int t23;
  int t35;
  int t36;
  struct iam iam;		/* Last incoming IAM parameters */
  char* addr;			/* called addr */
  int attempts;			/* Number of outgoing call attempts on addr */
  int echocan_start;
  int echocancel;
  struct timeval lastread;

  unsigned char buffer[AST_FRIENDLY_OFFSET + AUDIO_READSIZE];
  struct ast_frame frame;
  int sending_dtmf;
  struct ast_dsp *dsp;
  int grs_count;                /* Count of CICs in ISUP GRS message */
  int cgb_mask;                 /* Mask of CICs in ISUP CGB message */
  int law;
  char context[AST_MAX_CONTEXT];
  char language[MAX_LANGUAGE];
};

/*   Locking order (deadlock avoidance): global lock, chan->lock, pvt->lock
*/


/* Global list of idle CICs, sorted in order of "time free". Linked through
   the ss7_chan->next_idle pointers. Protected by global lock. */


static struct timeval now;
static struct timeval mtp_fifo_full_report;

/* used by moduletest.c */
int isup_called_party_num_encode(struct ss7_chan *pvt, char *number, unsigned char *param, int plen);
int isup_called_party_num_encode_no_st(struct ss7_chan *pvt, char *number, unsigned char *param, int plen);
int isup_calling_party_num_encode(char *number, int pres_restr, int si, unsigned char *param, int plen);

static pthread_t continuity_check_thread = AST_PTHREADT_NULL;
static int continuity_check_thread_running = 0;
AST_MUTEX_DEFINE_STATIC(continuity_check_lock);
static int continuity_check_changes = 0;
static int must_stop_continuity_check_thread = 0;


static void isup_send_grs(struct ss7_chan *pvt, int count, int do_timers);

#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
static struct ast_channel *ss7_requester(const char *type, int format, void *data, int *cause);
#else
static struct ast_channel *ss7_requester(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause);
#endif
static int ss7_send_digit_begin(struct ast_channel *chan, char digit);
static int ss7_send_digit_end(struct ast_channel *chan, char digit, unsigned int duration);
static int ss7_call(struct ast_channel *chan, char *addr, int timeout);
static int ss7_hangup(struct ast_channel *chan);
static int ss7_answer(struct ast_channel *chan);
static struct ast_frame *ss7_read(struct ast_channel * chan);
static int ss7_write(struct ast_channel * chan, struct ast_frame *frame);
static struct ast_frame *ss7_exception(struct ast_channel *chan);
static int ss7_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
#ifdef USE_ASTERISK_1_2
static int ss7_indicate(struct ast_channel *chan, int condition);
#else
  static int ss7_indicate(struct ast_channel *chan, int condition, const void* data, size_t datalen);
#endif
static void t7_clear(struct ss7_chan *pvt);
static void t1_start(struct ss7_chan *pvt);
static void t5_start(struct ss7_chan *pvt);
static void t16_start(struct ss7_chan *pvt);
static void t16_clear(struct ss7_chan *pvt);
static void t17_start(struct ss7_chan *pvt);
static void t19_start(struct ss7_chan *pvt);
static void t21_start(struct ss7_chan *pvt);
static int do_group_circuit_block_unblock(struct linkset* linkset, int firstcic, unsigned long cgb_mask, int sup_type_ind, int own_cics_only, int do_timers, int do_block);
static struct ss7_chan* reattempt_call(struct ss7_chan *pvt);
static void *continuity_check_thread_main(void *data);
static void handle_complete_address(struct ss7_chan *pvt);

static const char type[] = "SS7";
static const char tdesc[] = "SS7 Protocol Driver";
static const struct ast_channel_tech ss7_tech = {
  .type = type,
  .description = tdesc,
  .capabilities = AST_FORMAT_ALAW | AST_FORMAT_ULAW,
  .requester = ss7_requester,
#ifdef USE_ASTERISK_1_2
  .send_digit = ss7_send_digit_begin,
#else
  .send_digit_begin = ss7_send_digit_begin,
  .send_digit_end = ss7_send_digit_end,
#endif
  .call = ss7_call,
  .hangup = ss7_hangup,
  .answer = ss7_answer,
  .read = ss7_read,
  .write = ss7_write,
  .exception = ss7_exception,
  .fixup = ss7_fixup,
  .indicate = ss7_indicate,
};


/* Send fifo for sending protocol requests to the MTP thread.
   The fifo is lock-free (one thread may put and another get simultaneously),
   but multiple threads doing put must be serialized with this mutex. */
AST_MUTEX_DEFINE_STATIC(mtp_send_mutex);
static struct lffifo **mtp_send_fifo;

#ifdef USE_ASTERISK_1_2
#define ast_channel_lock(chan) ast_mutex_lock(&chan->lock)
#define ast_channel_unlock(chan) ast_mutex_unlock(&chan->lock)
#define ast_strdup(s) strdup(s)
#define ast_malloc(d) malloc(d)
#endif  

#ifdef USE_ASTERISK_1_2
#define	AST_FRAME_SET_BUFFER(fr, _base, _ofs, _datalen)	\
	{					\
	(fr)->data = (char *)_base + (_ofs);	\
	(fr)->offset = (_ofs);			\
	(fr)->datalen = (_datalen);		\
	}
#define FRAME_DATA(fr,offset) (((unsigned char*) (fr)->data) + offset)
#else
#ifdef USE_ASTERISK_1_4
#define FRAME_DATA(fr,offset) (((unsigned char*) (fr)->data) + offset)
#else
#define FRAME_DATA(fr,offset) (((unsigned char*) (fr)->data.ptr) + offset)
#endif
#endif

static int usecnt = 0;

#ifdef USE_ASTERISK_1_2
AST_MUTEX_DEFINE_STATIC(usecnt_lock);
int usecount(void);

static void incr_usecount(void)
{
  ast_mutex_lock(&usecnt_lock);
  usecnt++;
  ast_mutex_unlock(&usecnt_lock);
}

static void decr_usecount(void)
{
  ast_mutex_lock(&usecnt_lock);
  usecnt--;
  if (usecnt < 0)
    ast_log(LOG_WARNING, "Usecnt < 0???\n");
  ast_mutex_unlock(&usecnt_lock);
}

int usecount(void)
{
  int res;
  ast_mutex_lock(&usecnt_lock);
  res = usecnt;
  ast_mutex_unlock(&usecnt_lock);
  return res;
}
#else
static void incr_usecount(void)
{
  ast_atomic_fetchadd_int(&usecnt, 1);
  ast_update_use_count();
}

static void decr_usecount(void)
{
  ast_atomic_fetchadd_int(&usecnt, -1);
  ast_update_use_count();
  if (usecnt < 0)
    ast_log(LOG_WARNING, "Usecnt < 0???\n");
}
#endif

static int str2redirectreason(const char *str)
{
  if (strcmp(str, "UNKNOWN") == 0)
    return 0x00;
  else if (strcmp(str, "BUSY") == 0)
    return 0x01;
  else if (strcmp(str, "NO_REPLY") == 0)
    return 0x02;
  else if (strcmp(str, "UNCONDITIONAL") == 0)
    return 0x03;
  else if (strcmp(str, "UNREACHABLE") == 0)
    return 0x06;
  else {
    ast_log(LOG_NOTICE, "Invalid redirection reason value '%s' in PRIREDIRECTREASON variable.\n", str);
    return 0x00;
  }
}

static void request_hangup(struct ast_channel* chan, int hangupcause)
{
  chan->hangupcause = hangupcause;
  ast_softhangup_nolock(chan, AST_SOFTHANGUP_DEV);
}



/* Lookup OPC for circuit */
static inline int peeropc(struct ss7_chan* pvt)
{
  return pvt->link->linkset->opc;
}

/* Lookup DPC for circuit */
static inline int peerdpc(struct ss7_chan* pvt)
{
  return pvt->link->linkset->dpc;
}

/* Lookup variant for circuit */
static inline ss7_variant variant(struct ss7_chan* pvt)
{
  return pvt->link->linkset->variant;
}

static void mtp_enqueue_isup_packet(struct link* link, int cic, unsigned char *msg, int msglen, int reqtyp)
{
  int res;
  unsigned char req_buf[MTP_REQ_MAX_SIZE];
  struct mtp_req *req = (struct mtp_req *)req_buf;
  struct linkset* linkset = link->linkset;
  struct link* slink = NULL;
  int lsi = link->linkset->lsi;

  if(sizeof(struct mtp_req) + msglen > sizeof(req_buf)) {
    ast_log(LOG_ERROR, "Attempt to send oversized ISUP message of len "
            "%d > %zu.\n", msglen, sizeof(req_buf) - sizeof(struct mtp_req));
    return;
  }
  switch (link->linkset->loadshare) {
  case LOADSHARE_NONE:
    if (!link->schannel.mask)
      slink = link;
    break;
  case LOADSHARE_LINKSET:
    if (linkset->n_slinks)
      slink = linkset->slinks[cic % linkset->n_slinks];
    break;
  case LOADSHARE_COMBINED_LINKSET:
    {
      int n_slinks = 0;
      int six;
      for (lsi = 0; lsi < n_linksets; lsi++)
	if (linksets[lsi].enabled)
	  if (&linksets[lsi] == linkset || 
	      (is_combined_linkset(linkset, &linksets[lsi])))
	    n_slinks += linksets[lsi].n_slinks;
      if (n_slinks) {
	six = cic % n_slinks;
	n_slinks = 0;
	for (lsi = 0; lsi < n_linksets; lsi++)
	  if (linksets[lsi].enabled)
	    if (&linksets[lsi] == linkset || 
		(is_combined_linkset(linkset, &linksets[lsi]))) {
	      if (six - n_slinks < linksets[lsi].n_slinks) {
		slink = linksets[lsi].slinks[six - n_slinks];
		break;
	      }
	      n_slinks += linksets[lsi].n_slinks;
	    }
      }
    }
    break;
  }

  if (slink)
    lsi = slink->linkset->lsi;
  else
    lsi = linkset->lsi;
  memset(req, 0, sizeof(*req));
  req->typ = reqtyp;
  req->isup.slink = slink;
  req->isup.link = link;
  req->isup.slinkix = slink ? slink->linkix : 0;
  req->len = msglen;
  memcpy(req->buf, msg, msglen);

  if(slink && slink->mtp3fd > -1) {
    res = mtp3_send(slink->mtp3fd, (unsigned char *)req, sizeof(struct mtp_req) + req->len);
    if (res < 0) {
      ast_log(LOG_DEBUG, "closing connection to mtp3d, fd %d, res: %d, err: %s\n", slink->mtp3fd, res, strerror(errno));
      close(slink->mtp3fd);
      slink->mtp3fd = -1;
    }
    {
      struct isup_msg isup_msg;
      res = decode_isup_msg(&isup_msg, slink->linkset->variant, msg, msglen);
      ast_log(LOG_DEBUG, "Sent to mtp3d: %s (CIC %d), link '%s'\n", isupmsg(isup_msg.typ), cic, slink->name);
    }
    return;
  }

  ast_mutex_lock(&mtp_send_mutex);
  if (!mtp_send_fifo || !mtp_send_fifo[lsi]) {
    if (cluster_receivers_alive(linkset)) {
      ast_log(LOG_DEBUG, "MTP send fifo not ready, forwarding to cluster, lsi=%d.\n", lsi);
      cluster_mtp_forward(req);
    }
    else
      ast_log(LOG_WARNING, "MTP send fifo not ready, lsi=%d.\n", lsi);
    ast_mutex_unlock(&mtp_send_mutex);
    return;
  }
  ast_log(LOG_DEBUG, "Queue packet CIC=%d, len=%d, linkset='%s', link='%s', slinkset='%s', slink='%s'\n", cic, msglen, linkset->name, link->name, linksets[lsi].name, slink ? slink->name : "(none)");
  res = lffifo_put(mtp_send_fifo[lsi], (unsigned char *)req, sizeof(struct mtp_req) + req->len);
  ast_mutex_unlock(&mtp_send_mutex);
  if(res != 0) {
    gettimeofday(&now, NULL);
    if (timediff_msec(now, mtp_fifo_full_report) > 30000) {
      ast_log(LOG_WARNING, "MTP send fifo full (MTP thread blocked?).\n");
      gettimeofday(&mtp_fifo_full_report, NULL);
    }
  }
}

static void mtp_enqueue_isup(struct ss7_chan* pvt, unsigned char *msg, int msglen)
{
  mtp_enqueue_isup_packet(pvt->link, pvt->cic, msg, msglen, MTP_REQ_ISUP);
}

static void mtp_enqueue_isup_forward(struct ss7_chan* pvt, unsigned char *msg, int msglen)
{
  mtp_enqueue_isup_packet(pvt->link, pvt->cic, msg, msglen, MTP_REQ_ISUP_FORWARD);
}

/* Deprecated, use find_pvt_with_pc */
__attribute__((__deprecated__))
static struct ss7_chan* find_pvt(struct link* slink, int cic)
{
  struct linkset* ls;
  int lsi;

  ls = slink->linkset;
  if (ls->cic_list[cic])
    return ls->cic_list[cic];
  for (lsi = 0; lsi < n_linksets; lsi++)
    if (is_combined_linkset(ls, &linksets[lsi]))
      if (linksets[lsi].cic_list[cic])
	return linksets[lsi].cic_list[cic];
  return NULL;
}

static struct ss7_chan* find_pvt_with_pc(struct link* slink, int cic, int pc)
{
  struct linkset* ls;
  int lsi;

  ls = slink->linkset;
  if (ls->dpc == pc) {
    if (ls->cic_list[cic])
      return ls->cic_list[cic];
    for (lsi = 0; lsi < n_linksets; lsi++)
      if (is_combined_linkset(ls, &linksets[lsi]))
        if (linksets[lsi].cic_list[cic])
          return linksets[lsi].cic_list[cic];
  } else {
    for (lsi = 0; lsi < n_linksets; lsi++)
      if (is_combined_linkset(ls, &linksets[lsi]))
        if (linksets[lsi].dpc == pc)
          if (linksets[lsi].cic_list[cic])
            return linksets[lsi].cic_list[cic];
  }
  return NULL;
}

/* This function must be called with the global lock mutex held. */
static void remove_from_idlelist(struct ss7_chan *pvt) {
  struct linkset* linkset = pvt->link->linkset;
  struct ss7_chan *prev, *cur;

  cur = linkset->group_linkset->idle_list;
  prev = NULL;
  while(cur != NULL) {
    if(pvt->cic == cur->cic) {
      if(prev == NULL) {
        linkset->group_linkset->idle_list = pvt->next_idle;
      } else {
        prev->next_idle = pvt->next_idle;
      }
      pvt->next_idle = NULL;
      return;
    }
    prev = cur;
    cur = cur->next_idle;
  }
  ast_log(LOG_NOTICE, "Trying to remove CIC=%d from idle list, but not found?!?.\n", pvt->cic);
}

/* This function must be called with the global lock mutex held. */
static void add_to_idlelist(struct ss7_chan *pvt) {
  struct linkset* linkset = pvt->link->linkset;
  struct ss7_chan *prev, *cur;

  cur = linkset->group_linkset->idle_list;
  prev = NULL;
  while(cur != NULL) {
    if(pvt->cic == cur->cic) {
      ast_log(LOG_NOTICE, "Trying to add CIC=%d to idle list, but already there?!?\n", pvt->cic);
      return;
    }
    cur = cur->next_idle;
  }

  pvt->next_idle = linkset->group_linkset->idle_list;
  linkset->group_linkset->idle_list = pvt;
}

/* This implements hunting policy. It must be called with the global lock mutex
   held. */

/* This implements the policy: Primary hunting group odd CICs, secondary
   hunting group even CICs. Choose least recently used CIC. */
static struct ss7_chan *cic_hunt_odd_lru(struct linkset* linkset, int first_cic, int last_cic) {
  struct ss7_chan *cur, *prev, *best, *best_prev;
  int odd;

  best = NULL;
  best_prev = NULL;
  for(odd = 1; odd >= 0; odd--) {
    for(cur = linkset->group_linkset->idle_list, prev = NULL; cur != NULL; prev = cur, cur = cur->next_idle) {
      /* Don't select lines that are resetting or blocked. */
      if(!cur->reset_done || (cur->blocked & (BL_LH|BL_RM|BL_RH|BL_UNEQUIPPED|BL_LINKDOWN|BL_NOUSE))) {
        continue;
      }
      /* is this cic within the selected range? */
      if(cur->cic < first_cic || cur->cic > last_cic) {
        continue;
      }
      if((cur->cic % 2) == odd) {
        best = cur;
        best_prev = prev;
      }
    }
    if(best != NULL) {
      if(best_prev == NULL) {
        linkset->group_linkset->idle_list = best->next_idle;
      } else {
        best_prev->next_idle = best->next_idle;
      }
      best->next_idle = NULL;
      return best;
    }
  }
  ast_log(LOG_WARNING, "No idle circuit found, linkset=%s.\n", linkset->name);
  return NULL;
}

/* This implements the policy: Primary hunting group even CICs, secondary
   hunting group odd CICs. Choose most recently used CIC. */
static struct ss7_chan *cic_hunt_even_mru(struct linkset* linkset, int first_cic, int last_cic) {
  struct ss7_chan *cur, *prev, *best, *best_prev;

  best = NULL;
  best_prev = NULL;

  for(cur = linkset->group_linkset->idle_list, prev = NULL; cur != NULL; prev = cur, cur = cur->next_idle) {
    /* Don't select lines that are resetting or blocked. */
    if(!cur->reset_done || (cur->blocked & (BL_LH|BL_RM|BL_RH|BL_UNEQUIPPED|BL_LINKDOWN|BL_NOUSE))) {
      continue;
    }
    /* is this cic within the selected range? */
    if(cur->cic < first_cic || cur->cic > last_cic) {
      continue;
    }
    if((cur->cic % 2) == 0) {
      /* Choose the first idle even circuit, if any. */
      best = cur;
      best_prev = prev;
      break;
    } else if(best == NULL) {
      /* Remember the first odd circuit, in case no even circuits are
         available. */
      best = cur;
      best_prev = prev;
    }
  }

  if(best != NULL) {
    if(best_prev == NULL) {
      linkset->group_linkset->idle_list = best->next_idle;
    } else {
      best_prev->next_idle = best->next_idle;
    }
    best->next_idle = NULL;
    return best;
  } else {
    ast_log(LOG_WARNING, "No idle circuit found, linkset=%s.\n", linkset->name);
    return NULL;
  }
}

/* This implements the policy: Sequential low to high CICs */
static struct ss7_chan *cic_hunt_seq_lth_htl(struct linkset* linkset, int lth, int first_cic, int last_cic)
{
  struct ss7_chan *cur, *prev, *best = NULL, *best_prev = NULL;

  for(cur = linkset->group_linkset->idle_list, prev = NULL; cur != NULL; prev = cur, cur = cur->next_idle) {
    /* Don't select lines that are resetting or blocked. */
    if(!cur->reset_done || (cur->blocked & (BL_LH|BL_RM|BL_RH|BL_UNEQUIPPED|BL_LINKDOWN|BL_NOUSE))) {
      continue;
    }
    /* is this cic within the selected range? */
    if(cur->cic < first_cic || cur->cic > last_cic) {
      continue;
			          }
    if (!best) {
      best = cur;
      continue;
    }
    if (lth) {
      if (cur->cic < best->cic) {
	best = cur;
	best_prev = prev;
      }
    }
    else {
      if (cur->cic > best->cic) {
	best = cur;
	best_prev = prev;
      }
    }
  }

  if(best != NULL) {
    if(best_prev == NULL) {
      linkset->group_linkset->idle_list = best->next_idle;
    } else {
      best_prev->next_idle = best->next_idle;
    }
    best->next_idle = NULL;
    return best;
  } else {
    ast_log(LOG_WARNING, "No idle circuit found, linkset=%s.\n", linkset->name);
    return NULL;
  }
}

static void handle_redir_info(struct ast_channel *chan, struct isup_redir_info* inf)
{
  if(inf->is_redirect) {
    char *string_reason;
    char count[4];
    char redir[4];
    int res;

    snprintf(redir, sizeof(redir), "%d", inf->is_redirect);
    /* The names here are taken to match with those used in chan_zap.c
       redirectingreason2str(). */
    switch(inf->reason) {
    case 1:
      string_reason = "BUSY";
      break;
    case 2:
      /* Cause 4 "deflection during alerting"; not sure, but it seems to be
	 more or less equivalent to "no reply".*/
    case 4:
      string_reason = "NO_REPLY";
      break;
    case 3:
      /* Cause 5 "deflection immediate response"; not sure, but it seems to
	 be more or less equivalent to "unconditional".*/
    case 5:
      string_reason = "UNCONDITIONAL";
      break;
    case 6:
      string_reason = "UNREACHABLE";
      break;
    default:
      string_reason = "UNKNOWN";
      break;
    }
    /* Set SS7_REDIRECTCOUNT */
    res = snprintf(count, sizeof(count), "%d",inf->count + 1);
    pbx_builtin_setvar_helper(chan, "__SS7_REDIRECTCOUNT", (res > 0) ? count : "1");
    /* Use underscore variable to make it inherit like other callerid info. */
    pbx_builtin_setvar_helper(chan, "__PRIREDIRECTREASON", string_reason);
    pbx_builtin_setvar_helper(chan, "SS7_REDIR", redir);
  }
}

/* Send a "release" message. */
static void isup_send_rel(struct ss7_chan *pvt, int cause) {
  struct ast_channel *chan = pvt->owner;
  char* redir  = chan ? (char*) pbx_builtin_getvar_helper(chan, "SS7_REDIR") : NULL;
  char* rdni  = chan ? (char*) pbx_builtin_getvar_helper(chan, "SS7_RDNI") : NULL;
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  unsigned char param[2];
  const char *strp;

  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), pvt->cic, ISUP_REL, &current);
  isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 1, 1);
  param[0] = 0x85;              /* Last octet, ITU-T coding, private network */
  param[1] = 0x80 | (cause & 0x7f); /* Last octet */
  isup_msg_add_variable(msg, sizeof(msg), &varptr, &current, param, 2);
  isup_msg_start_optional_part(msg, sizeof(msg), &varptr, &current);

  if (redir) {
    unsigned char param_redir[2];
    unsigned char reason = 0x03, rcount = 1;

    param_redir[0] = atoi(redir);
    strp  = chan ? (char*) pbx_builtin_getvar_helper(chan, "PRIREDIRECTREASON") : NULL;
    if (strp)
      reason = str2redirectreason(strp);
    /* Read SS7_REDIRECTCOUNT and use it to set redirection counter (see ITU-T Q.763 3.44) */
    strp = pbx_builtin_getvar_helper(chan, "SS7_REDIRECTCOUNT");
    if (strp) {
      char *endptr;
      unsigned long val = strtoul(strp, &endptr, 0);
      if ((strp == endptr) || val < 0 || val > 7)
        ast_log(LOG_NOTICE, "Invalid redirection count value '%ld' "
                            "in SS7_REDRECTCOUNT variable.\n", val);
      else
        rcount = val;
    }
    param_redir[1] = ((reason & 0x0F) << 4) | (rcount & 0x07);   /* redirecting reason, counter */
    isup_msg_add_optional(msg, sizeof(msg), &current, IP_REDIRECTION_INFORMATION,
			  param_redir, 2);
  }
  if (rdni && *rdni) {
    unsigned char param_rdni[2 + PHONENUM_MAX];
    int res = isup_calling_party_num_encode(rdni, 0 /* no pres_restr */, 0 /* national use: user provided, not verified */, param_rdni, sizeof(param_rdni));
    isup_msg_add_optional(msg, sizeof(msg), &current, IP_REDIRECTION_NUMBER, param_rdni, res);
  }


  isup_msg_end_optional_part(msg, sizeof(msg), &current);
  mtp_enqueue_isup(pvt, msg, current);
}

/* Send a "release confirmed" message. */
static void isup_send_rlc(struct ss7_chan* pvt) {
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  int cic = pvt->cic;

  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), cic, ISUP_RLC, &current);
  if (variant(pvt) != ANSI_SS7) {
    isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 0, 1);
    isup_msg_start_optional_part(msg, sizeof(msg), &varptr, &current);
    isup_msg_end_optional_part(msg, sizeof(msg), &current);
  }
  mtp_enqueue_isup(pvt, msg, current);
}

/* Send a "reset circuit" message. */
static void isup_send_rsc(struct ss7_chan* pvt) {
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  int cic = pvt->cic;

  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), cic, ISUP_RSC, &current);
  isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 0, 0);
  mtp_enqueue_isup(pvt, msg, current);
}

/* Send an "address complete" message. */
static void isup_send_acm(struct ss7_chan* pvt) {
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  unsigned char param[2];
  int cic = pvt->cic;

  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), cic, ISUP_ACM, &current);
  param[0] = 0x12;
  param[1] = 0x14;
	   
  isup_msg_add_fixed(msg, sizeof(msg), &current, param, 2);
  if (pvt->has_inband_ind) {
    unsigned char param_opt_backw_ind[1];
    param_opt_backw_ind[0] = 0x01;
    isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 0, 1);
    isup_msg_start_optional_part(msg, sizeof(msg), &varptr, &current);
    isup_msg_add_optional(msg, sizeof(msg), &current, IP_OPTIONAL_BACKWARD_CALL_INDICATORS,
			  param_opt_backw_ind, 1);
    isup_msg_end_optional_part(msg, sizeof(msg), &current);
  }
  else {
    isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 0, 1);
  }
  mtp_enqueue_isup(pvt, msg, current);
}

/* Send a "circuit group blocking" message. */
static void isup_send_cgb(struct ss7_chan* pvt, int mask) {
  int sup_type_ind = 0x00; /* Maintenance oriented supervision message type */
  int cic = pvt->cic;

  if (pvt->equipped)
    sup_type_ind = 0x00; /* Maintenance oriented supervision message type */
  else
    sup_type_ind = 0x01; /* Hardware failure oriented */
  do_group_circuit_block_unblock(pvt->link->linkset, cic, mask, sup_type_ind, 0, 0, 1);
}

/* Send a "circuit group unblocking" message. */
static void isup_send_cgu(struct ss7_chan* pvt, int mask) {
  int sup_type_ind = 0x00; /* Maintenance oriented supervision message type */
  int cic = pvt->cic;

  if (pvt->equipped)
    sup_type_ind = 0x00; /* Maintenance oriented supervision message type */
  else
    sup_type_ind = 0x01; /* Hardware failure oriented */
  do_group_circuit_block_unblock(pvt->link->linkset, cic, mask, sup_type_ind, 0, 0, 0);
}

/* Send a "blocked" message. */
static void isup_send_blk(struct ss7_chan *pvt)
{
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  
  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), pvt->cic, ISUP_BLK, &current);
  isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 0, 0);
  mtp_enqueue_isup(pvt, msg, current);
}

/* Send an "unblocked" message. */
static void isup_send_ubl(struct ss7_chan *pvt)
{
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  
  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), pvt->cic, ISUP_UBL, &current);
  isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 0, 0);
  mtp_enqueue_isup(pvt, msg, current);
}

/* Reset circuit. Called with pvt->lock held */
static void reset_circuit(struct ss7_chan* pvt)
{
  isup_send_rsc(pvt);
  t16_start(pvt);
}

/* Initiate release circuit. Called with pvt->lock held */
static void initiate_release_circuit(struct ss7_chan* pvt, int cause)
{
  pvt->hangupcause = cause; /* Remember for REL retransmit */
  /* We sometimes get hangupcause=0 (seen when no match in dialplan, not
     even invalid handler). This doesn't work too well, for example
     ast_softhangup() doesn't actually hang up when hangupcause=0. */
  if(pvt->hangupcause == 0) {
    pvt->hangupcause = AST_CAUSE_NORMAL_CLEARING;
  }
  isup_send_rel(pvt, pvt->hangupcause);
  pvt->state = ST_SENT_REL;
  /* Set up timer T1 and T5 waiting for RLC. */
  t1_start(pvt);
  t5_start(pvt);
}

/* Setup a new channel, for an incoming or an outgoing call.
   Assumes called with global lock and pvt->lock held. */
static struct ast_channel *ss7_new(struct ss7_chan *pvt, int state, char* cid_num, char* exten) {
  struct ast_channel *chan;
  int format;
#ifdef USE_ASTERISK_1_2
  chan = ast_channel_alloc(1);
  if(!chan) {
    return NULL;
  }
  snprintf(chan->name, sizeof(chan->name), "%s/%s/%d", type, pvt->link->linkset->name, pvt->cic);
  chan->type = type;
#else
#if defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  chan = ast_channel_alloc(1, state, cid_num, NULL, NULL, exten, pvt->context, 0, "%s/%s/%d", type, pvt->link->linkset->name, pvt->cic);
#else
  chan = ast_channel_alloc(1, state, cid_num, NULL, NULL, exten, pvt->context, NULL, 0, "%s/%s/%d", type, pvt->link->linkset->name, pvt->cic);
#endif
  ast_jb_configure(chan, ss7_get_global_jbconf());
  if(!chan) {
    return NULL;
  }
#endif

  chan->tech = &ss7_tech;
  if (variant(pvt) == ANSI_SS7)
    format = AST_FORMAT_ULAW;
  else
    format = AST_FORMAT_ALAW;
  chan->nativeformats = format;
  chan->rawreadformat = format;
  chan->rawwriteformat = format;
  chan->readformat = format;
  chan->writeformat = format;
  ast_setstate(chan, state);
  chan->fds[0] = pvt->zaptel_fd;

  chan->tech_pvt = pvt;
  pvt->owner = chan;

  incr_usecount();

  flushchannel(pvt->zaptel_fd, pvt->cic);
  pvt->lastread.tv_sec = pvt->lastread.tv_usec = 0;
  return chan;
}

/* hunt free CIC */
static struct ss7_chan* cic_hunt(struct linkset* linkset, int first_cic, int last_cic)
{
  if(first_cic > last_cic) {
     ast_log(LOG_ERROR, "first CIC: %d greater than last CIC: %d\n", first_cic, last_cic);
     return NULL;
  }
  if(first_cic < linkset->first_cic || first_cic > linkset->last_cic || last_cic > linkset->last_cic) {
     ast_log(LOG_ERROR, "CICs not in valid range, first: %d last: %d\n", first_cic, last_cic);
     return NULL;
  }

  struct ss7_chan* pvt;
  switch(linkset->hunt_policy) {
  case HUNT_ODD_LRU:
    pvt = cic_hunt_odd_lru(linkset, first_cic, last_cic);
    break;
  case HUNT_EVEN_MRU:
    pvt = cic_hunt_even_mru(linkset, first_cic, last_cic);
    break;
  case HUNT_SEQ_LTH:
    pvt = cic_hunt_seq_lth_htl(linkset, 1, first_cic, last_cic);
    break;
  case HUNT_SEQ_HTL:
    pvt = cic_hunt_seq_lth_htl(linkset, 0, first_cic, last_cic);
    break;
  default:
    pvt = NULL;
    ast_log(LOG_ERROR, "Internal error: invalid hunting policy %d.\n",
	    linkset->hunt_policy);
  }
  return pvt;
}

/* Request an SS7 channel. */
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
static struct ast_channel *ss7_requester(const char *type, int format, void *data, int *cause)
#else
static struct ast_channel *ss7_requester(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause)
#endif
{
  char *arg = data;
  struct ast_channel *chan;
  struct ss7_chan *pvt;
  struct linkset* linkset = this_host->default_linkset;
  char *sep = strchr(arg, '/');
  char *cic_sep = strchr(arg, ':');
  int first_cic, last_cic;

  ast_log(LOG_DEBUG, "SS7 request (%s/%s) format = 0x%llX.\n", type, arg, (long long) format);

  if(!(format & (AST_FORMAT_ALAW | AST_FORMAT_ULAW))) {
    ast_log(LOG_NOTICE, "Audio format 0x%llX not supported by SS7 channel.\n", (long long) format);
    return NULL;
  }
  if (sep) {
    char name_buf[100];
    if(cic_sep != NULL) {
      strncpy(name_buf, arg, cic_sep-arg);
      name_buf[cic_sep-arg] = 0;
    }
    else {
      strncpy(name_buf, arg, sep-arg);
      name_buf[sep-arg] = 0;
    }
    if (!has_linkset_group(name_buf)) {
      linkset = lookup_linkset(name_buf);
      if (!linkset) {
	ast_log(LOG_ERROR, "SS7 requester: No such linkset: '%s', using default\n", name_buf);
	linkset = this_host->default_linkset;
      }
    } else
      linkset = lookup_linkset_for_group(name_buf, 0);
    if (!linkset) {
      ast_log(LOG_ERROR, "SS7 requester: Cannot use linkset/group '%s', using default.\n", name_buf);
      linkset = this_host->default_linkset;
    }
  }
  lock_global();

  first_cic = linkset->first_cic;
  last_cic = linkset->last_cic;
  if(sep && cic_sep) {
    /* use specific cics */
    char cics[100];
    char *cics_sep;
    char first_cic_dig[10], last_cic_dig[10];

    strncpy(cics, cic_sep + 1, sep-cic_sep-1);
    cics[sep-cic_sep-1] = '\0';

    cics_sep = strchr(cics, '-');

    if(cics_sep != NULL) {
      int n;
      strncpy(first_cic_dig, cics, cics_sep-cics);
      strncpy(last_cic_dig, cics_sep + 1, strlen(cics) - (cics_sep-cics) - 1);

      first_cic_dig[cics_sep-cics] = '\0';
      last_cic_dig[strlen(cics) - (cics_sep-cics) - 1] = '\0';
      n = atoi(first_cic_dig);
      if (n != 0)
	first_cic = n;
      else
	ast_log(LOG_ERROR, "SS7 requester: Invalic CIC number '%s' in range, ignoring.\n", first_cic_dig);
      n = atoi(last_cic_dig);
      if (n != 0)
	last_cic = n;
      else
	ast_log(LOG_ERROR, "SS7 requester: Invalic CIC number '%s' in range, ignoring.\n", last_cic_dig);
    }
    else {
      int cic = atoi(cics);
      if (cic != 0) {
	first_cic = cic;
	last_cic = cic;
      }
      else
	ast_log(LOG_ERROR, "SS7 requester: Invalic CIC number '%s', ignoring.\n", cics);
    }
  }
  pvt = cic_hunt(linkset, first_cic, last_cic);

  if(pvt == NULL) {
    unlock_global();
    *cause = AST_CAUSE_CONGESTION;
    ast_log(LOG_WARNING, "SS7 requester: No idle circuit available, linkset=%s.\n", linkset->name);
    return NULL;
  }

  ast_mutex_lock(&pvt->lock);

  chan = ss7_new(pvt, AST_STATE_DOWN, NULL, sep ? sep+1 : arg);
  if(!chan) {
    ast_mutex_unlock(&pvt->lock);
    unlock_global();
    *cause = AST_CAUSE_CONGESTION;
    ast_log(LOG_WARNING, "Unable to allocate SS7 channel structure.\n");
    return NULL;
  }

  ast_mutex_unlock(&pvt->lock);
  unlock_global();

  ast_update_use_count();

  ast_log(LOG_DEBUG, "SS7 channel %s/%s allocated successfully.\n", type, arg);
  return chan;
}

static int ss7_send_digit_begin(struct ast_channel *chan, char digit) {
  struct ss7_chan *pvt = chan->tech_pvt;

  ast_mutex_lock(&pvt->lock);
  if (!io_send_dtmf(pvt->zaptel_fd, pvt->cic, digit))
    pvt->sending_dtmf = 1;
  ast_mutex_unlock(&pvt->lock);

  return 0;
}

static int ss7_send_digit_end(struct ast_channel *chan, char digit, unsigned int duration) {
  return 0;
}


static void ss7_send_call_progress(struct ss7_chan *pvt, int value) {
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  unsigned char param[1];
  unsigned char param_backward_ind[2];
  unsigned char param_opt_backw_ind[1];

  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), pvt->cic, ISUP_CPR, &current);
  param[0] = value;              /* Event information */
  param_backward_ind[0] = 0x16;  /* Charge, subscriber free, ordinary subscriber, no end-to-end */
  param_backward_ind[1] = 0x14;  /* No interworking, no end-to-end, ISDN all the way, no
                                    hold, terminating access ISDN, no echo control */
  param_opt_backw_ind[0] = 0x01;
  isup_msg_add_fixed(msg, sizeof(msg), &current, param, 1);
  isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 0, 1);
  isup_msg_start_optional_part(msg, sizeof(msg), &varptr, &current);
  isup_msg_add_optional(msg, sizeof(msg), &current, IP_BACKWARD_CALL_INDICATORS,
			param_backward_ind, 2);
  isup_msg_add_optional(msg, sizeof(msg), &current, IP_OPTIONAL_BACKWARD_CALL_INDICATORS,
			param_opt_backw_ind, 1);
  isup_msg_end_optional_part(msg, sizeof(msg), &current);
  mtp_enqueue_isup(pvt, msg, current);
}

#ifdef USE_ASTERISK_1_2
 static int ss7_indicate(struct ast_channel *chan, int condition) {
#else
static int ss7_indicate(struct ast_channel *chan, int condition, const void* data, size_t datalen) {
#endif
  struct ss7_chan *pvt = chan->tech_pvt;
  int res;

  ast_mutex_lock(&pvt->lock);

  ast_log(LOG_DEBUG, "SS7 indicate CIC=%d.\n", pvt->cic);
  switch(condition) {
  case AST_CONTROL_RINGING:
    ast_log(LOG_DEBUG, "Sending ALERTING call progress for CIC=%d in-band ind=%d.\n",
	    pvt->cic, pvt->has_inband_ind);
    ss7_send_call_progress(pvt, 0x01);
    ast_setstate(chan, AST_STATE_RINGING);
    res = !pvt->has_inband_ind && !pvt->is_digital; /* If there is no indication of in-band information, tell asterisk to generate ringing indication tone */
    break;

  case AST_CONTROL_PROGRESS:
    ast_log(LOG_DEBUG, "Sending in-band information available call progress for CIC=%d..\n",
	    pvt->cic);
    ss7_send_call_progress(pvt, 0x03);
    ast_playtones_stop(chan);
    res = 0;
    break;
#ifdef USE_ASTERISK_1_6
  case AST_CONTROL_T38_PARAMETERS:
    /* Signal back that T38 is not supported, otherwise the bridged channel has to wait until a timeout     */
    res = -1;
    break;
#endif
  default:
    /* Not supported. */
    res = !pvt->has_inband_ind && !pvt->is_digital; /* If there is no indication of in-band information, tell asterisk to generate ringing indication tone */
  }

  ast_mutex_unlock(&pvt->lock);
  if (!res)
    ast_log(LOG_DEBUG, "Generating in-band indication tones for CIC=%d, condition=%d.\n", pvt->cic, condition);

  return res;
}

static int t1_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  ast_log(LOG_NOTICE, "T1 timeout (waiting for RLC) CIC=%d.\n", pvt->cic);
  isup_send_rel(pvt, pvt->hangupcause);
  return 1;                     /* Run us again the next period */
}

/* This should be called with pvt->lock held. */
static void t1_clear(struct ss7_chan *pvt) {
  if(pvt->t1 != -1) {
    stop_timer(pvt->t1);
    pvt->t1 = -1;
  }
}

/* This should be called with pvt->lock held. */
static void t1_start(struct ss7_chan *pvt) {
  t1_clear(pvt);
  pvt->t1 = start_timer(30000, t1_timeout, pvt);
}

static int t2_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;
  struct ast_channel *chan = pvt->owner;

  ast_log(LOG_NOTICE, "T2 timeout (waiting for RES, user) CIC=%d.\n", pvt->cic);
  request_hangup(chan, AST_CAUSE_NORMAL_CLEARING); /* Q.764 2.4.3 and Annex A */
  pvt->t2 = -1;
  return 0;                     /* Remove us from sched */
}

/* This should be called with pvt->lock held. */
static void t2_clear(struct ss7_chan *pvt) {
  if(pvt->t2 != -1) {
    stop_timer(pvt->t2);
    pvt->t2 = -1;
  }
}

/* This should be called with pvt->lock held. */
static void t2_start(struct ss7_chan *pvt) {
  t2_clear(pvt);
  pvt->t2 = start_timer(180000, t2_timeout, pvt);
}


/* This should be called with pvt->lock held. */
static void t5_clear(struct ss7_chan *pvt) {
  if(pvt->t5 != -1) {
    stop_timer(pvt->t5);
    pvt->t5 = -1;
  }
}

static int t5_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  /* For the long T5 timeout, alert maintenance, and switch to sending
     "reset circuit". */
  ast_log(LOG_WARNING, "T5 timeout (No \"release complete\" from peer) CIC=%d.\n", pvt->cic);
  t1_clear(pvt);
  isup_send_rsc(pvt);
  t17_start(pvt);
  pvt->t5 = -1;
  return 0;                     /* Remove us from sched */
}

/* This should be called with pvt->lock held. */
static void t5_start(struct ss7_chan *pvt) {
  t5_clear(pvt);
  pvt->t5 = start_timer(600000, t5_timeout, pvt);
}

static int t6_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;
  struct ast_channel *chan = pvt->owner;

  ast_log(LOG_NOTICE, "T6 timeout (waiting for RES, network) CIC=%d.\n", pvt->cic);
  request_hangup(chan, AST_CAUSE_RECOVERY_ON_TIMER_EXPIRE);
  pvt->t6 = -1;
  return 0;                     /* Remove us from sched */
}

/* This should be called with pvt->lock held. */
static void t6_clear(struct ss7_chan *pvt) {
  if(pvt->t6 != -1) {
    stop_timer(pvt->t6);
    pvt->t6 = -1;
  }
}

/* This should be called with pvt->lock held. */
static void t6_start(struct ss7_chan *pvt) {
  t6_clear(pvt);
  pvt->t6 = start_timer(60000, t6_timeout, pvt);
}

static int t7_timeout(const void *arg) {
  struct ast_channel *chan = (struct ast_channel*) arg;
  struct ss7_chan *pvt = chan->tech_pvt;

  ast_log(LOG_NOTICE, "T7 timeout (waiting for ACM or CON) CIC=%d.\n", pvt->cic);
  /* Q.764 2.4.3 */
  request_hangup(chan, AST_CAUSE_NORMAL_CLEARING);
  pvt->t7 = -1;
  /* asterisk sometimes fail to call ss7_hangup ... */
  return 0;                     /* Remove us from sched */
}

/* This should be called with pvt->lock held. */
static void t7_clear(struct ss7_chan *pvt) {
  if(pvt->t7 != -1) {
    stop_timer(pvt->t7);
    pvt->t7 = -1;
  }
}

/* This should be called with pvt->lock held. */
static void t7_start(struct ast_channel *chan) {
  struct ss7_chan *pvt = chan->tech_pvt;
  t7_clear(pvt);
  pvt->t7 = start_timer(25000, t7_timeout, chan);
}

static int t9_timeout(const void *arg) {
  struct ast_channel *chan = (struct ast_channel*) arg;
  struct ss7_chan *pvt = chan->tech_pvt;

  ast_log(LOG_NOTICE, "T9 timeout (waiting for ANM).\n");
  request_hangup(chan, AST_CAUSE_NETWORK_OUT_OF_ORDER);
  pvt->t9 = -1;
  return 0;                     /* Remove us from sched */
}

/* This should be called with pvt->lock held. */
static void t9_clear(struct ss7_chan *pvt) {
  if(pvt->t9 != -1) {
    stop_timer(pvt->t9);
    pvt->t9 = -1;
  }
}

/* This should be called with pvt->lock held. */
static void t9_start(struct ast_channel *chan) {
  struct ss7_chan *pvt = chan->tech_pvt;
  t9_clear(pvt);
  pvt->t9 = start_timer(90000, t9_timeout, chan);
}

static int t12_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  ast_log(LOG_NOTICE, "T12 timeout (waiting for BLA).\n");
  isup_send_blk(pvt);
  return 1;                     /* Run us again the next period */
}

/* This should be called with pvt->lock held. */
static void t12_clear(struct ss7_chan *pvt) {
  if(pvt->t12 != -1) {
    stop_timer(pvt->t12);
    pvt->t12 = -1;
  }
}

/* This should be called with pvt->lock held. */
static void t12_start(struct ss7_chan *pvt) {
  t12_clear(pvt);
  pvt->t12 = start_timer(30000, t12_timeout, pvt);
}

static int t14_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  ast_log(LOG_NOTICE, "T14 timeout (waiting for UBA).\n");
  isup_send_ubl(pvt);
  return 1;                     /* Run us again the next period */
}

/* This should be called with pvt->lock held. */
static void t14_clear(struct ss7_chan *pvt) {
  if(pvt->t14 != -1) {
    stop_timer(pvt->t14);
    pvt->t14 = -1;
  }
}

/* This should be called with pvt->lock held. */
static void t14_start(struct ss7_chan *pvt) {

  t14_clear(pvt);
  pvt->t14 = start_timer(30000, t14_timeout, pvt);
}
 
/* This should be called with pvt->lock held. */
static void t16_clear(struct ss7_chan *pvt) {
  if(pvt->t16 != -1) {
    stop_timer(pvt->t16);
    pvt->t16 = -1;
  }
}

static int t16_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  /* For the long T16 timeout, alert maintenance, and switch to sending
     "reset circuit". */
  ast_log(LOG_WARNING, "T16 timeout (No \"release complete\" from peer) CIC=%d, sent RSC.\n", pvt->cic);
  isup_send_rsc(pvt);
  return 1;                     /* Run us again the next period */
}

/* This should be called with pvt->lock held. */
static void t16_start(struct ss7_chan *pvt) {
  t16_clear(pvt);
  pvt->t16 = start_timer(30000, t16_timeout, pvt);
}

/* This should be called with pvt->lock held. */
static void t17_clear(struct ss7_chan *pvt) {
  if(pvt->t17 != -1) {
    stop_timer(pvt->t17);
    pvt->t17 = -1;
  }
}

static int t17_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  /* For the long T17 timeout, alert maintenance, and switch to sending
     "reset circuit". */
  ast_log(LOG_WARNING, "T17 timeout (No \"release complete\" from peer) CIC=%d.\n", pvt->cic);
  isup_send_rsc(pvt);
  return 1;                     /* Run us again the next period */
}

/* This should be called with pvt->lock held. */
static void t17_start(struct ss7_chan *pvt) {
  t17_clear(pvt);
  pvt->t17 = start_timer(600000, t17_timeout, pvt);
}

/* This should be called with pvt->lock held. */
static void t18_clear(struct ss7_chan *pvt) {
  if(pvt->t18 != -1) {
    stop_timer(pvt->t18);
    pvt->t18 = -1;
  }
}

static int t18_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  /* For the long T18 timeout, alert maintenance, and switch to sending
     "reset circuit". */
  ast_log(LOG_WARNING, "T18 timeout (No \"circuit group blocking acknowledge\" from peer) CIC=%d.\n", pvt->cic);
  isup_send_cgb(pvt, pvt->cgb_mask);
  pvt->t18 = -1;
  t19_start(pvt);
  return 0;                     /* Remove us from sched */
}

/* This should be called with pvt->lock held. */
static void t18_start(struct ss7_chan *pvt) {
  t18_clear(pvt);
  pvt->t18 = start_timer(30000, t18_timeout, pvt);
}

/* This should be called with pvt->lock held. */
static void t19_clear(struct ss7_chan *pvt) {
  if(pvt->t19 != -1) {
    stop_timer(pvt->t19);
    pvt->t19 = -1;
  }
}

static int t19_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  /* For the long T19 timeout, alert maintenance, and switch to sending
     "reset circuit". */
  ast_log(LOG_WARNING, "T19 timeout (No \"circuit group blocking acknowledge\" from peer) CIC=%d.\n", pvt->cic);
  isup_send_cgb(pvt, pvt->cgb_mask);
  return 1;                     /* Run us again the next period */
}

/* This should be called with pvt->lock held. */
static void t19_start(struct ss7_chan *pvt) {
  t19_clear(pvt);
  pvt->t19 = start_timer(600000, t19_timeout, pvt);
}

/* This should be called with pvt->lock held. */
static void t20_clear(struct ss7_chan *pvt) {
  if(pvt->t20 != -1) {
    stop_timer(pvt->t20);
    pvt->t20 = -1;
  }
}

static int t20_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  /* For the long T20 timeout, alert maintenance, and switch to sending
     "reset circuit". */
  ast_log(LOG_WARNING, "T20 timeout (No \"circuit group unblocking acknowledge\" from peer) CIC=%d.\n", pvt->cic);
  isup_send_cgu(pvt, pvt->cgb_mask);
  pvt->t20 = -1;
  t21_start(pvt);
  return 0;                     /* Remove us from sched */
}

/* This should be called with pvt->lock held. */
static void t20_start(struct ss7_chan *pvt) {
  t20_clear(pvt);
  pvt->t20 = start_timer(30000, t20_timeout, pvt);
}

/* This should be called with pvt->lock held. */
static void t21_clear(struct ss7_chan *pvt) {
  if(pvt->t21 != -1) {
    stop_timer(pvt->t21);
    pvt->t21 = -1;
  }
}

static int t21_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  /* For the long T21 timeout, alert maintenance, and switch to sending
     "reset circuit". */
  ast_log(LOG_WARNING, "T21 timeout (No \"circuit group blocking acknowledge\" from peer) CIC=%d.\n", pvt->cic);
  isup_send_cgu(pvt, pvt->cgb_mask);
  return 1;                     /* Run us again the next period */
}

/* This should be called with pvt->lock held. */
static void t21_start(struct ss7_chan *pvt) {
  t21_clear(pvt);
  pvt->t21 = start_timer(600000, t21_timeout, pvt);
}

/* This should be called with pvt->lock held. */
static void t22_clear(struct ss7_chan *pvt) {
  if(pvt->t22 != -1) {
    stop_timer(pvt->t22);
    pvt->t22 = -1;
  }
}

static int t22_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  ast_log(LOG_NOTICE, "T22 timeout (No \"circuit group reset acknowledge\" from peer) CIC=%d.\n", pvt->cic);
  isup_send_grs(pvt, pvt->grs_count, 0);
  return 1;                     /* Run us again the next period */
}

/* This should be called with pvt->lock held. */
static void t22_start(struct ss7_chan *pvt) {
  t22_clear(pvt);
  pvt->t22 = start_timer(30000, t22_timeout, pvt);
}

/* This should be called with pvt->lock held. */
static void t23_clear(struct ss7_chan *pvt) {
  if(pvt->t23 != -1) {
    stop_timer(pvt->t23);
    pvt->t23 = -1;
  }
}

static int t23_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  /* For the long T23 timeout, alert maintenance using LOG_WARNING. */
  ast_log(LOG_WARNING, "T23 timeout (No \"circuit group reset acknowledge\" from peer) CIC=%d.\n", pvt->cic);
  t22_clear(pvt);
  isup_send_grs(pvt, pvt->grs_count, 0);
  return 1;                     /* Run us again the next period */
}

/* This should be called with pvt->lock held. */
static void t23_start(struct ss7_chan *pvt) {
  t23_clear(pvt);
  pvt->t23 = start_timer(10*60*1000, t23_timeout, pvt);
}

static int t35_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  pvt->t35 = -1;
  if (pvt->link->linkset->t35_action) {
    pvt->iam.dni.complete = 1;
    handle_complete_address(pvt);
    return 0;                     /* Remove us from sched */
  }
  ast_log(LOG_NOTICE, "T35 timeout (waiting for end-of-pulsing) CIC=%d.\n", pvt->cic);
  initiate_release_circuit(pvt, AST_CAUSE_INVALID_NUMBER_FORMAT);
  return 0;                     /* Remove us from sched */
}

/* This should be called with pvt->lock held. */
static void t35_clear(struct ss7_chan *pvt) {
  if(pvt->t35 != -1) {
    stop_timer(pvt->t35);
    pvt->t35 = -1;
  }
}

/* This should be called with pvt->lock held. */
static void t35_start(struct ss7_chan* pvt)
{
  t35_clear(pvt);
  pvt->t35 = start_timer(pvt->link->linkset->t35_value, t35_timeout, pvt);
}

static int t36_timeout(const void *arg) {
  struct ss7_chan *pvt = (struct ss7_chan*) arg;

  ast_log(LOG_NOTICE, "T36 timeout (waiting for COT or REL) CIC=%d.\n", pvt->cic);
  initiate_release_circuit(pvt, AST_CAUSE_NORMAL_TEMPORARY_FAILURE);
  ast_mutex_lock(&continuity_check_lock);
  continuity_check_changes = 1;
  ast_mutex_unlock(&continuity_check_lock);
  pvt->t36 = -1;
  return 0;                     /* Remove us from sched */
}

/* This should be called with pvt->lock held. */
static void t36_clear(struct ss7_chan *pvt) {
  if(pvt->t36 != -1) {
    stop_timer(pvt->t36);
    pvt->t36 = -1;
  }
}

/* This should be called with pvt->lock held. */
static void t36_start(struct ss7_chan* pvt)
{
  t36_clear(pvt);
  pvt->t36 = start_timer(12000, t36_timeout, pvt);
}

static void isup_send_grs(struct ss7_chan *pvt, int count, int do_timers) {
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  unsigned char param[1];

  if(pvt == NULL) {
    ast_log(LOG_NOTICE, "Error: NULL pvt passed in?!?.\n");
    return;
  }
  if(count < 2) {
    ast_log(LOG_NOTICE, "Error (CIC=%d), cannot send group reset for %d "
            "circuits (need at least 2).\n", pvt->cic, count);
    return;
  }
  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), pvt->cic, ISUP_GRS, &current);
  isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 1, 0);
  param[0] = count - 1;
  isup_msg_add_variable(msg, sizeof(msg), &varptr, &current, param, 1);
  mtp_enqueue_isup(pvt, msg, current);

  if(do_timers) {
    t22_start(pvt);
    t23_start(pvt);
  }
}

/* At startup, send an initial GRS to reset all circuits, and setup a timer
   to wait for the ack. */
static void send_init_grs(struct linkset* linkset) {
  int i;
  int first_equipped;           /* Left end of a range in CIC scan. */
  int range;

  ast_log(LOG_DEBUG, "Sending GROUP RESET messages on linkset '%s'.\n", linkset->name);

  lock_global();

  if (linkset->grs) {
    /* Send a GRS for each continuous range of circuits. */
    first_equipped = -1;
    for(i = linkset->first_cic; i <= linkset->last_cic; i++) {
      if(linkset->cic_list[i] && linkset->cic_list[i]->equipped) {
	/* Clear the blocked status for the circuits; any remote blocking will be
	   reported by the peer. */
	linkset->cic_list[i]->blocked = linkset->blocked[i];
	/* Look for the start of a range. */
	if(first_equipped == -1) {
	  first_equipped = i;
	}
      }

      /* Look for the end of a range. */
      if(first_equipped != -1 &&
	 (i == linkset->last_cic || !(linkset->cic_list[i+1] && linkset->cic_list[i+1]->equipped) || first_equipped + 31 == i)) {
	range = i - first_equipped;
	if(range == 0) {
	  struct ss7_chan *pvt = linkset->cic_list[first_equipped];
	  ast_mutex_lock(&pvt->lock);
	  pvt->state = ST_SENT_REL;
	  isup_send_rsc(pvt); 
	  t16_start(pvt);
	  ast_mutex_unlock(&pvt->lock);
	  first_equipped = -1;
	} else {
	  linkset->cic_list[first_equipped]->grs_count = range + 1;
	  isup_send_grs(linkset->cic_list[first_equipped], range + 1, 1);
	}
	ast_log(LOG_DEBUG, "Group reset first %d, range %d \n", first_equipped, range);
	first_equipped = -1;
      }
    }
  }
  else {
    for(i = linkset->first_cic; i <= linkset->last_cic; i++) {
      if(linkset->cic_list[i] && linkset->cic_list[i]->equipped) {
        /* Clear the blocked status for the circuits; any remote blocking will be
           reported by the peer. */
	struct ss7_chan *pvt = linkset->cic_list[i];
	ast_mutex_lock(&pvt->lock);
        linkset->cic_list[i]->blocked = linkset->blocked[i];
	pvt->state = ST_SENT_REL;
	reset_circuit(pvt);
	ast_mutex_unlock(&pvt->lock);
      }
    }
  }

  unlock_global();

  /* When the reset acknowledge arrives, the pvt->reset_done is set true for
     all affected circuits. Until then, messages for that circuit are
     discarded. */
}

/* Release circuit after receiving GRS */
static void release_circuit(struct ss7_chan* pvt)
{
  struct ast_channel *chan = pvt->owner;
  if(chan != NULL) {
    ast_channel_lock(chan);
  }
  ast_mutex_lock(&pvt->lock);

  if(pvt->state != ST_IDLE) {
    pvt->state = ST_IDLE;
    if(chan != NULL) {
      request_hangup(chan, AST_CAUSE_NETWORK_OUT_OF_ORDER);
    } else {
      /* Channel already hung up */
    }
  }
  t1_clear(pvt);
  t2_clear(pvt);
  t5_clear(pvt);
  t6_clear(pvt);
  t7_clear(pvt);
  t9_clear(pvt);
  t16_clear(pvt);
  t17_clear(pvt);
  t18_clear(pvt);
  t19_clear(pvt);
  t20_clear(pvt);
  t21_clear(pvt);
  t35_clear(pvt);

  ast_mutex_unlock(&pvt->lock);
  if(chan != NULL) {
    ast_channel_unlock(chan);
  }
}

static void free_cic(struct ss7_chan* pvt)
{
  pvt->state = ST_IDLE;
  pvt->hangupcause = 0;
  pvt->dohangup = 0;
  pvt->has_inband_ind = 0;
  pvt->charge_indicator = 0;
  pvt->is_digital = 0;
  pvt->sending_dtmf = 0;
  pvt->owner = NULL;
  add_to_idlelist(pvt);
}

static void handle_complete_address(struct ss7_chan *pvt)
{
  int res;
  struct iam* iam = &pvt->iam;
  struct ast_channel *chan = ss7_new(pvt, AST_STATE_RING, iam->ani.present ? iam->ani.num : NULL, iam->dni.num);

  if(chan == NULL) {
    ast_log(LOG_WARNING, "Failed to allocate struct ast_channel * "
	    "for CIC=%d.\n", pvt->cic);
    /* Q.764 2.2 c) Initiate release procedure */
    initiate_release_circuit(pvt, AST_CAUSE_NORMAL_CLEARING);
    return;
  }

#ifdef USE_ASTERISK_1_2
  ast_copy_string(chan->exten, iam->dni.num, sizeof(chan->exten));
  ast_copy_string(chan->context, pvt->context, sizeof(chan->context));
  ast_copy_string(chan->language, pvt->language, sizeof(chan->language));
#else
  ast_string_field_set(chan, language, pvt->language);
#endif

#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  if(iam->ani.present) {
    chan->cid.cid_num = strdup(iam->ani.num);
    /* ToDo: Handle screening. */
    if(iam->ani.restricted) {
      chan->cid.cid_pres = AST_PRES_PROHIB_NETWORK_NUMBER;
    } else {
      chan->cid.cid_pres = AST_PRES_ALLOWED_NETWORK_NUMBER;
    }
  }
  if(iam->rni.present) {
    /* ToDo: implement redirection reason in Asterisk, and handle it here. */
    chan->cid.cid_rdnis = strdup(iam->rni.num);
  }
  chan->cid.cid_dnid = strdup(iam->dni.num);
#else
  if(iam->ani.present) {
    chan->connected.id.number.str = strdup(iam->ani.num);
    if(iam->ani.restricted) {
      chan->connected.id.name.presentation = AST_PRES_PROHIB_NETWORK_NUMBER;
      chan->connected.id.number.presentation = AST_PRES_PROHIB_NETWORK_NUMBER;
    } else {
      chan->connected.id.name.presentation = AST_PRES_ALLOWED_NETWORK_NUMBER;
      chan->connected.id.number.presentation = AST_PRES_ALLOWED_NETWORK_NUMBER;
    }
  }
  /* ToDo: Handle screening. */
  if(iam->rni.present) {
    /* ToDo: implement redirection reason in Asterisk, and handle it here. */
    chan->redirecting.from.number.str = strdup(iam->rni.num);
  }
#endif
  handle_redir_info(chan, &iam->redir_inf);
  if(iam->gni.ani.present)
    pbx_builtin_setvar_helper(chan, "__SS7_GENERIC_ANI", iam->gni.ani.num);
  if(iam->gni.dni.present)
    pbx_builtin_setvar_helper(chan, "__SS7_GENERIC_DNI", iam->gni.dni.num);
  if(iam->gni.rni.present)
    pbx_builtin_setvar_helper(chan, "__SS7_GENERIC_RNI", iam->gni.rni.num);
  if (iam->trans_medium) {
    char tmr[6];
    snprintf(tmr, sizeof(tmr), "0x%02x", iam->trans_medium);
    pbx_builtin_setvar_helper(chan, "__SS7_TMR", tmr);
  }

  if (!pvt->link->linkset->use_connect) {
    isup_send_acm(pvt);
    pvt->state = ST_SENT_ACM;
  }

  res = ast_pbx_start(chan);
  if(res != 0) {
    ast_log(LOG_WARNING, "Unable to start PBX for incoming call on CIC=%d.\n",
            pvt->cic);
    ast_hangup(chan);
  }
}

static void check_iam_sam(struct ss7_chan* pvt)
{
  int complete = (pvt->link->linkset->enable_st && pvt->iam.dni.complete) ||
    ast_exists_extension(pvt->owner, pvt->context, pvt->iam.dni.num, 1, pvt->iam.rni.num);
  if (complete) {
    pvt->iam.dni.complete = 1;
    ast_log(LOG_DEBUG, "Setting iam.dni.complete\n");
    handle_complete_address(pvt);
  } else {
    if (ast_canmatch_extension(pvt->owner, pvt->context, pvt->iam.dni.num, 1, pvt->iam.rni.num) != 0) {
      ast_log(LOG_DEBUG, "Processing addr %s, incomplete, starting T35\n", pvt->iam.dni.num);
      t35_start(pvt);
    }
    else {
      ast_log(LOG_DEBUG, "Unable to match extension, context: %s, dni: %s, rni: %s\n", pvt->context, pvt->iam.dni.num, pvt->iam.rni.num);
      initiate_release_circuit(pvt, AST_CAUSE_UNALLOCATED);
    }
  }
}

static void check_obci(struct ss7_chan* pvt, int obci)
{
  struct ast_channel* chan = pvt->owner;

  if ((obci & 0x1) == 1) {
    if (!pvt->has_inband_ind) {
      ast_log(LOG_DEBUG, "Got optional backward call indicator, queueing PROGRESS (Inband-information available) indication for Asterisk, CIC=%d.\n", pvt->cic);
      ast_queue_control(chan, AST_CONTROL_PROGRESS);
      pvt->has_inband_ind = 1;
    }
  }
}

static int isup_phonenum_check(char **number, int *nlen,
                               int *is_international) {
  if(*number == NULL) {
    ast_log(LOG_DEBUG, "NULL phonenumber, encoding failed.\n");
    return -1;
  }
  *nlen = strlen(*number);
  if(*nlen == 0) {
    ast_log(LOG_DEBUG, "Empty phonenumber, encoding failed.\n");
    return -1;
  }

  /* Handle both '00' and '+' as international prefix. */
  if((strncmp(*number, "00", 2) == 0) && (*nlen == 3) ) {
    /* pass through russian special numbers like 001,002,003 etc */
    *is_international = 0;
  } else if(strncmp(*number, "00", 2) == 0) {
    *is_international = 1;
    *number += 2;
    *nlen -= 2;
  } else if(strncmp(*number, "+", 1) == 0) {
    *is_international = 1;
    *number += 1;
    *nlen -= 1;
  } else {
    *is_international = 0;
  }

  return 0;                     /* Success */
}

static int isup_phonenum_digits(char *number, int add_st,
				int nlen, unsigned char *param) {
  int i, d;

  for(i = 0; i <= nlen; i++) {
    if(i == nlen) {
      if(add_st) {
        d = 0xf;                /* Digit "ST", meaning "number complete" */
      } else {
        break;
      }
    } else {
      if ((number[i] >= '0') && (number[i] <= '9'))
	d = number[i] - '0';
      else if ((number[i] == 'b') || (number[i] == 'B'))
	d = 0x0b;
      else if ((number[i] == 'c') || (number[i] == 'C'))
	d = 0x0c;
      else if ((number[i] == 'e') || (number[i] == 'E'))
	d = 0x0e;
      else {
	ast_log(LOG_DEBUG, "Invalid digit '%c' in phonenumber.\n", number[i]);
	return -1;
      }
    }
    if((i % 2) == 0) {
      param[2 + i/2] = d;
    } else {
      param[2 + (i - 1)/2] |= d << 4;
    }
  }

  return 0;
}

/* Encode a phone number in ISUP "Called Party Number" format. (Q.763 (3.9))
   Returns encoded length on success, -1 on error. */
int isup_called_party_num_encode(struct ss7_chan *pvt, char *number, unsigned char *param,
				 int plen) {
  int nlen;
  int is_odd;
  int is_international;
  int result_len;

  if(isup_phonenum_check(&number, &nlen, &is_international) == -1) {
    return -1;
  }

  /* We terminate the number with ST to signify that the number is complete
     (no overlapped dialing). Hence length is one more than nlen. */
  is_odd = (nlen + 1) % 2;
  /* Need room for two header bytes + all of the (nlen + 1) digits. */
  result_len = 2 + (nlen + 2)/2;
  if(result_len > plen) {
    ast_log(LOG_DEBUG, "Phonenumber too large to fit in parameter, "
            "len %d < %d.\n", plen, result_len);
    return -1;
  }

  param[0] = (is_odd << 7);
  if (pvt->link->linkset->noa != -1)
    param[0] |= (pvt->link->linkset->noa & 0x7f);
  else
    param[0] |= (is_international ? 4 : 3);
  param[1] = 0x10; /* Internal routing allowed, ISDN number plan */

  if(isup_phonenum_digits(number, 1, nlen, param) == -1) {
    return -1;
  }
  return result_len;            /* Success */
}

/* Encode a phone number in ISUP "Called Party Number" format. (Q.763 (3.9))
   Returns encoded length on success, -1 on error. */
int isup_called_party_num_encode_no_st(struct ss7_chan *pvt, char *number, unsigned char *param,
				       int plen) {
  int nlen;
  int is_odd;
  int is_international;
  int result_len;

  if(isup_phonenum_check(&number, &nlen, &is_international) == -1) {
    return -1;
  }

  /* We do not termminate the number with ST to signify that the number is incomplete
     (overlapped dialing). */
  is_odd = (nlen) % 2;
  /* Need room for two header bytes + all of the (nlen) digits. */
  result_len = 2 + (nlen + 1)/2;
  if(result_len > plen) {
    ast_log(LOG_DEBUG, "Phonenumber too large to fit in parameter, "
            "len %d < %d.\n", plen, result_len);
    return -1;
  }

  param[0] = (is_odd << 7);
  if (pvt->link->linkset->noa != -1)
    param[0] |= (pvt->link->linkset->noa & 0x7f);
  else
    param[0] |= (is_international ? 4 : 3);
  param[1] = 0x10; /* Internal routing allowed, ISDN number plan */

  if(isup_phonenum_digits(number, 0, nlen, param) == -1) {
    return -1;
  }
  return result_len;            /* Success */
}

/* Encode a phone number in ISUP "Calling Party Number" format. (Q.763 (3.10))
   Returns encoded length on success, -1 on error. */
int isup_calling_party_num_encode(char *number, int pres_restr, int si, unsigned char *param, int plen)
{
  int nlen;
  int is_odd;
  int is_international;
  int result_len;

  if(isup_phonenum_check(&number, &nlen, &is_international) == -1) {
    return -1;
  }

  is_odd = nlen % 2;
  /* Need room for two header bytes + all of the nlen digits. */
  result_len = 2 + (nlen + 1)/2;
  if(result_len > plen) {
    ast_log(LOG_DEBUG, "Phonenumber too large to fit in parameter, "
            "len %d < %d.\n", plen, result_len);
    return -1;
  }

  param[0] = (is_odd << 7) | (is_international ? 4 : 3);
  param[1] = 0x10 | si; /* Number complete; ISDN number plan; + screening indicator */
  if(pres_restr) {
    param[1] |= (0x1 << 2);
  }

  if(isup_phonenum_digits(number, 0, nlen, param) == -1) {
    return -1;
  }
  return result_len;            /* Success */
}

static int isup_send_sam(struct ss7_chan *pvt, char* addr, int complete)
{
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  unsigned char param[2 + PHONENUM_MAX];
  int res;

  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), pvt->cic, ISUP_SAM, &current);
  if (complete)
    res = isup_called_party_num_encode(pvt, addr, param, sizeof(param));
  else
    res = isup_called_party_num_encode_no_st(pvt, addr, param, sizeof(param));
  isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 1, 0);
  /* Param index 1 not used with SAM, change it */
  param[1] = param[0]; res--;
  isup_msg_add_variable(msg, sizeof(msg), &varptr, &current, &param[1], res);
  isup_msg_start_optional_part(msg, sizeof(msg), &varptr, &current);
  isup_msg_end_optional_part(msg, sizeof(msg), &current);

  mtp_enqueue_isup(pvt, msg, current);

  return 0;
}


static int isup_send_iam(struct ast_channel *chan, char *addr, char *rdni, char *dni, int dnilimit) {
  struct ss7_chan *pvt = chan->tech_pvt;
  unsigned char msg[MTP_MAX_PCK_SIZE];
  unsigned char param[2 + PHONENUM_MAX];
  int current, varptr;
  char dnicpy[100]; 
  int pres_restr;
  int res;
  const char *isdn_h324m;
  int h324m_usi=0, h324m_llc=0;
  const char *strp;

  isdn_h324m = pbx_builtin_getvar_helper(chan, "ISDN_H324M");
  if (isdn_h324m) {
    ast_verbose(VERBOSE_PREFIX_3 "chan_ss7: isup_send_iam: ISDN_H324M=%s\n", isdn_h324m);
    if (strstr(isdn_h324m,"USI")) {
      h324m_usi = 1;
    } 
    if (strstr(isdn_h324m,"LLC")) {
      h324m_llc = 1;
    }
    ast_log(LOG_DEBUG, "chan_ss7: isup_send_iam: h324m_usi=%d, h324m_llc=%d\n", h324m_usi, h324m_llc);
  }

  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), pvt->cic, ISUP_IAM, &current);

  /* Nature of connection indicators Q.763 (3.35). */
  param[0] = 0x00; /* No sattelite, no continuity check, no echo control */
  isup_msg_add_fixed(msg, sizeof(msg), &current, param, 1);

  /* Forward call indicator Q.763 (3.23). */
  if (h324m_usi || h324m_llc) {
    param[0] = 0xA0; /* No end-to-end method , no interworking, no end-to-end
                        info, ISDN all the way, ISDN required */
  } else {
    param[0] = 0x60; /* No end-to-end method , no interworking, no end-to-end
                        info, ISDN all the way, ISDN not required */
  }
  param[1] = 0x01; /* Originating access ISDN, no SCCP indication */
  isup_msg_add_fixed(msg, sizeof(msg), &current, param, 2);

  /* Calling party's category Q.763 (3.11). */
  param[0] = 0x0a; /* Ordinary calling subscriber */
  isup_msg_add_fixed(msg, sizeof(msg), &current, param, 1);

  if (variant(pvt) == ANSI_SS7) {
    isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 2, 1);
    /* Some switches do not understand H.223. Those switches use Access Transport
     * (Low Layer Compatibility) to signal the video call end-to-end.
     */
    if (h324m_usi) {
      /* User Service Information: Q.763 3.57 */
      param[0] = 0x88; /* unrestricted digital information */
      param[1] = 0x90; /* circuit mode, 64 kbit */
      param[2] = 0xA6; /* UL1, H.223 and H.245 */
      isup_msg_add_variable(msg, sizeof(msg), &varptr, &current, param, 3);
    }
    else {
      /* User Service Information. */
      param[0] = 0x90; /* Last octet, ITU-T standardized coding */
      param[1] = 0x90; /* Last octet, Circuit mode, 64 kbit/s */
      param[2] = 0xa2; /* Last octet, UL1, G.711 u-law */
      isup_msg_add_variable(msg, sizeof(msg), &varptr, &current, param, 3);
    }
  }
  else {
    /* Transmission medium requirement Q.763 (3.54). */
    strp = pbx_builtin_getvar_helper(chan, "SS7_TMR");
    if (strp) {
      /* Get transmission media value and make sure it is legal */
      char *endptr;
      unsigned long val = strtoul(strp, &endptr, 0);
      if ((strp == endptr) || val < 0 || val > 255) {
	ast_log(LOG_NOTICE, "Invalid transmedium requirement value '%ld' in SS7_TMR variable.\n", val);
	param[0] = 0x00;
      } else
	param[0] = (unsigned char) val;
    }
    else if (h324m_usi || h324m_llc) {
      param[0] = 0x02; /* 64 kbit/s unrestricted */
      pvt->is_digital = 1;
    } else {
      param[0] = 0x00; /* Speech */
    }
    isup_msg_add_fixed(msg, sizeof(msg), &current, param, 1);
    isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 1, 1);
  }

  /* Called party number Q.763 (3.9). */
  if (dnilimit > 0 && strlen(dni) > dnilimit) {
    /* Make part of dni */
    strncpy(dnicpy, dni, dnilimit);
    dnicpy[dnilimit] = '\0';
    res = isup_called_party_num_encode_no_st(pvt, dnicpy, param, sizeof(param));
  } else {
    res = isup_called_party_num_encode(pvt, dni, param, sizeof(param));
  }

  if(res < 0) {
    ast_log(LOG_NOTICE, "Invalid format for phonenumber '%s'.\n", dni);
    request_hangup(chan, AST_CAUSE_INVALID_NUMBER_FORMAT);
    ast_mutex_unlock(&pvt->lock);
    return -1;
  }
  isup_msg_add_variable(msg, sizeof(msg), &varptr, &current, param, res);

  isup_msg_start_optional_part(msg, sizeof(msg), &varptr, &current);

  /* Calling partys number Q.763 (3.10). */
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  if((chan->cid.cid_pres & AST_PRES_RESTRICTION) == AST_PRES_RESTRICTED) {
    pres_restr = 1;
  } else {
    pres_restr = 0;
  }
  res = isup_calling_party_num_encode(chan->cid.cid_num, pres_restr, 0x3 /* network provided */, param, sizeof(param));
#else
  if((chan->connected.id.number.presentation & AST_PRES_RESTRICTION) == AST_PRES_RESTRICTED) {
    pres_restr = 1;
  } else {
    pres_restr = 0;
  }
  res = isup_calling_party_num_encode(chan->connected.id.number.str, pres_restr, 0x3 /* network provided */, param, sizeof(param));
#endif
  if(res < 0) {
    ast_log(LOG_DEBUG, "Invalid format for calling number, dropped.\n");
  } else {
    isup_msg_add_optional(msg, sizeof(msg), &current, IP_CALLING_PARTY_NUMBER,
                          param, res);
  }

  /* Some switches do not understand H.223. Those switches use Access Transport
   * (Low Layer Compatibility) to signal the video call end-to-end.
   */
  if (h324m_usi) {
    /* User Service Information: Q.763 3.57 */
    param[0] = 0x88; /* unrestricted digital information */
    param[1] = 0x90; /* circuit mode, 64 kbit */
    param[2] = 0xA6; /* UL1, H.223 and H.245 */
    isup_msg_add_optional(msg, sizeof(msg), &current, IP_USER_SERVICE_INFORMATION,
                          param, 3);
  }
  if (h324m_llc) {
    /* Access Transport Q.763 3.3 */
    param[0] = 0x7C; /* unrestricted digital information */
    param[1] = 0x03; /* circuit mode, 64 kbit */
    param[2] = 0x88; /* UL1, H.223 and H.245 */
    param[3] = 0x90; /* UL1, H.223 and H.245 */
    param[4] = 0xA6; /* UL1, H.223 and H.245 */
    isup_msg_add_optional(msg, sizeof(msg), &current, IP_ACCESS_TRANSPORT,
                          param, 5);
  }

  if (*rdni) {
    char* redir  = chan ? (char*) pbx_builtin_getvar_helper(chan, "SS7_REDIR") : NULL;
    /* Default values: reason "unconditional", count "1" */
    unsigned char reason = 0x03, rcount = 1;
    /* Q.763 3.45 */
    res = isup_calling_party_num_encode(rdni, pres_restr, 0 /* national use: user provided, not verified */, param, sizeof(param));
    isup_msg_add_optional(msg, sizeof(msg), &current, IP_REDIRECTING_NUMBER, param, res);
    isup_msg_add_optional(msg, sizeof(msg), &current, IP_ORIGINAL_CALLED_NUMBER, param, res);
    param[0] = 0x04; /* redirecting indicator: call diverted, all redirection information presentation restricted,
			original redirection reason: unknown */
    if (redir)
      param[0] = atoi(redir);
    /* Read PRIREDRECTREASON and use it to set redirection reason (see ITU-T Q.763 3.44) */
    strp = pbx_builtin_getvar_helper(chan, "PRIREDIRECTREASON");
    if (strp) {
      /* Parse string value */
      reason = str2redirectreason(strp);
    }
    /* Read SS7_REDIRECTCOUNT and use it to set redirection counter (see ITU-T Q.763 3.44) */
    strp = pbx_builtin_getvar_helper(chan, "SS7_REDIRECTCOUNT");
    if (strp) {
      char *endptr;
      unsigned long val = strtoul(strp, &endptr, 0);
      if ((strp == endptr) || val < 0 || val > 7)
        ast_log(LOG_NOTICE, "Invalid redirection count value '%ld' "
                            "in SS7_REDRECTCOUNT variable.\n", val);
      else
        rcount = val;
    }
    param[1] = ((reason & 0x0F) << 4) | (rcount & 0x07);   /* redirecting reason, counter */
    isup_msg_add_optional(msg, sizeof(msg), &current, IP_REDIRECTION_INFORMATION, param, 2);
  }

  /* End and send the message. */
  isup_msg_end_optional_part(msg, sizeof(msg), &current);

  mtp_enqueue_isup(pvt, msg, current);

#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  ast_verbose(VERBOSE_PREFIX_3 "Sent IAM CIC=%-3d  ANI=%s DNI=%s RNI=%s\n", pvt->cic, pres_restr ? "*****" : chan->cid.cid_num, dni, rdni);
#else
  ast_verbose(VERBOSE_PREFIX_3 "Sent IAM CIC=%-3d  ANI=%s DNI=%s RNI=%s\n", pvt->cic,  pres_restr ? "*****" : chan->connected.id.number.str, dni, rdni);
#endif
  return 0;
}

/* Assume that we are called with chan->lock held (as ast_call() does). */
static int ss7_call(struct ast_channel *chan, char *addr, int timeout) {
  struct ss7_chan *pvt = chan->tech_pvt;
  char *sep = strchr(addr, '/');
  char rdni[100];
  char dnicpy[100];
  char dni[100];
  int chunk_limit, chunk_sofar=0;
  int res;

  ast_mutex_lock(&pvt->lock);

#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  ast_log(LOG_DEBUG, "SS7 call, addr=%s, cid=%s(0x%x/%s) CIC=%d. linkset '%s'\n",
          (addr ? addr : "<NULL>"),
          (chan->cid.cid_num ? chan->cid.cid_num : "<NULL>"),
          chan->cid.cid_pres,
          ast_describe_caller_presentation(chan->cid.cid_pres),
	  pvt->cic, pvt->link->linkset->name);
#else
  ast_log(LOG_DEBUG, "SS7 call, addr=%s, cid=%s(0x%x/%s) CIC=%d. linkset '%s'\n",
          (addr ? addr : "<NULL>"),
          (chan->connected.id.number.str ? chan->connected.id.number.str : "<NULL>"),
          chan->connected.id.number.presentation,
          ast_describe_caller_presentation(chan->connected.id.number.presentation),
	  pvt->cic, pvt->link->linkset->name);
#endif

  pvt->addr = addr;
  pvt->attempts = 1;

  if (sep)
    addr = sep+1;
  strcpy(dni, addr);
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  strcpy(rdni, chan->cid.cid_rdnis ? chan->cid.cid_rdnis : "");
#else
  strcpy(rdni, chan->redirecting.from.number.str ? chan->redirecting.from.number.str : "");
#endif
  sep = strchr(dni, ':');
  if (sep) {
    *sep = '\0';
    strcpy(rdni, sep+1);
  }

  chunk_limit = pvt->link->linkset->dni_chunk_limit;

  pvt->link->linkset->outgoing_calls++;
  res = isup_send_iam(chan, addr, rdni, dni, chunk_limit);
  if (res < 0) {
    ast_log(LOG_WARNING, "SS7 call failed, addr=%s CIC=%d. linkset '%s'\n", (addr ? addr : "<NULL>"), pvt->cic, pvt->link->linkset->name);
    free_cic(pvt);
    ast_mutex_unlock(&pvt->lock);
    return res;
  }

  if (chunk_limit > 0 && strlen(dni) > chunk_limit) {
    while(chunk_sofar < strlen(dni)) {
      strncpy(dnicpy, &dni[chunk_sofar], chunk_limit);
      chunk_sofar += chunk_limit;
      dnicpy[chunk_sofar] = '\0';
      isup_send_sam(pvt, dnicpy, 1);
    }
  }

  pvt->state = ST_SENT_IAM;

  t7_start(chan);

  ast_mutex_unlock(&pvt->lock);

  return 0;
}

static int ss7_hangup(struct ast_channel *chan) {
  struct ss7_chan *pvt = chan->tech_pvt;

  if (!pvt || pvt->cic == -1) {
    decr_usecount();
    ast_update_use_count();
    return 0;
  }
  ast_verbose( VERBOSE_PREFIX_3 "SS7 hangup '%s' CIC=%d Cause=%d (state=%d)\n",
               chan->name, pvt->cic, chan->hangupcause, pvt->state);

  /* Digium insists that ss7_hangup() must be called with chan->lock() held,
     even though it is the wrong thing to do (bug 5051). So we have to unlock
     it on entry and re-lock it on exit to get sane locking semantics. */
  ast_channel_unlock(chan);

  /* First remove us from the global circuit list. */
  lock_global();

  ast_mutex_lock(&pvt->lock);
  decr_usecount();


  ast_log(LOG_DEBUG, "SS7 hangup '%s' CIC=%d (state=%d), chan=0x%08lx\n",
	  chan->name, pvt->cic, pvt->state, (unsigned long) chan);

  /* Clear all the timers that may hold on to references to chan. This must be
     done while global lock is held to prevent races. */
  t1_clear(pvt);
  t2_clear(pvt);
  t5_clear(pvt);
  t6_clear(pvt);
  t7_clear(pvt);
  t9_clear(pvt);
  t16_clear(pvt);
  t17_clear(pvt);
  t18_clear(pvt);
  t19_clear(pvt);
  t20_clear(pvt);
  t21_clear(pvt);
  t35_clear(pvt);

  if(pvt->state == ST_GOT_REL) {
    isup_send_rlc(pvt);
    ast_setstate(chan, AST_STATE_DOWN);
    free_cic(pvt);
  }
  else if(pvt->state == ST_SENT_REL) {
    t1_start(pvt);
    t5_start(pvt);
  } else if(pvt->state != ST_IDLE) {
    ast_log(LOG_DEBUG, "SS7 hangup '%s' CIC=%d cause=%d\n", chan->name, pvt->cic, chan->hangupcause);
    initiate_release_circuit(pvt, chan->hangupcause);
  }

  if (pvt->echocancel) {
    io_disable_echo_cancellation(pvt->zaptel_fd, pvt->cic);
    pvt->echocancel = 0;
  }
  clear_audiomode(pvt->zaptel_fd);
  chan->tech_pvt = NULL;
  pvt->owner = NULL;

  ast_mutex_unlock(&pvt->lock);
  unlock_global();

  ast_update_use_count();

  ast_channel_lock(chan);  /* See above */

  return 0;
}

static int ss7_answer(struct ast_channel *chan) {
  struct ss7_chan *pvt = chan->tech_pvt;
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  unsigned char param[2];

  ast_mutex_lock(&pvt->lock);

  ast_log(LOG_DEBUG, "SS7 answer CIC=%d, pvt->state=%d.\n", pvt->cic, pvt->state);

  /* Send ANM instead of CON if previously sent ACM. */
  if (pvt->state == ST_SENT_ACM) {
    isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), pvt->cic, ISUP_ANM, &current);
    param[0] = 0x14;  /* Subscriber free, ordinary subscriber, no end-to-end */
    param[1] = 0x14;  /* No interworking, no end-to-end, ISDN all the way, no
			 hold, terminating access ISDN, no echo control */
    isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 0, 1);
    isup_msg_start_optional_part(msg, sizeof(msg), &varptr, &current);
    isup_msg_add_optional(msg, sizeof(msg), &current, IP_BACKWARD_CALL_INDICATORS, param, 2);
    isup_msg_end_optional_part(msg, sizeof(msg), &current);
    mtp_enqueue_isup(pvt, msg, current);
  } else if (pvt->state == ST_GOT_IAM) {
    isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), pvt->cic, ISUP_CON, &current);
    param[0] = 0x14;  /* Subscriber free, ordinary subscriber, no end-to-end */
    param[1] = 0x14;  /* No interworking, no end-to-end, ISDN all the way, no
			 hold, terminating access ISDN, no echo control */
    isup_msg_add_fixed(msg, sizeof(msg), &current, param, 2);
    isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 0, 1);
    mtp_enqueue_isup(pvt, msg, current);
  }
  /* else: already connected */
  pvt->state = ST_CONNECTED;
  ast_setstate(chan, AST_STATE_UP);

  set_audiomode(pvt->zaptel_fd);

  /* Start echo-cancelling if required */
  if (pvt->echocan_start) {
    if (!io_enable_echo_cancellation(pvt->zaptel_fd, pvt->cic, pvt->link->echocan_taps, pvt->link->echocan_train))
      pvt->echocancel = 1;
    pvt->echocan_start = 0;
  }

  ast_mutex_unlock(&pvt->lock);

  return 0;
}

static void ss7_handle_event(struct ss7_chan *pvt, int event) {
  int res, doing_dtmf;

#ifdef DAHDI_TONEDETECT
  if(event & DAHDI_EVENT_DTMFDOWN ) {
    pvt->frame.frametype = AST_FRAME_DTMF_BEGIN;
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
    pvt->frame.subclass = event & 0xff;
#else
    pvt->frame.subclass.integer = event & 0xff;
#endif
    return ;
       
  }
  if(event &  DAHDI_EVENT_DTMFUP ) {
    pvt->frame.frametype = AST_FRAME_DTMF_END;
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
    pvt->frame.subclass = event & 0xff;
#else
    pvt->frame.subclass.integer = event & 0xff;
#endif
    return;
		
  }
#endif
  switch(event) {
  case DAHDI_EVENT_DIALCOMPLETE:
    /* Chech if still doing DTMF sending. If not, set flag to start
       outputting audio again. */
    res = ioctl(pvt->zaptel_fd, DAHDI_DIALING, &doing_dtmf);
    if(res < 0) {
      ast_log(LOG_WARNING, "Error querying zaptel for DAHDI_DIALING on cic=%d: %s.\n",
	      pvt->cic, strerror(errno));
      /* Better start the audio, don't want to permanently disable it. */
      pvt->sending_dtmf = 0;
    } else if(!doing_dtmf) {
      /* Now we can start sending normal audio again. */
      pvt->sending_dtmf = 0;
    }
    break;

  default:
    ast_log(LOG_NOTICE, "Unhandled zaptel event 0x%x on CIC=%d.\n",
	    event, pvt->cic);
  }
}

static void get_dahdi_event(struct ss7_chan* pvt)
{
  int res, event;

  /* While these should really be handled in ss7_exception(), they can
     also occur here, probably because of a race between the zaptel
     driver and the channel poll() loop. */
  res = io_get_dahdi_event(pvt->zaptel_fd, &event);
  if(res < 0) {
    ast_mutex_unlock(&pvt->lock);
    ast_log(LOG_WARNING, "Error reading zaptel event for CIC=%d: %s.\n",
	    pvt->cic, strerror(errno));
    return;
  } else {
    ast_log(LOG_DEBUG, "Got event %d for CIC=%d, handling.\n",
	    event, pvt->cic);
    ss7_handle_event(pvt, event);
  }
}


/* ast_read() calls us with chan->lock held, so we assume that this is
   always the case. */
static struct ast_frame *ss7_read(struct ast_channel * chan) {
  struct ss7_chan *pvt = chan->tech_pvt;
  static struct ast_frame null_frame = { AST_FRAME_NULL };
  struct ast_frame *processed_frame;
  int res, sofar;

  if (pvt->dohangup) {
    chan->hangupcause = pvt->dohangup;
    return NULL;
  }
  ast_mutex_lock(&pvt->lock);

  memset(&pvt->frame, 0, sizeof(pvt->frame));
  pvt->frame.frametype = AST_FRAME_VOICE;
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  if (variant(pvt) == ANSI_SS7)
    pvt->frame.subclass = AST_FORMAT_ALAW;
  else
    pvt->frame.subclass = AST_FORMAT_ULAW;
#else
  if (variant(pvt) == ANSI_SS7)
    pvt->frame.subclass.codec = AST_FORMAT_ULAW;
  else
    pvt->frame.subclass.codec = AST_FORMAT_ALAW;
#endif
  pvt->frame.samples = AUDIO_READSIZE;
  pvt->frame.mallocd = 0;
  pvt->frame.src = NULL;
  AST_FRAME_SET_BUFFER(&pvt->frame, pvt->buffer, AST_FRIENDLY_OFFSET, AUDIO_READSIZE);

  memset(pvt->buffer, 0, sizeof(pvt->buffer));
  sofar = 0;
  while(sofar < AUDIO_READSIZE) {
    res = read(pvt->zaptel_fd, &(pvt->buffer[AST_FRIENDLY_OFFSET + sofar]),
               AUDIO_READSIZE - sofar);
    if(res < 0) {
      if(errno == EINTR) {
        /* Interrupted syscall, try again. */
      } else if(errno == EAGAIN || errno == EWOULDBLOCK) {
	static struct timeval lastreport = {0, 0};
	static int supress = 0;
	struct timeval now;
	gettimeofday(&now, NULL);
	if (now.tv_sec - lastreport.tv_sec > 10) {
	  ast_log(LOG_NOTICE, "Short read on linkset \"%s\" CIC=%d (read only %d of %d) errno=%d (%s) (supressed %d).\n",
		  pvt->link->linkset->name, pvt->cic, sofar, AUDIO_READSIZE, errno, strerror(errno), supress);
	  lastreport = now;
	  supress = 0;
	}
	else
	  supress++;
        break;
      } else if(errno == ELAST) {
	struct pollfd fds[1];
	get_dahdi_event(pvt);
	fds[0].fd = pvt->zaptel_fd;
	fds[0].events = POLLIN;
	/* we are trying to read data, wait up to 20 msec for next frame */
	res = poll(fds, 1, 20);
      } else {
        ast_mutex_unlock(&pvt->lock);
        ast_log(LOG_WARNING, "Read error on CIC=%d: %s.\n", pvt->cic, strerror(errno));
        return NULL;
      }
    } else if(res == 0) {
      ast_mutex_unlock(&pvt->lock);
      ast_log(LOG_WARNING, "EOF on zaptel device CIC=%d?!?\n", pvt->cic);
      return NULL;
    } else {
      sofar += res;
    }
  }

  if(sofar == 0) {
    ast_mutex_unlock(&pvt->lock);
    return &null_frame;
  }

#ifndef xxxxx
  {
    int msecs = sofar / 8;
    struct timeval now;
    static struct timeval lastreport = {0, 0};
    static int supress = 0;
    int tdiff;//xxx
    
    gettimeofday(&now, NULL);
    if (pvt->lastread.tv_sec) {
      tdiff = (now.tv_sec - pvt->lastread.tv_sec) * 1000000 + (now.tv_usec - pvt->lastread.tv_usec);
      if (tdiff/1000 > msecs + 100) {
	if (now.tv_sec - lastreport.tv_sec > 10) {
	  ast_log(LOG_NOTICE, "Audio buffer underrun, data %d msecs, real time: %d msecs! (supressed %d)\n", msecs, tdiff / 1000, supress);
	  lastreport = now;
	  supress = 0;
	}
	else
	  supress++;
      }
    }
    pvt->lastread = now;
  }
#endif
  pvt->frame.datalen = sofar;
  pvt->frame.samples = sofar;

   if(pvt->dsp){
	  	processed_frame = ast_dsp_process(chan, pvt->dsp, &pvt->frame);
   } else {
		/*Incase of HWDTF */
		processed_frame = &pvt->frame;
	}

  ast_mutex_unlock(&pvt->lock);

  return processed_frame;
}

static int ss7_write(struct ast_channel * chan, struct ast_frame *frame) {
  struct ss7_chan *pvt = chan->tech_pvt;
  int res, sofar, retry = 20;

  ast_mutex_lock(&pvt->lock);

#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  if((frame->frametype != AST_FRAME_VOICE) || ((frame->subclass != AST_FORMAT_ALAW) && (frame->subclass != AST_FORMAT_ULAW))) {
    ast_mutex_unlock(&pvt->lock);
    ast_log(LOG_WARNING, "Unexpected frame.\n");
    return -1;
  }
#else
  if((frame->frametype != AST_FRAME_VOICE) || ((frame->subclass.codec != AST_FORMAT_ALAW) && (frame->subclass.codec != AST_FORMAT_ULAW))) {
    ast_mutex_unlock(&pvt->lock);
    ast_log(LOG_WARNING, "Unexpected frame type=%d, subclass=%d.\n", frame->frametype, frame->subclass.integer);
    return -1;
  }
#endif

  if(pvt->sending_dtmf) {
    /* If we send audio while playing DTMF, the tone seems to be lost. */
    ast_mutex_unlock(&pvt->lock);
    return 0;
  }

  sofar = 0;
  while(sofar < frame->datalen) {
    res = write(pvt->zaptel_fd, FRAME_DATA(frame, sofar), frame->datalen - sofar);
    if(res > 0) {
      sofar += res;
    } else if(res == 0) {
      ast_mutex_unlock(&pvt->lock);
      ast_log(LOG_WARNING, "EOF on zaptel device CIC=%d?!?\n", pvt->cic);
      return -1;
    } else {
      if(errno == EINTR) {
        /* Interrupted syscall, try again. */
      } else if(errno == EAGAIN || errno == EWOULDBLOCK) {
	if (!adjust_buffers(pvt->zaptel_fd, pvt->cic)) {
	  static struct timeval lastreport = {0, 0};
	  static int supress = 0;
	  struct timeval now;
	  if (retry--) {
	    struct timespec delay = {0, 500};
	    nanosleep(&delay, NULL);
	    continue;
	  }
	  ast_mutex_unlock(&pvt->lock);
	  gettimeofday(&now, NULL);
	  if (now.tv_sec - lastreport.tv_sec > 10) {
	    ast_log(LOG_NOTICE, "Write buffer full on CIC=%d (wrote only %d of %d), audio lost (suppress %d).\n",
		    pvt->cic, sofar, frame->datalen, supress);
	    lastreport = now;
	    supress = 0;
	  }
	  else
	    supress++;
	  return 0;
	}
      } else if(errno == ELAST) {
	get_dahdi_event(pvt);
      } else {
        ast_mutex_unlock(&pvt->lock);
        ast_log(LOG_WARNING, "Write error on CIC=%d: %s.\n", pvt->cic, strerror(errno));
        return -1;
      }
    }
  }

  ast_mutex_unlock(&pvt->lock);

  return 0;
}

static struct ast_frame *ss7_exception(struct ast_channel *chan) {
  struct ss7_chan *pvt = chan->tech_pvt;
  int res, event;

  ast_mutex_lock(&pvt->lock);

  memset(&pvt->frame, 0, sizeof(pvt->frame));
  pvt->frame.frametype = AST_FRAME_NULL;
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  pvt->frame.subclass = 0;
#else
  pvt->frame.subclass.integer = 0;
#endif
  pvt->frame.samples = 0;
  pvt->frame.mallocd = 0;
  pvt->frame.src = NULL;
  AST_FRAME_SET_BUFFER(&pvt->frame, NULL, 0, 0);

  res = io_get_dahdi_event(pvt->zaptel_fd, &event);
  if(res < 0) {
    ast_log(LOG_WARNING, "Error reading zaptel event for CIC=%d: %s.\n",
            pvt->cic, strerror(errno));
  } else {
    ss7_handle_event(pvt, event);
  }

  ast_mutex_unlock(&pvt->lock);

  return &pvt->frame;
}

static int ss7_fixup(struct ast_channel *oldchan, struct ast_channel *newchan) {
{
  struct ss7_chan *pvt = newchan->tech_pvt;
  ast_mutex_lock(&pvt->lock);

  if (pvt->owner != oldchan) {
    ast_log(LOG_WARNING, "Old channel wasn't %p but was %p\n", oldchan, pvt->owner);
    ast_mutex_unlock(&pvt->lock);
    return -1;
  }
  pvt->owner = newchan;
  ast_mutex_unlock(&pvt->lock);
  return 0;
}

  ast_log(LOG_WARNING, "SS7 fixup not implemented.\n");
  return -1;
}

static void handle_GRS_send_hwblock(struct ss7_chan* ipvt, struct isup_msg *grs_msg) {
  struct linkset* linkset = ipvt->link->linkset;
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varpart;
  unsigned char param[34];
  int i, cic, mask, need_hw_block;
  int range;
  unsigned long cgb_mask = 0;

  if (!linkset->grs) {
    ast_log(LOG_WARNING, "Discarding GROUP RESET message, opc=0x%x, dpc=0x%x, cic=%d, range=%d, but group messages are disabled.\n", grs_msg->opc, grs_msg->dpc, grs_msg->cic, grs_msg->grs.range);
    return;
  }
  ast_log(LOG_NOTICE, "Got GROUP RESET message, opc=0x%x, dpc=0x%x, sls=0x%x, cic=%d, range=%d.\n", grs_msg->opc, grs_msg->dpc, grs_msg->sls, grs_msg->cic, grs_msg->grs.range);
  if(grs_msg->cic < 0 || grs_msg->cic + grs_msg->grs.range + 1 >= MAX_CIC) {
    ast_log(LOG_NOTICE, "Got unreasonable GRS with range %d-%d, discarding.\n",
            grs_msg->cic, grs_msg->cic + grs_msg->grs.range);
    return;
  }

  lock_global();

  /* First send hardware blocked, if required. */
  isup_msg_init(msg, sizeof(msg), variant(ipvt), peeropc(ipvt), grs_msg->opc, grs_msg->cic, ISUP_CGB, &current);
  param[0] = 0x01;              /* Hardware failure oriented */
  isup_msg_add_fixed(msg, sizeof(msg), &current, param, 1);
  isup_msg_start_variable_part(msg, sizeof(msg), &varpart, &current, 1, 0);
  i = 0;
  range = grs_msg->grs.range;
  if(range > 31) {
    unlock_global();
    ast_log(LOG_NOTICE, "Got unreasonable range %d in GRS message, "
            "discarding.\n", range);
    return;
  }
  param[i++] = range;
  memset(&param[i], 0, (range + 8) / 8);
  mask = 1;
  need_hw_block = 0;
  /* real range is range code + 1 (Q.763 (3.43)) */
  for(cic = grs_msg->cic; cic < grs_msg->cic + range + 1; cic++) {
    if(!linkset->cic_list[cic] || !linkset->cic_list[cic]->equipped) {
      /* Q.764 (2.9.3.3 iii): Discard GRS concerning unequipped CIC. */
      unlock_global();
      ast_log(LOG_NOTICE, "Got GRS concerning unequipped CIC %d, "
              "discarding.\n", cic);
      return;
    }
    if(linkset->cic_list[cic]->blocked & BL_LH) {
      /* Mark that circuit is locally maintenance blocked. */
      param[i] |= mask;
      need_hw_block = 1;
      cgb_mask = cgb_mask | (1 << (cic - grs_msg->cic));
    }
    mask <<= 1;
    if(mask == 0x100) {
      i++;
      mask = 1;
    }
  }
  /* Pad with zero bits up to an even number of bytes. */
  if(mask != 1) {
    i++;
  }
  /* Don't send an empty hardware blocking message. */
  if(need_hw_block) {
    struct ss7_chan *pvt = linkset->cic_list[grs_msg->cic];
    pvt->cgb_mask = cgb_mask;
    mtp_enqueue_isup(pvt, msg, current);
    ast_mutex_lock(&pvt->lock);
    t18_start(pvt);
    ast_mutex_unlock(&pvt->lock);
    ast_log(LOG_DEBUG, "Sending CIRCUIT GROUP BLOCKING before GRA, cic=%d\n",
	    pvt->cic);
  }

  /* Now send a GRA (group reset acknowledgement). */
  isup_msg_init(msg, sizeof(msg), variant(ipvt), peeropc(ipvt), grs_msg->opc, grs_msg->cic, ISUP_GRA, &current);
  isup_msg_start_variable_part(msg, sizeof(msg), &varpart, &current, 1, 0);
  i = 0;
  range = grs_msg->grs.range;
  param[i++] = range;
  memset(&param[i], 0, (range + 8) / 8);
  mask = 1;
  /* real range is range code + 1 (Q.763 (3.43)) */
  for(cic = grs_msg->cic; cic < grs_msg->cic + range + 1; cic++) {
    struct ss7_chan *pvt = linkset->cic_list[cic];
    if(!pvt || !pvt->equipped) {
      /* Q.764 (2.9.3.3 iii): Discard GRS concerning unequipped CIC. */
      unlock_global();
      ast_log(LOG_NOTICE, "Got GRS concerning unequipped CIC %d, "
              "discarding.\n", cic);
      return;
    }
    pvt->blocked &= ~(BL_RM|BL_RH|BL_UNEQUIPPED);
    if(pvt->blocked & BL_LM) {
      /* Mark that circuit is locally maintenance blocked. */
      param[i] |= mask;
    }
    mask <<= 1;
    if(mask == 0x100) {
      i++;
      mask = 1;
    }
  }
  /* Pad with zero bits up to an even number of bytes. */
  if(mask != 1) {
    i++;
  }

  /* Separate loop here, since according to Q.764 (2.9.3.3 iii), we must
     discard the message if it references unused CICs, hence we must check
     that _before_ releasing circuits. */
  for(cic = grs_msg->cic; cic < grs_msg->cic + range + 1; cic++) {
    struct ss7_chan *pvt = linkset->cic_list[cic]; /* Checked non-NULL in previous loop */
    struct ast_channel *chan = pvt->owner;
    if(chan) {
      ast_channel_lock(chan);
    }
    ast_mutex_lock(&pvt->lock);
    switch(pvt->state) {
    case ST_SENT_REL:
      t1_clear(pvt);
      t2_clear(pvt);
      t5_clear(pvt);
      t6_clear(pvt);
      t16_clear(pvt);
      t17_clear(pvt);
      t18_clear(pvt);
      /* Intentionally fall-through. */
    case ST_SENT_ACM:
      t35_clear(pvt);
      /* Intentionally fall-through. */
    case ST_GOT_REL:
      free_cic(pvt);
      /* Intentionally fall-through. */
    case ST_IDLE:
      break;

    default:
      if (pvt->state == ST_SENT_IAM) {
	reattempt_call(pvt);
      }
      else {
	request_hangup(chan, AST_CAUSE_NORMAL_TEMPORARY_FAILURE);
	free_cic(pvt);
      }
    }
    ast_mutex_unlock(&pvt->lock);
    if(chan) {
      ast_channel_unlock(chan);
    }
  }

  isup_msg_add_variable(msg, sizeof(msg), &varpart, &current, param, i);
  mtp_enqueue_isup(linkset->cic_list[grs_msg->cic], msg, current);

  unlock_global();
}

/* Send an "unequipped CIC" message. See Q.764 (2.12) and Q.763 table 39. */
static void isup_send_unequipped(struct link* slink, int cic, int dpc) {
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;

  isup_msg_init(msg, sizeof(msg), slink->linkset->variant, slink->linkset->opc, dpc, cic, ISUP_UEC, &current);
  isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 0, 0);
  mtp_enqueue_isup_packet(slink, cic, msg, current, MTP_REQ_ISUP);
}

/* Find the appropriate pvt structure of a CIC, and call the passed
   callback on it to handle an ISUP message.
   The Callback will be called with global lock, chan, and pvt locked (in this order).
   The pvt pointer is guaranteed to be non-NULL, but the chan pointer may be
   NULL, and the handler must work correctly in this case. */
static void process_circuit_message(struct link* slink,
				    struct isup_msg *inmsg,
				    void (*handler)(struct ss7_chan *, struct isup_msg *))
{
  int cic = inmsg->cic;
  struct ast_channel *chan;
  struct ss7_chan *pvt;

  /* Look for the CIC in the global channel list for an active channel.
     We lock the global lock to avoid races against ss7_hangup().
     We next lock chan->lock, if present, to avoid deadlock in ast_queue_frame().
     Finally we lock pvt->lock, to avoid races against dialplan threads (probably
     only needed when chan is NULL, but done always just for good measure).

     Unfortunately this means the entire ISUP layer may block on a single
     channel that is locked by another thread. To avoid this we might run a
     separate monitor thread for each circuit, however this is not likely to be
     a problem in practice. */
  if(cic < 0 || cic >= MAX_CIC) {
    ast_log(LOG_WARNING, "Received out-of-range CIC %d not within 0-%d, typ=%s.\n",
            cic, MAX_CIC - 1, isupmsg(inmsg->typ));
    return;
  }
  lock_global();
  pvt = find_pvt_with_pc(slink, cic, inmsg->opc);
  ast_log(LOG_DEBUG, "Process circuit message %s, CIC=%d, state=%d, reset_done=%d\n", isupmsg(inmsg->typ), cic, pvt->state, pvt->reset_done);
  if(!pvt->equipped) {
    ast_log(LOG_ERROR, "Received CIC=%d for not equipped circuit (typ=%s), link '%s'.\n", cic, isupmsg(inmsg->typ), slink->name);
    unlock_global();
    /* ToDo: According to Q.764 (2.12), we should send "Unequipped CIC" only in
       response to a specific list of message types. But don't know what else to
       do with an unequipped CIC, so for now we send the message in response to
       all messages with unequipped CIC. */
    if (inmsg->typ != ISUP_UEC)
      isup_send_unequipped(slink, cic, inmsg->opc);
    return;
  }
  if(!pvt->reset_done) {
    if ((inmsg->typ == ISUP_BLK) && (pvt->state == ST_SENT_REL)) {
      pvt->state = ST_IDLE;
      pvt->reset_done = 1;
      t16_clear(pvt);
    }
    else if ((inmsg->typ != ISUP_RSC) && (inmsg->typ != ISUP_BLK) && (inmsg->typ != ISUP_UBL)) {
      if ((pvt->state != ST_SENT_REL) || (inmsg->typ != ISUP_RLC)) {
	ast_log(LOG_WARNING, "Reset still in progress for CIC=%d, typ=%s, state=%d "
		"message discarded.\n", cic, isupmsg(inmsg->typ), pvt->state);
	unlock_global();
	return;
      }
    }
  }

  chan = pvt->owner;
  if(chan != NULL) {
    ast_channel_lock(chan);
  }
  ast_mutex_lock(&pvt->lock);

  /* Now that proper locking is done, call on to handle the actual message. */
  (*handler)(pvt, inmsg);

  ast_mutex_unlock(&pvt->lock);
  if(chan != NULL) {
    ast_channel_unlock(chan);
  }
  unlock_global();
}

/* Find the appropriate pvt structure of a CIC, and call the passed
   callback on it to handle an ISUP message.
   The Callback will be called with global lock, chan, and pvt locked (in this order).
   The pvt pointer is guaranteed to be non-NULL, but the chan pointer may be
   NULL, and the handler must work correctly in this case. */
static void process_circuit_group_message(struct link* slink,
					  struct isup_msg *inmsg,
					  void (*handler)(struct ss7_chan *, struct isup_msg *))
{
  int cic = inmsg->cic;
  struct ast_channel *chan;
  struct ss7_chan *pvt;

  /* Look for the CIC in the global channel list for an active channel.
     We lock the global lock to avoid races against ss7_hangup().
     We next lock chan->lock, if present, to avoid deadlock in ast_queue_frame().
     Finally we lock pvt->lock, to avoid races against dialplan threads (probably
     only needed when chan is NULL, but done always just for good measure).

     Unfortunately this means the entire ISUP layer may block on a single
     channel that is locked by another thread. To avoid this we might run a
     separate monitor thread for each circuit, however this is not likely to be
     a problem in practice. */
  if(cic < 0 || cic >= MAX_CIC) {
    ast_log(LOG_WARNING, "Received out-of-range CIC %d not within 0-%d, typ=%s.\n",
            cic, MAX_CIC - 1, isupmsg(inmsg->typ));
    return;
  }
  lock_global();
  pvt = find_pvt_with_pc(slink, cic, inmsg->opc);
  if(!(pvt->equipped || (inmsg->typ == ISUP_CGA) || (inmsg->typ == ISUP_CUA) || (inmsg->typ == ISUP_GRA))) {
    ast_log(LOG_ERROR, "Received CIC=%d for not equipped circuit (typ=%s), link '%s'.\n", cic, isupmsg(inmsg->typ), slink->name);
    unlock_global();
    /* ToDo: According to Q.764 (2.12), we should send "Unequipped CIC" only in
       response to a specific list of message types. But don't know what else to
       do with an unequipped CIC, so for now we send the message in response to
       all messages with unequipped CIC. */
    if (inmsg->typ != ISUP_UEC)
      isup_send_unequipped(slink, cic, inmsg->opc);
    return;
  }
  if(!pvt->reset_done && pvt->equipped) {
    if ((inmsg->typ != ISUP_GRA) && (inmsg->typ != ISUP_GRS)) {
      ast_log(LOG_WARNING, "Group reset still in progress for CIC=%d, typ=%s "
	      "message discarded.\n", cic, isupmsg(inmsg->typ));
      unlock_global();
      return;
    }
  }

  chan = pvt->owner;
  if(chan != NULL) {
    ast_channel_lock(chan);
  }
  ast_mutex_lock(&pvt->lock);

  /* Now that proper locking is done, call on to handle the actual message. */
  (*handler)(pvt, inmsg);

  ast_mutex_unlock(&pvt->lock);
  if(chan != NULL) {
    ast_channel_unlock(chan);
  }
  unlock_global();
}

/* Reattempt call in chan on another circuit */
static struct ss7_chan* reattempt_call(struct ss7_chan *pvt)
{
  struct ast_channel* chan = pvt->owner;
  struct ss7_chan* newpvt;

  t7_clear(pvt);
  pvt->owner = NULL;
  chan->tech_pvt = NULL;
  ast_log(LOG_WARNING, "Reattempt call: hunting on all cics\n");
  // todo: use cics specified in dial parameters
  newpvt = cic_hunt(pvt->link->linkset, pvt->link->linkset->first_cic, pvt->link->linkset->last_cic);
  if (newpvt) {
    ast_mutex_lock(&newpvt->lock);
    ast_log(LOG_DEBUG, "Reattempt call: Got cic %d\n", newpvt->cic);
    chan->tech_pvt = newpvt;
    newpvt->owner = chan;
    ast_mutex_unlock(&newpvt->lock);
    ss7_call(chan, pvt->addr, 0);
  }
  else {
    ast_log(LOG_WARNING, "Reattempt call: No idle circuit available.\n");
    request_hangup(chan, AST_CAUSE_CONGESTION);
  }
  free_cic(pvt);
  return newpvt;
}


static int resolve_dual_seizure(struct ss7_chan *pvt, struct isup_msg *inmsg) {
  /* Q.764 2.9.1.4: The switch with the higher point code controls even numbered CICs */
  int iscontrolling =  (inmsg->dpc > inmsg->opc) ? ((inmsg->cic & 1) == 0) : ((inmsg->cic & 1) != 0);

  if (iscontrolling)
    return 1; /* Discard incoming IAM */
  /* Try to move chan to another CIC */
  reattempt_call(pvt);
  return 0; /* Process incoming IAM */
}

static void process_iam(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  ast_verbose(VERBOSE_PREFIX_3 "Recv IAM CIC=%-3d  ANI=%s DNI=%s RNI=%s redirect=%s/%d complete=%d\n",
          pvt->cic,
          inmsg->iam.ani.restricted ? "*****" : inmsg->iam.ani.num,
          inmsg->iam.dni.num,
          inmsg->iam.rni.restricted ? "*****" : inmsg->iam.rni.num,
          inmsg->iam.redir_inf.is_redirect ? "yes" : "no",
          inmsg->iam.redir_inf.reason,
	  inmsg->iam.dni.complete);
  if (pvt->state == ST_SENT_IAM) {
    if (resolve_dual_seizure(pvt, inmsg)) {
      ast_log(LOG_WARNING, "Dual seizure IAM, discarding on CIC=%d, state=%d.\n",
	      pvt->cic, pvt->state);
      return;
    }
  }
  else if(pvt->state == ST_GOT_IAM) {
    struct ast_channel* chan = pvt->owner;
    ast_log(LOG_WARNING, "Got second IAM on CIC=%d, state=%d.\n", pvt->cic, pvt->state);
    if (chan) {
      request_hangup(chan, AST_CAUSE_NORMAL_TEMPORARY_FAILURE);
      chan->tech_pvt = NULL;
      pvt->owner = NULL;
    }
    free_cic(pvt);
  }
  else if(pvt->state != ST_IDLE) {
    ast_log(LOG_WARNING, "Invalid IAM, discarding on CIC=%d, state=%d.\n",
	    pvt->cic, pvt->state);
    return;
  }
  ast_log(LOG_DEBUG, "IAM cic=%d, owner=0x%08lx\n", pvt->cic, (unsigned long) pvt->owner);
  if(pvt->blocked & (BL_LH|BL_LM)) {
    ast_log(LOG_DEBUG, "IAM cic=%d, is blocked, sending BLK\n", pvt->cic);
    isup_send_blk(pvt);
    return;
  }
  if(pvt->owner) {
    ast_log(LOG_ERROR, "Non-NULL chan found for idle CIC=%d, this shouldn't "
	    "have happened?!?.\n", pvt->cic);
    request_hangup(pvt->owner, AST_CAUSE_NORMAL_CLEARING);
  }

  if (inmsg->iam.trans_medium == 0x02) { /* 64kbit unrestricted data */
	pvt->is_digital = 1;
  }
  switch (pvt->link->echocancel) {
    case EC_ALLWAYS: 
      pvt->echocan_start = !pvt->is_digital;
      break;

    case EC_31SPEECH:
      pvt->echocan_start = inmsg->iam.echocontrol  == 0 && inmsg->iam.trans_medium == 0x3;
      break;
  }

  remove_from_idlelist(pvt);
  pvt->state = ST_GOT_IAM;
  memcpy(&pvt->iam, &inmsg->iam, sizeof(pvt->iam));
  check_iam_sam(pvt);
  pvt->link->linkset->incoming_calls++;
}

static void process_sam(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  ast_log(LOG_DEBUG, "SAM (cic=%d): SNI=%s, complete=%d, t35=%d\n", inmsg->cic,inmsg->sam.sni.num, inmsg->sam.sni.complete, pvt->t35);

  if (pvt->state != ST_GOT_IAM) {
    ast_log(LOG_WARNING, "Received SAM on CIC=%d, but got no IAM, state=%d.\n", pvt->cic, pvt->state);
    return;
  }

  t35_clear(pvt);
  if (strlen(inmsg->sam.sni.num) == PHONENUM_MAX-1) {
    initiate_release_circuit(pvt, AST_CAUSE_INVALID_NUMBER_FORMAT);
    return;
  }
  strcat(pvt->iam.dni.num, inmsg->sam.sni.num);
  pvt->iam.dni.complete = pvt->iam.dni.complete || inmsg->sam.sni.complete;
  check_iam_sam(pvt);
}


static void process_acm(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  struct ast_channel* chan = pvt->owner;
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  static struct ast_frame ring_frame = { AST_FRAME_CONTROL, AST_CONTROL_RINGING };
#else
  static struct ast_frame ring_frame = { AST_FRAME_CONTROL, {AST_CONTROL_RINGING} };
#endif

  /* Q.764 (2.1.4.6 a): When receiving ACM, stop T7 and start T9. */
  t7_clear(pvt);

  if(pvt->state != ST_SENT_IAM) {
    ast_log(LOG_NOTICE, "Got ACM message, but sent no IAM, on CIC=%d?!?",
            pvt->cic);
    /* Q.764 (2.9.5.1 f) error handling for the spurious ACM. */
    if(pvt->state == ST_IDLE)
      reset_circuit(pvt);
    return;
  }

  if(chan == NULL) {
    ast_log(LOG_NOTICE, "Missing chan pointer for CIC=%d, processing ACM?!?\n", pvt->cic);
    return;
  }
  t9_start(chan);

  pvt->charge_indicator = inmsg->acm.back_ind.charge_indicator;

  /* Q.764 (2.1.4.6 a): Alert if called_party_status is "subscriber free". */
  if(inmsg->acm.back_ind.called_party_status == 1) {
    ast_queue_frame(chan, &ring_frame);
  }
  pvt->state = ST_GOT_ACM;
  ast_setstate(chan, AST_STATE_RINGING);
  check_obci(pvt, inmsg->acm.obc_ind);
}

static void process_anm(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  struct ast_channel* chan = pvt->owner;
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  static struct ast_frame answer_frame = { AST_FRAME_CONTROL, AST_CONTROL_RINGING };
#else
  static struct ast_frame answer_frame = { AST_FRAME_CONTROL, {AST_CONTROL_ANSWER} };
#endif

  /* Q.764 (2.1.7.6): When receiving ANM, stop T9. */
  t9_clear(pvt);

  if(pvt->state != ST_GOT_ACM) {
    ast_log(LOG_NOTICE, "Got ANM message, but no ACM, on CIC=%d?!?",
            pvt->cic);
    /* Q.764 (2.9.5.1 f) error handling for the spurious ANM. */
    if(pvt->state == ST_IDLE)
      reset_circuit(pvt);
    return;
  }

  if(chan == NULL) {
    ast_log(LOG_NOTICE, "Missing chan pointer for CIC=%d, processing ANM?!?\n", pvt->cic);
    return;
  }

  set_audiomode(pvt->zaptel_fd);

  /* Start echo-cancelling */
  if (pvt->link->echocancel != EC_DISABLED) {
    if (!io_enable_echo_cancellation(pvt->zaptel_fd, pvt->cic, pvt->link->echocan_taps, pvt->link->echocan_train))
      pvt->echocancel = 1;
  }

  ast_queue_frame(chan, &answer_frame);
  pvt->state = ST_CONNECTED;
  ast_setstate(chan, AST_STATE_UP);
  check_obci(pvt, inmsg->anm.obc_ind);
}

static void process_con(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  struct ast_channel* chan = pvt->owner;
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  static struct ast_frame answer_frame = { AST_FRAME_CONTROL, AST_CONTROL_ANSWER };
#else
  static struct ast_frame answer_frame = { AST_FRAME_CONTROL, {AST_CONTROL_ANSWER} };
#endif

  t7_clear(pvt);

  if(pvt->state == ST_SENT_REL) {
    /* Sent release before receiving connect */
    return;
  }
  if(pvt->state != ST_SENT_IAM) {
    ast_log(LOG_NOTICE, "Got CON message, but sent no IAM, on CIC=%d?!?",
            pvt->cic);
    /* Q.764 (2.9.5.1 f) error handling for the spurious CON. */
    if(pvt->state == ST_IDLE)
      reset_circuit(pvt);
    return;
  }

  if(chan == NULL) {
    ast_log(LOG_NOTICE, "Missing chan pointer for CIC=%d, processing CON?!?\n", pvt->cic);
    return;
  }

  pvt->charge_indicator = inmsg->con.back_ind.charge_indicator;
  ast_queue_frame(chan, &answer_frame);
  pvt->state = ST_CONNECTED;
  ast_setstate(chan, AST_STATE_UP);
  check_obci(pvt, inmsg->cpr.obc_ind);
}

static void process_cpr(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  struct ast_channel* chan = pvt->owner;

  if(pvt->state != ST_SENT_IAM && pvt->state != ST_GOT_ACM) {
    ast_log(LOG_NOTICE, "Got call progress, but call setup not active, CIC=%d, state=%d?!?\n",
            pvt->cic, pvt->state);
    /* Q.764 (2.9.5.1 f) error handling for the spurious CPR. */
    if(pvt->state == ST_IDLE)
      reset_circuit(pvt);
    return;
  }

  if(chan == NULL) {
    ast_log(LOG_NOTICE, "Missing chan pointer for CIC=%d, processing CPR?!?\n", pvt->cic);
    return;
  }

  ast_log(LOG_DEBUG, "Process CPR, CIC=%d event=0x%x, obci=0x%x\n", pvt->cic, inmsg->cpr.event_info, inmsg->cpr.obc_ind);
  /* Q.763 3.21 */
  switch(inmsg->cpr.event_info) {
  case 0x1:                   /* ALERTING */
    ast_log(LOG_DEBUG, "Queueing RINGING indication for Asterisk, CIC=%d.\n",
	    pvt->cic);
    ast_queue_control(chan, AST_CONTROL_RINGING);
    break;
  case 0x2:                   /* PROGRESS */
    ast_log(LOG_DEBUG, "Got CPR Progress, NOT queueing indication for Asterisk, CIC=%d.\n",
	    pvt->cic);
#if 0
    ast_queue_control(chan, AST_CONTROL_PROGRESS);
#endif
    break;
  case 0x3:                   /* In-band information or appropriate pattern available */
    if (!pvt->has_inband_ind) {
      ast_log(LOG_DEBUG, "Queueing PROGRESS (Inband-information available) indication for Asterisk, CIC=%d.\n", pvt->cic);
      ast_queue_control(chan, AST_CONTROL_PROGRESS);
      pvt->has_inband_ind = 1;
    }
    break;
  }
  check_obci(pvt, inmsg->cpr.obc_ind);
}

static void process_rlc(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  ast_log(LOG_DEBUG, "Process RLC CIC=%d, state=%d, reset_done %d\n", pvt->cic, pvt->state, pvt->reset_done);
  if (!pvt->reset_done && (pvt->state == ST_SENT_REL)) {
    /* Sent a reset circuit message */
    t16_clear(pvt);
    pvt->state = ST_IDLE;
    if (pvt->owner)
      ast_setstate(pvt->owner, AST_STATE_DOWN);
    pvt->reset_done = 1;
    ast_log(LOG_NOTICE, "Process RLC CIC=%d, state=%d, sent RSC\n", pvt->cic, pvt->state);
    return;
  }
  if(pvt->state == ST_SENT_REL) {
    if (pvt->owner)
      ast_setstate(pvt->owner, AST_STATE_DOWN);
    free_cic(pvt);

    /* Clear timer T1 and T5 "waiting for release complete".
       Also clear T16 "waiting for RLC after circuit reset",
       and clear T17 "waiting for RLC after circuit reset". */
    t1_clear(pvt);
    t2_clear(pvt);
    t5_clear(pvt);
    t6_clear(pvt);
    t16_clear(pvt);
    t17_clear(pvt);
  } else if(pvt->state == ST_IDLE) {
    /* Q.764 (2.9.5.1 b): Discard spurious RLC. */
    t16_clear(pvt);
  } else {
    /* Q.764 (2.9.5.1 c): If a RLC is received without sending REL,
       release the circuit and send REL. */
    /* The channel has already been locked in process_isup_message(). */
    if(pvt->owner == NULL) {
      ast_log(LOG_ERROR, "NULL chan, CIC=%d, processing RLC!?!\n", pvt->cic);
      isup_send_rel(pvt, AST_CAUSE_NORMAL_TEMPORARY_FAILURE);
      pvt->state = ST_SENT_REL;
    } else {
      struct ast_channel* chan = pvt->owner;
      request_hangup(chan, AST_CAUSE_INVALID_MSG_UNSPECIFIED);
    }
    /* We will send REL later, in ss7_hangup(). */
  }
}

static void process_rel(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  struct ast_channel* chan = pvt->owner;

  if(pvt->state == ST_GOT_REL) {
    /* Didn't see this described in Q.764 (receive a second REL before sending
       first RLC reply). */
    reset_circuit(pvt);
    pvt->state = ST_SENT_REL;
    return;
  }
  if (chan) {
    handle_redir_info(chan, &inmsg->rel.redir_inf);
    if(inmsg->rel.rdni.present)
      pbx_builtin_setvar_helper(chan, "SS7_RDNI", inmsg->rel.rdni.num);
  }
  if(pvt->state != ST_IDLE && pvt->state != ST_SENT_REL) {
    if(chan != NULL) {
      /* The channel has already been locked in process_isup_message(). */
      request_hangup(chan, inmsg->rel.cause);
      /* Q.764 (2.3.1 c): Postpone the RLC until ss7_hangup() when the
         circuit is ready for re-selection. */
      pvt->state = ST_GOT_REL;
      return;
    } else {
      if (pvt->state == ST_GOT_IAM) {
	t35_clear(pvt);
      }
      else if (pvt->state == ST_CONCHECK) {
	t36_clear(pvt);
      }
      else {
	ast_log(LOG_NOTICE, "NULL chan for non-idle circuit CIC=%d, processing REL?!?.\n",
		inmsg->cic);
	/* Intentionally fall through ... */
      }
    }
  }

  /* If state == ST_SENT_REL, send RLC and stay in this state, still awaiting RLC */
  if(pvt->state != ST_IDLE && pvt->state != ST_SENT_REL) {
    if (pvt->owner)
      ast_setstate(pvt->owner, AST_STATE_DOWN);
    free_cic(pvt);
  }
  /* Send "Release Confirmed", Q.764 (2.9.5.1 a). */
  isup_send_rlc(pvt);
}

/* Process suspend message */
static void process_sus(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  if (pvt->state != ST_CONNECTED) {
    ast_log(LOG_NOTICE, "Received SUS (%d) while not in connected state, CIC=%d\n", inmsg->sus.indicator, inmsg->cic);
    return;
  }
  if (inmsg->sus.indicator == 0)
    t2_start(pvt);
  else
  if (inmsg->sus.indicator == 1)
    t6_start(pvt);
  else
    ast_log(LOG_NOTICE, "Got invalid indicator=%d CIC=%d, processing SUS\n", inmsg->sus.indicator, inmsg->cic);
}

/* Process resume message */
static void process_res(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  if (inmsg->sus.indicator == 0) {
    if (pvt->t2 == -1) {
      ast_log(LOG_NOTICE, "Received RES (user) but got no earlier SUS, CIC=%d\n", inmsg->cic);
      return;
    }
    t2_clear(pvt);
  }
  else if (inmsg->sus.indicator == 1) {
    if (pvt->t6 == -1) {
      ast_log(LOG_NOTICE, "Received RES (network) but got no earlier SUS, CIC=%d\n", inmsg->cic);
      return;
    }
    t6_clear(pvt);
  }
  else
    ast_log(LOG_NOTICE, "Got invalid indicator=%d CIC=%d, processing RES\n", inmsg->sus.indicator, inmsg->cic);
}

static void process_rsc(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  struct ast_channel* chan = pvt->owner;

  /* Send blocking message(s) if we are locally blocked. */
  if(pvt->blocked & (BL_LH|BL_LM)) {
    isup_send_blk(pvt);
  }
  pvt->blocked &= ~(BL_RM|BL_RH|BL_UNEQUIPPED);

  if(pvt->state == ST_GOT_REL) {
    /* Didn't see this described in Q.764 (receive RSC after REL before sending
       first RLC reply). In this situation we send a single RLC message, from
       ss7_hangup(). */
    return;
  }
  
  ast_log(LOG_DEBUG, "Reset, CIC=%d state=%d, chan=0x%08lx\n", inmsg->cic, pvt->state, (unsigned long) pvt->owner);
  if (!pvt->reset_done && (pvt->state == ST_SENT_REL)) {
    /* Sent a reset circuit message */
    ast_log(LOG_NOTICE, "Process RSC CIC=%d, state=%d\n", pvt->cic, pvt->state);
    t16_clear(pvt);
    pvt->state = ST_IDLE;
    if (pvt->owner)
      ast_setstate(pvt->owner, AST_STATE_DOWN);
    pvt->reset_done = 1;
    isup_send_rlc(pvt);
    return;
  }
  if(pvt->state != ST_IDLE) {
    if(chan != NULL) {
      /* Q.764 (2.9.3.1 a): For non-idle circuit, treat RSC as REL. */
      if (pvt->state == ST_SENT_IAM) {
	lock_global();
	reattempt_call(pvt);
	unlock_global();
	/* Send "Release Confirmed", Q.764 (2.9.3.1 a). */
	/* Intentionally fall through ... */
      }
      else {
	request_hangup(chan, AST_CAUSE_NORMAL_TEMPORARY_FAILURE);
	if (pvt->state != ST_SENT_REL)
	  pvt->state = ST_GOT_REL;
	return;
      }
    } else {
      if (pvt->state == ST_SENT_REL) {
	t1_clear(pvt);
	t5_clear(pvt);
	/* Send "Release Confirmed", Q.764 (2.9.3.1 a). */
	/* Intentionally fall through ... */
      }
      else {
	ast_log(LOG_NOTICE, "NULL chan for non-idle circuit CIC=%d, processing RSC?!?.\n",
		inmsg->cic);
	/* Intentionally fall through ... */
      }
    }
  }

  if (pvt->state != ST_IDLE) {
    if (pvt->owner)
      ast_setstate(pvt->owner, AST_STATE_DOWN);
    free_cic(pvt);
  }
  /* Send "Release Confirmed", Q.764 (2.9.3.1 b). */
  isup_send_rlc(pvt);	
}

/* Process block acknowledgement message */
static void process_bla(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  /* Mark the circuit as blocked. */
  pvt->blocked |= BL_LM;
  t12_clear(pvt);
}

/* Process unblock acknowledgement message */
static void process_uba(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  /* Mark the circuit as unblocked. */
  pvt->blocked &= ~BL_LM;
  t14_clear(pvt);
}

/* Process block message */
static void process_blk(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;

  if (pvt->state == ST_SENT_IAM) {
    /* Q.764 2.8.2.1: Make an automated repeat attempt on a non-connected
       outgoing call. */
    reattempt_call(pvt);
  }

  /* Mark the circuit as blocked. */
  pvt->blocked |= BL_RM;

  /* Reply with blocking acknowledge. */
  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), inmsg->opc, inmsg->cic, ISUP_BLA,
                &current);
  isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current,
                               0, 0);
  mtp_enqueue_isup(pvt, msg, current);

  if (pvt->state == ST_SENT_IAM) {
    /* Q.764 2.8.2.1: Release the call in the normal manner */
    initiate_release_circuit(pvt, AST_CAUSE_NORMAL_CLEARING);
  }
}

/* Process unblock message */
static void process_ubl(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;

  /* Mark the circuit as not blocked. */
  pvt->blocked &= ~BL_RM;

  /* Reply with unblocking acknowledge. */
  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), inmsg->opc, inmsg->cic, ISUP_UBA,
                &current);
  isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current,
                               0, 0);
  mtp_enqueue_isup(pvt, msg, current);
}

/* Process unequipped CIC message */
static void process_uec(struct ss7_chan *pvt, struct isup_msg *inmsg)
{

  ast_log(LOG_NOTICE, "Received unequipped CIC message, CIC=%d\n", inmsg->cic);
  /* Mark the circuit as unequipped. */
  pvt->blocked |= BL_UNEQUIPPED;
  if (pvt->state == ST_SENT_IAM) {
    /* Q.764 2.12.2 2): Re-attempt if this was first attempt */
    if (pvt->attempts == 1) {
      struct ss7_chan* newpvt = reattempt_call(pvt);
      if (!newpvt) {
	return;
      }
      newpvt->attempts = 2;
      if (pvt->owner)
	ast_setstate(pvt->owner, AST_STATE_DOWN);
      free_cic(pvt);
    }
    else {
      initiate_release_circuit(pvt, AST_CAUSE_DESTINATION_OUT_OF_ORDER);
    }
  }
  else {
    /* ToDo: Handle other cases here */
  }
}

/* Process continuity check request */
static void process_ccr(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  /* Send blocking message(s) if we are locally blocked. */
  if(pvt->blocked & (BL_LH|BL_LM)) {
    isup_send_blk(pvt);
  }

  if(pvt->state != ST_IDLE) {
    ast_log(LOG_NOTICE, "Received CCR but state is not ST_IDLE for CIC=%d\n", pvt->cic);
    return;
  }

  if(pvt->owner != NULL) {
    ast_log(LOG_ERROR, "Non-NULL chan found for idle CIC=%d, this shouldn't have happened, processing CCR.\n", pvt->cic);
    return;
  }

  if(pvt->cic < 0 || pvt->cic >= MAX_CIC) {
    ast_log(LOG_ERROR, "Invalid CIC=%d, processing CCR\n", pvt->cic);
    return;
  }

  pvt->state = ST_CONCHECK;
  t36_start(pvt);
  ast_mutex_lock(&continuity_check_lock);
  continuity_check_changes = 1;
  ast_mutex_unlock(&continuity_check_lock);
}

/* Process continuity */
static void process_cot(struct ss7_chan *pvt, struct isup_msg *inmsg)
{
  if(pvt->state != ST_CONCHECK) {
    ast_log(LOG_WARNING, "Received COT, but state is not ST_CONCHECK for CIC=%d?!?\n", pvt->cic);
    return;
  }

  t36_clear(pvt);
  pvt->state = ST_IDLE;
  ast_mutex_lock(&continuity_check_lock);
  continuity_check_changes = 1;
  ast_mutex_unlock(&continuity_check_lock);
}

/* Process circuit group reset acknowledge */
static void process_gra(struct ss7_chan* pvt, struct isup_msg *inmsg) {
  struct linkset* linkset = pvt->link->linkset;
  int i, j, mask;
  int cic;

  ast_log(LOG_NOTICE, "Process GRA, cic=%d, range=%d\n", inmsg->cic, inmsg->gra.range_status.range);
  cic = inmsg->cic;
  if(cic < 0 || cic >= MAX_CIC) {
    ast_log(LOG_NOTICE, "Out-of-range CIC=%d in GRA, discarding.\n", cic);
    return;
  }

  if(pvt->grs_count == -1 || inmsg->gra.range_status.range + 1 != pvt->grs_count) {
    ast_log(LOG_DEBUG, "Processing unexpected GRA (CIC=%d, range %d) (assuming initiated by other host).\n",
            inmsg->cic, inmsg->gra.range_status.range);
  }

  t22_clear(pvt);
  t23_clear(pvt);
  pvt->grs_count = -1;

  /* I think we have no other locking issues here, since this stuff is
     only ever accessed from within the monitor thread. */
  j = 0;
  mask = 1;
  for(i = cic; i <= cic + inmsg->gra.range_status.range; i++) {
    struct ss7_chan* pvt = linkset->cic_list[i];
    if (pvt) {
      pvt->blocked &= ~(BL_UNEQUIPPED|BL_LH|BL_RH);
      if(pvt->reset_done) {
	if(pvt->equipped) {
	  ast_log(LOG_NOTICE, "Unexpected GRA for already reset circuit "
		  "CIC=%d?!?.\n", i);
	}
      } else {
	if(inmsg->gra.range_status.status[j] & mask) {
	  pvt->blocked |= BL_RM;
	}
	pvt->reset_done = 1;
      }
    }
    mask <<= 1;
    if(mask == 0x100) {
      mask = 1;
      j++;
    }
  }
}

/* Process circuit group blocking */
static void process_cgb(struct ss7_chan* pvt, struct isup_msg *inmsg) {
  struct linkset* linkset = pvt->link->linkset;
  int i, j, n, mask, blockmask;
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varpart;
  unsigned char param[34];
  int range;

  range = inmsg->cgb.range_status.range;
  ast_log(LOG_NOTICE, "Process CGB, cic=%d, range=%d\n", inmsg->cic, range);

  if(range < 1 || range > 255 || inmsg->cic + range + 1 >= MAX_CIC) {
    ast_log(LOG_WARNING, "Got invalid cic=%d/range=%d for CGB.\n",
	    inmsg->cic, range);
    return;
  }

  switch(inmsg->cgb.cgsmti) {
  case 0:
    blockmask = BL_RM;
    break;
  case 1:
    blockmask = BL_RH;
    break;
  default:
    ast_log(LOG_NOTICE, "Unimplemented circuit group blocking type %d, "
	    "discarding.\n", inmsg->cgb.cgsmti);
    return;
  }

  n = 0;
  for(i = inmsg->cic, j=0; i <= inmsg->cic + range; i++, j++)
    if(inmsg->cgb.range_status.status[j / 8] & (1<<(j%8)))
      n++;
  if (n > 32) {
    /* Q.764 2.8.2.3 ix) Discard message if more than 32 circuits in mask */
    return;
  }

  j = 0;
  mask = 1;
  for(i = inmsg->cic; i <= inmsg->cic + range; i++) {
    if(inmsg->cgb.range_status.status[j] & mask) {
      struct ss7_chan* pvt = linkset->cic_list[i];
      if(!pvt || !pvt->equipped) {
	ast_log(LOG_NOTICE, "Unexpected NULL pvt for CIC=%d to be blocked.\n",
		i);
      } else {
	pvt->blocked |= blockmask;
	if(pvt->state == ST_SENT_IAM) {
	  if (pvt->owner)
	    request_hangup(pvt->owner, AST_CAUSE_NORMAL_UNSPECIFIED);
	  /* Q.764 (2.8.2.1): Release call attempt */
	  release_circuit(pvt);
	  free_cic(pvt);
	}
      }
    }
    mask <<= 1;
    if(mask == 0x100) {
      mask = 1;
      j++;
    }
  }

  /* Reply with circuit group blocking acknowledge. */
  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), inmsg->opc, inmsg->cic, ISUP_CGA, &current);
  param[0] = inmsg->cgb.cgsmti;
  isup_msg_add_fixed(msg, sizeof(msg), &current, param, 1);
  isup_msg_start_variable_part(msg, sizeof(msg), &varpart, &current, 1, 0);
  param[0] = range;
  memcpy(&param[1], inmsg->cgb.range_status.status, (range + 8) / 8);
  isup_msg_add_variable(msg, sizeof(msg), &varpart, &current, param, 1 + (range + 8) / 8);
  mtp_enqueue_isup(pvt, msg, current);
}

/* Process circuit group blocking acknkowledge */
static void process_cga(struct ss7_chan* pvt, struct isup_msg *inmsg) {
  struct linkset* linkset = pvt->link->linkset;
  int i, j, n, mask, blockmask;
  int range;

  range = inmsg->cgb.range_status.range;
  ast_log(LOG_NOTICE, "Process CGA, cic=%d, range=%d\n", inmsg->cic, range);

  if(range < 1 || range > 255 || inmsg->cic + range + 1 >= MAX_CIC) {
    ast_log(LOG_WARNING, "Got invalid cic=%d/range=%d for CGB.\n",
	    inmsg->cic, range);
    return;
  }

  switch(inmsg->cgb.cgsmti) {
  case 0:
    blockmask = BL_LM;
    break;
  case 1:
    blockmask = BL_LH;
    break;
  default:
    ast_log(LOG_NOTICE, "Unimplemented circuit group blocking type %d, "
	    "discarding.\n", inmsg->cgb.cgsmti);
    return;
  }

  n = 0;
  for(i = inmsg->cic, j=0; i <= inmsg->cic + range; i++, j++)
    if(inmsg->cgb.range_status.status[j / 8] & (1<<(j%8)))
      n++;
  if (n > 32) {
    /* Q.764 2.8.2.3 ix) Discard message if more than 32 circuits in mask */
    return;
  }

  j = 0;
  mask = 1;
  for(i = inmsg->cic; i <= inmsg->cic + range; i++) {
    if(inmsg->cgb.range_status.status[j] & mask) {
      if (linkset->cic_list[i])
	linkset->cic_list[i]->blocked |= blockmask;
    }
    mask <<= 1;
    if(mask == 0x100) {
      mask = 1;
      j++;
    }
  }
  t18_clear(pvt);
  t19_clear(pvt);
}


/* Process circuit group unblocking acknkowledge */
static void process_cua(struct ss7_chan* pvt, struct isup_msg *inmsg) {
  struct linkset* linkset = pvt->link->linkset;
  int i, j, n, mask, blockmask;
  int range;

  range = inmsg->cgb.range_status.range;
  ast_log(LOG_NOTICE, "Process CUA, cic=%d, range=%d\n", inmsg->cic, range);

  if(range < 1 || range > 255 || inmsg->cic + range + 1 >= MAX_CIC) {
    ast_log(LOG_WARNING, "Got invalid cic=%d/range=%d for CGB.\n",
	    inmsg->cic, range);
    return;
  }

  switch(inmsg->cgb.cgsmti) {
  case 0:
    blockmask = BL_LM;
    break;
  case 1:
    blockmask = BL_LH;
    break;
  default:
    ast_log(LOG_NOTICE, "Unimplemented circuit group unblocking type %d, "
	    "discarding.\n", inmsg->cgb.cgsmti);
    return;
  }

  n = 0;
  for(i = inmsg->cic, j=0; i <= inmsg->cic + range; i++, j++)
    if(inmsg->cgb.range_status.status[j / 8] & (1<<(j%8)))
      n++;
  if (n > 32) {
    /* Q.764 2.8.2.3 ix) Discard message if more than 32 circuits in mask */
    return;
  }

  j = 0;
  mask = 1;
  for(i = inmsg->cic; i <= inmsg->cic + range; i++) {
    if(inmsg->cgb.range_status.status[j] & mask) {
      if (linkset->cic_list[i])
	linkset->cic_list[i]->blocked &= ~blockmask;
    }
    mask <<= 1;
    if(mask == 0x100) {
      mask = 1;
      j++;
    }
  }
  t20_clear(pvt);
  t21_clear(pvt);
}


/* Process circuit group unblocking */
static void process_cgu(struct ss7_chan* pvt, struct isup_msg *inmsg) {
  struct linkset* linkset = pvt->link->linkset;
  int i, j, n, mask, blockmask;
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varpart;
  unsigned char param[34];
  int range;

  range = inmsg->cgu.range_status.range;
  ast_log(LOG_NOTICE, "Process CGU, cic=%d, range=%d\n", inmsg->cic, range);

  if(range < 1 || range > 255 || inmsg->cic + range + 1 >= MAX_CIC) {
    ast_log(LOG_WARNING, "Got invalid cic=%d/range=%d for CGU.\n",
	    inmsg->cic, range);
    return;
  }

  switch(inmsg->cgu.cgsmti) {
  case 0:
    blockmask = ~BL_RM;
    break;
  case 1:
    blockmask = ~BL_RH;
    break;
  default:
    ast_log(LOG_NOTICE, "Unimplemented circuit group unblocking type %d, "
	    "discarding.\n", inmsg->cgu.cgsmti);
    return;
  }

  n = 0;
  for(i = inmsg->cic, j=0; i <= inmsg->cic + range; i++, j++)
    if(inmsg->cgb.range_status.status[j / 8] & (1<<(j%8)))
      n++;
  if (n > 32) {
    /* Q.764 2.8.2.3 ix) Discard message if more than 32 circuits in mask */
    return;
  }

  j = 0;
  mask = 1;
  for(i = inmsg->cic; i <= inmsg->cic + range; i++) {
    if(inmsg->cgu.range_status.status[j] & mask) {
      struct ss7_chan* pvt = linkset->cic_list[i];
      if(!pvt || !pvt->equipped) {
	ast_log(LOG_NOTICE, "Unexpected NULL pvt for CIC=%d to be unblocked.\n",
		i);
      } else {
	pvt->blocked &= blockmask;
      }
    }
    mask <<= 1;
    if(mask == 0x100) {
      mask = 1;
      j++;
    }
  }

  /* Reply with circuit group unblocking acknowledge. */
  isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), inmsg->opc, inmsg->cic, ISUP_CUA, &current);
  param[0] = inmsg->cgu.cgsmti;
  isup_msg_add_fixed(msg, sizeof(msg), &current, param, 1);
  isup_msg_start_variable_part(msg, sizeof(msg), &varpart, &current, 1, 0);
  param[0] = range;
  memcpy(&param[1], inmsg->cgu.range_status.status, (range + 8) / 8);
  isup_msg_add_variable(msg, sizeof(msg), &varpart, &current, param, 1 + (range + 8) / 8);
  mtp_enqueue_isup(pvt, msg, current);
}

static void process_isup_message(struct link* slink, struct isup_msg *inmsg)
{
  if (inmsg->opc != slink->linkset->dpc) {
    ast_log(LOG_DEBUG, "Got ISUP message from unconfigured PC=%d, typ=%s, CIC=%d\n", inmsg->opc, isupmsg(inmsg->typ), inmsg->cic);
    if (slink->linkset->opc != inmsg->opc) /* typical config error, swapped point codes */
      isup_send_unequipped(slink, inmsg->cic, inmsg->opc);
    return;
  }

  // xxx  ast_log(LOG_DEBUG, "processing ISUP message, typ=%s, CIC=%d\n", isupmsg(inmsg->typ), inmsg->cic);

  switch(inmsg->typ) {
  case ISUP_IAM:
    process_circuit_message(slink, inmsg, process_iam);
    break;

  case ISUP_SAM:
    process_circuit_message(slink, inmsg, process_sam);
    break;

  case ISUP_ACM:
    process_circuit_message(slink, inmsg, process_acm);
    break;

  case ISUP_CON:
    process_circuit_message(slink, inmsg, process_con);
    break;

  case ISUP_ANM:
    process_circuit_message(slink, inmsg, process_anm);
    break;

  case ISUP_CPR:
    process_circuit_message(slink, inmsg, process_cpr);
    break;

  case ISUP_REL:
    process_circuit_message(slink, inmsg, process_rel);
    break;

  case ISUP_RLC:
    process_circuit_message(slink, inmsg, process_rlc);
    break;

  case ISUP_SUS:
    process_circuit_message(slink, inmsg, process_sus);
    break;

  case ISUP_RES:
    process_circuit_message(slink, inmsg, process_res);
    break;

  case ISUP_RSC:
    process_circuit_message(slink, inmsg, process_rsc);
    break;

  case ISUP_BLK:
    process_circuit_message(slink, inmsg, process_blk);
    break;

  case ISUP_UBL:
    process_circuit_message(slink, inmsg, process_ubl);
    break;

  case ISUP_UEC:
    process_circuit_message(slink, inmsg, process_uec);
    break;

  case ISUP_CCR:
    process_circuit_message(slink, inmsg, process_ccr);
    break;

  case ISUP_COT:
    process_circuit_message(slink, inmsg, process_cot);
    break;

  case ISUP_BLA:
    process_circuit_message(slink, inmsg, process_bla);
    break;

  case ISUP_UBA:
    process_circuit_message(slink, inmsg, process_uba);
    break;

  case ISUP_GRS:
    process_circuit_group_message(slink, inmsg, handle_GRS_send_hwblock);
    break;

  case ISUP_GRA:
    process_circuit_group_message(slink, inmsg, process_gra);
    break;

  case ISUP_CGB:
    process_circuit_group_message(slink, inmsg, process_cgb);
    break;

  case ISUP_CGA:
    process_circuit_group_message(slink, inmsg, process_cga);
    break;

  case ISUP_CGU:
    process_circuit_group_message(slink, inmsg, process_cgu);
    break;

  case ISUP_CUA:
    process_circuit_group_message(slink, inmsg, process_cua);
    break;
  default:
    ast_log(LOG_NOTICE, "Got unimplemented ISUP message type %s.\n", isupmsg(inmsg->typ));
  }
}

static void proxy_process_isup_message(struct link* slink, struct isup_msg *inmsg, unsigned char* buf, unsigned int len)
{
  struct ss7_chan* pvt = slink->linkset->cic_list[inmsg->cic];

  ast_log(LOG_DEBUG, "Investigating ISUP event for unequipped CIC=%d, typ=%s \n", inmsg->cic, isupmsg(inmsg->typ));
  if((inmsg->typ == ISUP_CGA) || (inmsg->typ == ISUP_CUA) || (inmsg->typ == ISUP_GRA)) {
    process_isup_message(slink, inmsg);
    //xxxx    return;
  }
  if (cluster_receivers_alive(slink->linkset)) {
    /* Host deals with message itself, cluster module has sent it */
  }
  {
    unsigned char event_buf[MTP_EVENT_MAX_SIZE];
    struct mtp_event *event = (struct mtp_event *)event_buf;
    event->typ = MTP_EVENT_ISUP;
    event->isup.slink = slink;
    event->isup.link = slink;
    event->len = len;
    memcpy(event->buf, buf, event->len);
    cluster_mtp_forward((struct mtp_req*) event);/* fixme */
    return;
  }
  /* Host owning CIC is down, deal with message */
  ast_log(LOG_DEBUG, "Processing ISUP event for unequipped CIC=%d, typ=%s \n", inmsg->cic, isupmsg(inmsg->typ));
  lock_global();
  ast_mutex_lock(&pvt->lock);
  switch(inmsg->typ) {
  case ISUP_IAM:
  case ISUP_SAM:
  case ISUP_CCR:
  case ISUP_ACM:
  case ISUP_CON:
  case ISUP_ANM:
  case ISUP_CPR:
    isup_send_rel(pvt, AST_CAUSE_DESTINATION_OUT_OF_ORDER);
    break;
  case ISUP_REL:
  case ISUP_RSC:
    isup_send_rlc(pvt);
    break;

  case ISUP_RLC:
  case ISUP_BLK:
  case ISUP_UBL:
  case ISUP_UEC:
  case ISUP_COT:
    /* Ignore */
  case ISUP_GRS:
  case ISUP_GRA:
  case ISUP_CGB:
  case ISUP_CGA:
  case ISUP_CGU:
  case ISUP_CUA:
    /* Ignore */
    break;
  default:
    ast_log(LOG_NOTICE, "Got unimplemented ISUP message type %s.\n", isupmsg(inmsg->typ));
  }
  ast_mutex_unlock(&pvt->lock);
  unlock_global();
}

void l4isup_link_status_change(struct link* link, int up)
{
  int i, lsi;

  lock_global();
  if (up)
    l4isup_inservice(link);
  link->linkset->inservice += (up*2-1);
  if (up || (!mtp_has_inservice_schannels(link) && !cluster_receivers_alive(link->linkset))) {
    for (lsi = 0; lsi < n_linksets; lsi++) {
      struct linkset* linkset = &linksets[lsi];
      if (link->linkset == linkset ||
	  is_combined_linkset(link->linkset, linkset)) {
	for (i = 1; i < MAX_CIC; i++) {
	  struct ss7_chan* pvt = linkset->cic_list[i];
	  if (!pvt)
	    continue;
	  if (up)
	    pvt->blocked &= ~(BL_LH);
	  else
	    pvt->blocked |= BL_LH;
	}
      }
    }
  }
  if (!link->auto_block) {
    unlock_global();
    return;
  }
  for (i = 0; i < 32; i++) {
    if (link->channelmask & (1<<i)) {
      struct ss7_chan* pvt = link->linkset->cic_list[link->first_cic + i];
      ast_mutex_lock(&pvt->lock);
      if (up)
	pvt->blocked &= ~(BL_LINKDOWN);
      else
	pvt->blocked |= BL_LINKDOWN;
      ast_log(LOG_DEBUG, "Block mask 0x%02x, cic=%d.\n", pvt->blocked, link->first_cic + i);
      ast_mutex_unlock(&pvt->lock);
    }
  }
  unlock_global();
}


static void *continuity_check_thread_main(void *data) {
  int i, lsi, n = 0;
  int res;
  struct pollfd fds[MAX_CIC];
  struct ss7_chan* fds_pvt[MAX_CIC];

  ast_verbose(VERBOSE_PREFIX_3 "Starting continuity check thread, pid=%d.\n", getpid());

  while(!must_stop_continuity_check_thread) {
    int changes = 0;
    ast_mutex_lock(&continuity_check_lock);
    changes = continuity_check_changes;
    continuity_check_changes = 0;
    ast_mutex_unlock(&continuity_check_lock);
    if (changes) {
      n = 0;
      lock_global();
      for (lsi = 0; lsi < n_linksets; lsi++) {
	struct linkset* linkset = &linksets[lsi];
	for (i = linkset->first_cic; i <= linkset->last_cic; i++) {
	  struct ss7_chan* pvt = linkset->cic_list[i];
	  if (!pvt)
	    continue;
	  if (pvt->state == ST_CONCHECK) {
	    fds[n].fd = pvt->zaptel_fd;
	    fds[n].events = POLLIN;
	    fds_pvt[n] = pvt;
	    n++;
	  }
	}
      }
      unlock_global();
    }
    res = poll(fds, n, 1000);
    if (res < 0) {
      if(errno == EINTR) {
	continue;
      } else {
	ast_log(LOG_NOTICE, "poll() failure, errno=%d: %s\n",
		errno, strerror(errno));
      }
    }
    else if (res > 0) {
      for (i = 0; i < n; i++) {
	if(fds[i].revents & POLLIN) {
	  unsigned char buffer[AST_FRIENDLY_OFFSET + AUDIO_READSIZE];
	  int total = 0;
	  int p = 0;
	  int retry = 20;
	  struct ss7_chan* pvt = fds_pvt[i];
	  /* No need to take to chan->lock */
	  ast_mutex_lock(&pvt->lock);
	  while (total < AUDIO_READSIZE) {
	    int count = read(fds[i].fd, &buffer[total], AUDIO_READSIZE-total);
	    if(count < 0) {
	      if(errno == EINTR) {
		/* Just try again. */
	      } else if(errno == ELAST) {
		get_dahdi_event(pvt);
	      } else {
		if (retry--) {
		  struct timespec delay = {0, 500};
		  nanosleep(&delay, NULL);
		  continue;
		}
		ast_log(LOG_NOTICE, "read() failure, errno=%d: %s\n",
			errno, strerror(errno));
		break;
	      }
	    }
	    else if(count > 0) {
	      total += count;
	    }
	  }
	  retry = 20;
	  while (total > 0) {
	    int count = write(fds[i].fd, &buffer[p], total);
	    if(count < 0) {
	      if(errno == EINTR) {
		/* Just try again. */
	      } else {
		if (retry--) {
		  struct timespec delay = {0, 500};
		  nanosleep(&delay, NULL);
		  continue;
		}
		ast_log(LOG_NOTICE, "write() failure, errno=%d: %s\n",
			errno, strerror(errno));
		break;
	      }
	    }
	    else {
	      total -= count;
	      p += count;
	    }
	  }
	  ast_mutex_unlock(&pvt->lock);
	}
      }
    }
  }
  return NULL;
}

static int start_continuity_check_thread(void)
{
  return start_thread(&continuity_check_thread, continuity_check_thread_main, &continuity_check_thread_running, 10);
}

static void stop_continuity_check_thread(void)
{
  must_stop_continuity_check_thread = 1;
  stop_thread(&continuity_check_thread, &continuity_check_thread_running);
}


static int do_group_circuit_block_unblock(struct linkset* linkset, int firstcic, unsigned long cgb_mask, int sup_type_ind, int own_cics_only, int do_timers, int do_block) {
  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current, varptr;
  unsigned char param[6];
  unsigned char cir_group_sup_type_ind;
  unsigned long mask = 0;
  struct ss7_chan *pvt;
  int p;

  if (!cgb_mask)
    return firstcic+32;
  lock_global();
  if (linkset->grs) {
    memset(param, 0, sizeof(param));
    for (p = 0; p < 32; p++) {
      param[0]++;
      if (cgb_mask & (1<<p)) {
	pvt = linkset->cic_list[firstcic+p];
	if (pvt) {
	  struct link* link = pvt->link;
	  if ((1<<(firstcic - link->first_cic + p)) & link->schannel.mask)
	    continue;
	}
	if (own_cics_only)
	  if (!pvt || !pvt->equipped)
	    continue;
	mask |= (1<<p);
	param[(p / 8) + 1] |= 0x1 << (p % 8);
      }
    }
    param[0]--; /* Range code = range-1 */
    param[0] = 32; /* SIU requires this!! */
    ast_log(LOG_NOTICE, "Sending CIRCUIT GROUP %sBLOCKING, cic=%d, mask=0x%08lx.\n", do_block ? "" : "UN", firstcic, mask);

    pvt = linkset->cic_list[firstcic];
    ast_mutex_lock(&pvt->lock);
    pvt->cgb_mask = cgb_mask;

    isup_msg_init(msg, sizeof(msg), variant(pvt), peeropc(pvt), peerdpc(pvt), firstcic, do_block ? ISUP_CGB : ISUP_CGU, &current);
    cir_group_sup_type_ind = sup_type_ind;
    isup_msg_add_fixed(msg, sizeof(msg), &current, &cir_group_sup_type_ind, 1);

    /* variable range and status */
    isup_msg_start_variable_part(msg, sizeof(msg), &varptr, &current, 1, 0);

    isup_msg_add_variable(msg, sizeof(msg), &varptr, &current, param, 6);
    mtp_enqueue_isup(pvt, msg, current);
    if (do_timers) {
      if (do_block)
	t18_start(pvt);
      else
	t20_start(pvt);
    }
    ast_mutex_unlock(&pvt->lock);
  }
  else {
    for (p = 0; p < 32; p++) {
      param[0]++;
      if (cgb_mask & (1<<p)) {
        pvt = linkset->cic_list[firstcic+p];
        if (pvt) {
          struct link* link = pvt->link;
          if ((1<<(firstcic - link->first_cic + p)) & link->schannel.mask)
            continue;
        }
        if (own_cics_only)
          if (!pvt || !pvt->equipped)
            continue;

        if (do_block) {
          isup_send_blk(pvt);
          if (do_timers)
            t12_start(pvt);

        } else {
          isup_send_ubl(pvt);
          if (do_timers)
            t14_start(pvt);
        }
      }
    }
  }
  unlock_global();

  return firstcic+p;
}


static int cmd_block_unblock(int fd, int argc, argv_type argv, int do_block) {
  struct ss7_chan *pvt;
  int first, count;
  int res = 0;
  struct linkset* linkset = this_host->default_linkset;
  if (argc <= 3) {
    return RESULT_SHOWUSAGE;
  }

  if (argc >= 5) {
    int lsi;
    const char* linksetname = argv[4];
    linkset = NULL;
    for (lsi = 0; lsi < n_linksets; lsi++)
      if (strcmp(linksets[lsi].name, linksetname) == 0)
	linkset = &linksets[lsi];
    if (!linkset) {
      ast_cli(fd, "Unknown linkset: '%s'\n", linksetname);
      return -1;
    }
  }
  first = strtol(argv[2], NULL, 0);
  if (first < linkset->first_cic || first > linkset->last_cic) {
    ast_cli(fd, "<first> cic is out of range (%d..%d)\n", linkset->first_cic, linkset->last_cic);  
    return RESULT_SHOWUSAGE;
  }

  count = strtol(argv[3], NULL, 0);
  if (count <= 0 || count > 32) {
    ast_cli(fd, "Number of circuits should be between 1 and 32\n");  
    return RESULT_SHOWUSAGE;
  }

  lock_global();
  pvt = linkset->cic_list[first];

  if (!pvt->equipped) {
    ast_cli(fd, "cic %d is not an audio circuit\n", first);
    unlock_global();
    return RESULT_FAILURE;
  }

  while ((first <= linkset->last_cic) && (count > 0)) {
    int sup_type_ind = 0x00; /* Maintenance oriented supervision message type */
    unsigned long mask;
    if (count >= 32)
      mask = 0xffffffff;
    else
      mask = (1<<count)-1;
    res = do_group_circuit_block_unblock(linkset, first, mask, sup_type_ind, 1, 1, do_block);
    if (res < 0)
      break;
    ast_cli(fd, "Sending %s message to peer\n", do_block ? "Blocking" : "Unblocking");
    count -= (res-first);
    first = res;
  }
  if (res < 0) {
    ast_cli(fd, "Error sending circuit group %s\n", do_block ? "Blocking" : "Unblocking");
  }

  unlock_global();

  return RESULT_SUCCESS;
}

int cmd_block(int fd, int argc, argv_type argv) {
  return cmd_block_unblock(fd, argc, argv, 1);
}

int cmd_unblock(int fd, int argc, argv_type argv) {
  return cmd_block_unblock(fd, argc, argv, 0);
}


int cmd_linestat(int fd, int argc, argv_type argv) {
  int lsi;
  char* format = "CIC %3d %-15s%s\n";

  for (lsi = 0; lsi < n_linksets; lsi++) {
    struct linkset* linkset = &linksets[lsi];
    int i;
    if (!linkset->enabled)
      continue;
    lock_global();

    ast_cli(fd, "Linkset: %s\n", linkset->name);
    for(i = linkset->first_cic; i <= linkset->last_cic; i++) {
      char blbuf[1000];
      char statbuf[1000];
      struct ss7_chan* pvt = linkset->cic_list[i];
      if (!pvt) continue;
      *blbuf = 0;
      *statbuf = 0;

      if (pvt->blocked) {
	char* lm = "";
	char* lh = "";
	char* rm = "";
	char* rh = "";
	char* ue = "";
	char* ld = "";
	char* nu = "";
	if (pvt->blocked & BL_LM)
          lm =" Local Maintenance";
	if (pvt->blocked & BL_LH)
          lh =" Local Hardware";
	if (pvt->blocked & BL_RM)
          rm =" Remote Maintenance";
	if (pvt->blocked & BL_RH)
          rh =" Remote Hardware";
	if (pvt->blocked & BL_UNEQUIPPED)
          ue =" Unequipped CIC";
	if (pvt->blocked & BL_LINKDOWN)
          ld =" Link down";
	if (pvt->blocked & BL_NOUSE)
          nu =" Local NoUse";
	sprintf(blbuf, "  BLOCKED%s%s%s%s%s%s%s", lm, lh, rm, rh, ue, ld, nu);
      }
      switch (pvt->state) {
      case ST_IDLE:
	sprintf(statbuf, "Idle");
	break;
      case ST_GOT_IAM:
	sprintf(statbuf, "Ringing");
	break;
      case ST_SENT_IAM:
      case ST_GOT_ACM:
      case ST_SENT_ACM:
	sprintf(statbuf, "Initiating call");
	break;
      case ST_CONNECTED:
      case ST_SENT_REL:
      case ST_GOT_REL:
	sprintf(statbuf, "Busy");
	break;
      default:
	sprintf(statbuf, "Unknown state: 0x%x!", pvt->state);
	break;
      }
      if (!pvt->equipped)
	strcat(statbuf, " Unequipped");
      if (!pvt->reset_done)
	strcat(statbuf, " Reset pending");
      ast_cli(fd, format, i, statbuf, blbuf);
    }
    unlock_global();
  }

  return RESULT_SUCCESS;
}


int cmd_reset(int fd, int argc, argv_type argv) {
  int i, lsi;
  struct ss7_chan* idle_list;

  for (lsi = 0; lsi < n_linksets; lsi++) {
    lock_global();
    struct linkset* linkset = &linksets[lsi];
    for(i = linkset->first_cic; i <= linkset->last_cic; i++) {
      struct ss7_chan* pvt = linkset->cic_list[i];
      if (!pvt)
	continue;
      ast_mutex_lock(&pvt->lock);
#ifdef MODULETEST
      pvt->reset_done = 1;
#else
      pvt->reset_done = 0;
#endif
      pvt->state = ST_IDLE;
      t1_clear(pvt);
      t2_clear(pvt);
      t5_clear(pvt);
      t6_clear(pvt);
      t7_clear(pvt);
      t9_clear(pvt);
      t16_clear(pvt);
      t17_clear(pvt);
      t18_clear(pvt);
      t19_clear(pvt);
      t20_clear(pvt);
      t21_clear(pvt);
      ast_mutex_unlock(&pvt->lock);
    }
    idle_list = NULL;
    while (linkset->group_linkset->idle_list) {
      struct ss7_chan* best = NULL, *cur;
      for (cur = linkset->group_linkset->idle_list; cur != NULL; cur = cur->next_idle) {
	if (!best || (best->cic > cur->cic)) {
	  remove_from_idlelist(cur);
	  cur->next_idle = idle_list;
	  idle_list = cur;
	  break;
	}
      }
    }
    linkset->group_linkset->idle_list = idle_list;
    unlock_global();
#ifndef MODULETEST
    send_init_grs(linkset);
#endif
  }
  
  return RESULT_SUCCESS;
}

int cmd_linkset_status(int fd, int argc, argv_type argv) {
  int i, lsi;
  struct ss7_chan* cur;

  for (lsi = 0; lsi < n_linksets; lsi++) {
    int n_idle = 0;
    int n_initiating = 0;
    int n_busy = 0;
    int n_pendingreset = 0;
    int n_idlelist = 0;

    struct linkset* linkset = &linksets[lsi];
    if (!linkset->enabled)
      continue;

    lock_global();
    for(i = linkset->first_cic; i <= linkset->last_cic; i++) {
      struct ss7_chan* pvt = linkset->cic_list[i];
      if (!pvt)
	continue;
      ast_mutex_lock(&pvt->lock);

      if (!pvt->reset_done) {
	n_pendingreset++;
	ast_mutex_unlock(&pvt->lock);
	continue;
      }
      else {
	switch (pvt->state) {
	case ST_IDLE:
	  n_idle++;
	  break;
	case ST_GOT_IAM:
	case ST_SENT_IAM:
	case ST_GOT_ACM:
	case ST_SENT_ACM:
	  n_initiating++;
	  break;
	default:
	  n_busy++;
	  break;
	}
      }
      ast_mutex_unlock(&pvt->lock);
    }
    for (cur = linkset->idle_list, n_idlelist = 0; cur; cur=cur->next_idle, n_idlelist++);

    ast_cli(fd, "linkset        idle busy initiating resetting total incoming total outgoing\n");
    ast_cli(fd, "%-14s %4d %4d %10d %9d %14d %14d\n", linkset->name, n_idle, n_busy, n_initiating, n_pendingreset, linkset->incoming_calls, linkset->outgoing_calls);
    if (n_idle != n_idlelist) {
      ast_cli(fd, "*** Idle list lenth is: %d\n", n_idlelist);
    }
    unlock_global();
  }
  return RESULT_SUCCESS;
}


static int fill_gain_alaw(float gain, float linear_gain, int idx) {
    int val, res;

    if (gain) {
        val = (int) (((float) AST_ALAW(idx)) * linear_gain);
        if (val > 32767) val = 32767;
        if (val < -32767) val = -32767;
        res = AST_LIN2A(val);
    } else {
        res = idx;
    }

    return res;
}


static int fill_gain_ulaw(float gain, float linear_gain, int idx) {
    int val, res;

    if (gain) {
        val = (int) (((float) AST_MULAW(idx)) * linear_gain);
        if (val > 32767) val = 32767;
        if (val < -32767) val = -32767;
        res = AST_LIN2MU(val);
    } else {
        res = idx;
    }

    return res;
}


static int set_gain(struct ss7_chan *pvt, float rx_gain, float tx_gain) {

  struct dahdi_gains gain;
  float rx_linear_gain, tx_linear_gain;
  int res, i;

  memset(&gain, 0, sizeof(gain));
  gain.chan = 0;

  res = ioctl(pvt->zaptel_fd, DAHDI_GETGAINS, &gain);
  if (res) {
    ast_log(LOG_WARNING, "Failed to read gains: %s\n", strerror(errno));
    return -1;
  }

  rx_linear_gain = pow(10.0, rx_gain / 20.0);
  tx_linear_gain = pow(10.0, tx_gain / 20.0);

  switch (pvt->law) {
      case DAHDI_LAW_ALAW:
          /* Calculate receive-gain alaw-values */
          for (i = 0; i < (sizeof(gain.rxgain) / sizeof(gain.rxgain[0])); i++) {
              gain.rxgain[i] = fill_gain_alaw(rx_gain, rx_linear_gain, i);
          }

          /* Calculate transmit-gain alaw-values */
          for (i = 0; i < (sizeof(gain.txgain) / sizeof(gain.txgain[0])); i++) {
              gain.txgain[i] = fill_gain_alaw(tx_gain, tx_linear_gain, i);
          }

          break;

      case DAHDI_LAW_MULAW:
          /* Calculate receive-gain ulaw-values */
          for (i = 0; i < (sizeof(gain.rxgain) / sizeof(gain.rxgain[0])); i++) {
              gain.rxgain[i] = fill_gain_ulaw(rx_gain, rx_linear_gain, i);
          }

          /* Calculate transmit-gain ulaw-values */
          for (i = 0; i < (sizeof(gain.txgain) / sizeof(gain.txgain[0])); i++) {
              gain.txgain[i] = fill_gain_ulaw(tx_gain, tx_linear_gain, i);
          }

          break;
  }

  ast_log(LOG_DEBUG, "Configuring gain on cic %d (link %s) rxgain: %.1f  txgain: %.1f\n", 
                    pvt->cic, pvt->link->name, rx_gain, tx_gain);

  /* Set gain-config on one timeslot */
  res = ioctl(pvt->zaptel_fd, DAHDI_SETGAINS, &gain);
  if (res) {
    ast_log(LOG_WARNING, "Failed to set gains: %s\n", strerror(errno));
  }

  return res;
}


/* Initialize a struct ss7_chan. */
static void init_pvt(struct ss7_chan *pvt, struct link* link, int cic) {
  pvt->owner = NULL;
  pvt->next_idle = NULL;
  pvt->link = link;
  pvt->cic = cic;
  pvt->reset_done = 0;
  pvt->blocked = 0;
  pvt->equipped = 0;
  ast_mutex_init(&pvt->lock);
  pvt->state = ST_IDLE;
  pvt->zaptel_fd = -1;
  pvt->t1 = -1;
  pvt->t2 = -1;
  pvt->t5 = -1;
  pvt->t6 = -1;
  pvt->t7 = -1;
  pvt->t9 = -1;
  pvt->t12 = -1;
  pvt->t14 = -1;
  pvt->t16 = -1;
  pvt->t17 = -1;
  pvt->t18 = -1;
  pvt->t19 = -1;
  pvt->t20 = -1;
  pvt->t21 = -1;
  pvt->t22 = -1;
  pvt->t23 = -1;
  pvt->t35 = -1;

  memset(pvt->buffer, 0, sizeof(pvt->buffer));
  memset(&pvt->frame, 0, sizeof(pvt->frame));
  pvt->frame.frametype = AST_FRAME_VOICE;
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
  if (variant(pvt) == ANSI_SS7)
    pvt->frame.subclass = AST_FORMAT_ALAW;
  else
    pvt->frame.subclass = AST_FORMAT_ULAW;
#else
  if (variant(pvt) == ANSI_SS7) {
    pvt->frame.subclass.codec = AST_FORMAT_ULAW;
    pvt->law = DAHDI_LAW_MULAW;
  }
  else {
    pvt->frame.subclass.codec = AST_FORMAT_ALAW;
    pvt->law = DAHDI_LAW_ALAW;
  }
#endif
  pvt->frame.samples = AUDIO_READSIZE;
  pvt->frame.mallocd = 0;
  pvt->frame.src = NULL;
  AST_FRAME_SET_BUFFER(&pvt->frame, pvt->buffer, AST_FRIENDLY_OFFSET, AUDIO_READSIZE);
  pvt->sending_dtmf = 0;
  pvt->dsp = NULL;
  pvt->hangupcause = 0;
  pvt->dohangup = 0;
  pvt->echocan_start = 0;
  pvt->echocancel = 0;
  pvt->has_inband_ind = 0;
  pvt->charge_indicator = 0;
  pvt->is_digital = 0;
  pvt->grs_count = -1;
  pvt->cgb_mask = 0;
  memset(pvt->context, 0, sizeof(pvt->context));
  memset(pvt->language, 0, sizeof(pvt->language));
};

/* Deallocate any resources associated with a struct ss7_chan.
   Assumes that no other actions need to be taken (ie. no signalling). */
static void cleanup_pvt(struct ss7_chan *pvt) {
  if(pvt->owner != NULL) {
    ast_log(LOG_NOTICE, "pvt->owner non-NULL, while cleaning up pvt!\n");
  }
  if(pvt->zaptel_fd != -1) {
    close(pvt->zaptel_fd);
  }
  t1_clear(pvt);
  t2_clear(pvt);
  t5_clear(pvt);
  t6_clear(pvt);
  t7_clear(pvt);
  t9_clear(pvt);
  t16_clear(pvt);
  t17_clear(pvt);
  t18_clear(pvt);
  t19_clear(pvt);
  t20_clear(pvt);
  t21_clear(pvt);
  t22_clear(pvt);
  t23_clear(pvt);
  t35_clear(pvt);
  if(pvt->dsp != NULL) {
    ast_dsp_free(pvt->dsp);
  }
  free(pvt);
}

static int setup_cic(struct link* link, int channel)
{
  int cic = link->first_cic + channel;
  char* lang = link->linkset->language;
  char* ctxt = link->linkset->context;
  int features,x;
  struct ss7_chan *pvt;

  pvt = malloc(sizeof(*pvt));
  if(pvt == NULL) {
    ast_log(LOG_ERROR, "Out of memory allocating %zu bytes.\n", sizeof(*pvt));
    return -1;
  }
  init_pvt(pvt, link, cic);
  pvt->equipped = 1;
  if(ctxt != NULL) {
    ast_copy_string(pvt->context, ctxt, sizeof(pvt->context));
  }
  if(lang != NULL) {
    ast_copy_string(pvt->language, lang, sizeof(pvt->language));
  }

  pvt->blocked = link->linkset->blocked[cic];
  link->linkset->cic_list[cic] = pvt;
  add_to_idlelist(pvt);

  pvt->zaptel_fd = openchannel(link, channel);
  if (pvt->zaptel_fd < 0)
    return pvt->zaptel_fd < 0;
  features = DSP_FEATURE_DIGIT_DETECT;
#ifdef DAHDI_TONEDETECT
  x = DAHDI_TONEDETECT_ON | DAHDI_TONEDETECT_MUTE;
  if (ioctl(pvt->zaptel_fd, DAHDI_TONEDETECT, &x) == 0) {
    features = 0;
  }
#endif
  if(features){
    pvt->dsp = ast_dsp_new();
    if(pvt->dsp == NULL) {
      ast_log(LOG_WARNING, "Failed to allocate DSP for CIC=%d.\n", pvt->cic);
      return -1;
    }
    ast_dsp_set_features(pvt->dsp, DSP_FEATURE_DIGIT_DETECT);
#if defined(USE_ASTERISK_1_2) ||  defined(USE_ASTERISK_1_4)
    ast_dsp_digitmode(pvt->dsp, DSP_DIGITMODE_DTMF | (link->relaxdtmf ? DSP_DIGITMODE_RELAXDTMF : 0));
#else
    ast_dsp_set_digitmode(pvt->dsp, DSP_DIGITMODE_DTMF | (link->relaxdtmf ? DSP_DIGITMODE_RELAXDTMF : 0));
#endif
  }
  /* Set gain - Channel must be in audiomode when setting gain */
  set_audiomode(pvt->zaptel_fd);
  set_gain(pvt, link->rxgain, link->txgain);
  clear_audiomode(pvt->zaptel_fd);

  return 0;
}

static void isup_event_handler(struct mtp_event* event)
{
  struct mtp_req* req = (struct mtp_req*) event;
  struct isup_msg isup_msg;
  struct linkset* linkset;
  struct ss7_chan *pvt;
  int cic, dpc = 0;
  int res;

  if (event->typ == MTP_EVENT_ISUP) {
    res = decode_isup_msg(&isup_msg, event->isup.slink->linkset->variant, event->buf, event->len);
    dpc = isup_msg.opc;
  }
  else if (event->typ == MTP_REQ_ISUP_FORWARD) {
    res = decode_isup_msg(&isup_msg, req->isup.slink->linkset->variant, req->buf, req->len);
    dpc = isup_msg.dpc;
  }
  else {
    ast_log(LOG_ERROR, "Invalid event/request: %d\n", event->typ);
    return;
  }
  cic = isup_msg.cic;
  if(!res) {
    /* Q.764 (2.9.5): Discard invalid message.*/
    ast_log(LOG_NOTICE, "ISUP decoding error, message discarded (typ=%d).\n", isup_msg.typ);
    return;
  }
  lock_global();
  if ((linkset = find_linkset_for_dpc(dpc, cic)) == NULL) {
    ast_log(LOG_ERROR, "No linkset for for ISUP event, typ=%s, cic=%d, pc=%d eventtyp=%d\n", isupmsg(isup_msg.typ), cic, dpc, event->typ);
    unlock_global();
    return;
  }
  pvt = find_pvt_with_pc(linkset->links[0], cic, isup_msg.opc);
  ast_log(LOG_DEBUG, "Got ISUP event, typ=%s, cic=%d, dpc=%d, linkset=%s, pvt=0x%08lx, pvt.eq=%d \n", isupmsg(isup_msg.typ), cic, dpc, linkset->name, (unsigned long int) pvt, pvt ? pvt->equipped : -1);
  unlock_global();

  if (!pvt)
    return;
  if (event->typ == MTP_EVENT_ISUP) {
    if(pvt->equipped || (isup_msg.typ == ISUP_CGA) || (isup_msg.typ == ISUP_CUA) || (isup_msg.typ == ISUP_GRA)) {
      process_isup_message(pvt->link, &isup_msg);
    }
  }
  else {
    ast_log(LOG_DEBUG, "Forward ISUP event %s, CIC=%d, len=%d\n", isupmsg(isup_msg.typ), cic, req->len);
    mtp_enqueue_isup_forward(pvt, req->buf, req->len);
  }
}

static void isup_block_handler(struct link* link)
{
  int sup_type_ind = 0x01; /* Hardware failure oriented */
  
  ast_log(LOG_DEBUG, "ISUP block firstcic=%d, mask=0x%08lx \n", link->first_cic, link->channelmask);
  do_group_circuit_block_unblock(link->linkset, link->first_cic, link->channelmask, sup_type_ind, 0, 1, 1);
}

void l4isup_inservice(struct link* link)
{
  struct linkset* linkset = link->linkset;
  if (!mtp_send_fifo)
    mtp_send_fifo = mtp_get_send_fifo();
  if (!linkset->init_grs_done) {
    send_init_grs(linkset);
    linkset->init_grs_done = 1;
  }
  /* ToDo: maybe also need a reset if all links are down for
     an extended period of time? */
}


void l4isup_event(struct mtp_event* event)
{
  struct isup_msg isup_msg;
  int res;

  res = decode_isup_msg(&isup_msg, event->isup.slink->linkset->variant, event->buf, event->len);
  if(!res) {
    /* Q.764 (2.9.5): Discard invalid message.*/
    ast_log(LOG_NOTICE, "ISUP decoding error, message discarded. (typ=%d)\n", isup_msg.typ);
  } else {
    struct ss7_chan* pvt = find_pvt_with_pc(event->isup.slink, isup_msg.cic, isup_msg.opc);
    {
      ast_log(LOG_WARNING, "Received %s (CIC %d), link '%s'.\n", isupmsg(isup_msg.typ), isup_msg.cic, event->isup.slink->name);
    }

    if (pvt) {
      if(pvt->equipped)
	process_isup_message(pvt->link, &isup_msg);
      else
	proxy_process_isup_message(pvt->link, &isup_msg, event->buf, event->len);
    }
    else {
      if (isup_msg.typ != ISUP_UEC)
	isup_send_unequipped(event->isup.slink, isup_msg.cic, isup_msg.opc);
      ast_log(LOG_WARNING, "Received CIC=%d for unequipped circuit (typ=%s), link '%s'.\n", isup_msg.cic, isupmsg(isup_msg.typ), event->isup.slink->name);
    }
  }
}


int isup_init(void) {
  int i, l;

  /* Configure CIC ranges, specified in 'channel' lines. */
  ast_log(LOG_DEBUG, "Spans %d, host %s \n", this_host->n_spans, this_host->name);
  for (i = 0; i < this_host->n_spans; i++) {
    ast_log(LOG_DEBUG, "Span %d, links %d, host %s \n", i+1, this_host->spans[i].n_links, this_host->name);
    for (l = 0; l < this_host->spans[i].n_links; l++) {
      struct link* link = this_host->spans[i].links[l];
      int connector = this_host->spans[i].connector;
      int firstcic = link->first_cic;
      int c;
      if (!link->enabled)
	continue;
      ast_log(LOG_DEBUG, "New CICs, span %d, link %d, first_zapid %d, channelmask 0x%08lx, connector %d, firstcic %d, schannel 0x%08ux \n", i+1, l+1, link->first_zapid, link->channelmask, connector, firstcic, link->schannel.mask);
      for (c = 0; c < 31; c++) {
	if (link->channelmask & (1 << c)) {
	  int cic = firstcic + c;
	  /* channel to zap id mapping:
	     1 -> 1, 2 -> 2, 3 -> 3, ...
	     32-> none
	     33 -> 32, 34 -> 33, 35 -> 34, ...
	     64-> none
	     65 -> 63, 66 -> 64, 67 -> 65, ...
	     96-> none
	     97 -> 94, 98 -> 95, 99 -> 96, ...
	     128-> none */
	  if ((1<<c) & link->schannel.mask) {
	    ast_log(LOG_ERROR, "Error: Zap channel %d is used for SS7 signalling, "
		    "hence cannot be allocated for a CIC.\n", c+1);
	    return -1;
	  }
	  if(link->linkset->cic_list[cic] != NULL) {
	    ast_log(LOG_ERROR, "Overlapping CIC=%d, aborting.\n", cic);
	    return -1;
	  }            
	  if(setup_cic(link, c)) {
	    return -1;
	  }
	}
      }
    }
  }

  /* Configure all links that are on our linksets */
  for (i = 0; i < this_host->n_spans; i++) {
    for (l = 0; l < this_host->spans[i].n_links; l++) {
      struct linkset* slinkset = this_host->spans[i].links[l]->linkset;
      int lsi;
      for (lsi = 0; lsi < n_linksets; lsi++) {
	struct linkset* linkset = &linksets[lsi];
	if (is_combined_linkset(slinkset, linkset)) {
	  int li;
	  for(li = 0; li < linkset->n_links; li++) {
	    struct link* link = linkset->links[li];
	    int c;
	    for (c = 0; c < 32; c++) {
	      int cic = link->first_cic + c;
	      struct ss7_chan* pvt;
	      if (linkset->cic_list[cic])
		continue;
	      if (link->channelmask & (1 << c)) {
		pvt = malloc(sizeof(*pvt));
		if(pvt == NULL) {
		  ast_log(LOG_ERROR, "Out of memory allocating %zu bytes.\n", sizeof(*pvt));
		  return -1;
		}
		init_pvt(pvt, link, cic);
		ast_log(LOG_DEBUG, "Configuring peers CIC %d on linkset '%s'\n", cic, linkset->name);
		linkset->cic_list[cic] = pvt;
		pvt->equipped = 0;
	      }
	    }
	  }
	}
      }
    }
  }

#ifdef MODULETEST
  {
    int lsi;
    moduletest_init();
    for (lsi = 0; lsi < n_linksets; lsi++) {
      struct linkset* linkset = &linksets[lsi];
      for(i = linkset->first_cic; i <= linkset->last_cic; i++) {
	struct ss7_chan* pvt = linkset->cic_list[i];
	if (pvt)
	  pvt->reset_done = 1;
      }
    }
  }
#else
  if(cluster_init(isup_event_handler, isup_block_handler)) {
    ast_log(LOG_ERROR, "Unable to initialize cluster.\n");
    return -1;
  }


#endif

  if(start_continuity_check_thread()) {
    ast_log(LOG_ERROR, "Unable to start continuity check thread.\n");
    return -1;
  }

  if(ast_channel_register(&ss7_tech)) {
    ast_log(LOG_ERROR, "Unable to register channel class %s\n", type);
    return -1;
  }

  return 0;
}

int isup_cleanup(void) {
  int lsi, i;

  ast_channel_unregister(&ss7_tech);
  lock_global();

  for (lsi = 0; lsi < n_linksets; lsi++) {
    struct linkset* linkset = &linksets[lsi];
    for(i = 0; i < MAX_CIC; i++) {
      struct ss7_chan* pvt = linkset->cic_list[i];
      if (pvt) {
	ast_mutex_lock(&pvt->lock);
	if (pvt->state != ST_IDLE) {
	  struct ast_channel* chan = pvt->owner;
	  if (chan) {
	    request_hangup(chan, AST_CAUSE_PRE_EMPTED);
	    chan->tech_pvt = NULL;
	    pvt->owner = NULL;
	  }
	  release_circuit(pvt);
	}
	ast_mutex_unlock(&pvt->lock);
	cleanup_pvt(pvt);
	linkset->cic_list[i] = NULL;
      }
    }
    linkset->idle_list = NULL;
  }
  unlock_global();

  stop_continuity_check_thread();

  cluster_cleanup();

  return 0;
}
