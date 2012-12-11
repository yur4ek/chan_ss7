/* dump.c - chan_ss7/mtp3d dump
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
#include "mtp3io.h"
#include "mtp.h"
#include "dump.h"


/* State for dumps. */
AST_MUTEX_DEFINE_STATIC(dump_mutex);
static FILE *dump_in_fh = NULL;
static FILE *dump_out_fh = NULL;
static int dump_do_fisu, dump_do_lssu, dump_do_msu;


static void dump_pcap(FILE *f, struct mtp_event *event)
{
  unsigned int sec  = event->dump.stamp.tv_sec;
  unsigned int usec  = event->dump.stamp.tv_usec - (event->dump.stamp.tv_usec % 1000) +
    event->dump.sls*2 + /* encode link number in usecs */
    event->dump.out /* encode direction in/out */;
  int res;

  res = fwrite(&sec, sizeof(sec), 1, f);
  res = fwrite(&usec, sizeof(usec), 1, f);
  res = fwrite(&event->len, sizeof(event->len), 1, f); /* number of bytes of packet in file */
  res = fwrite(&event->len, sizeof(event->len), 1, f); /* actual length of packet */
  res = fwrite(event->buf, 1, event->len, f);
  fflush(f);
}

int dump_enabled(struct mtp_event *event)
{
  FILE *dump_fh;

  if(event->dump.out) {
    dump_fh = dump_out_fh;
  } else {
    dump_fh = dump_in_fh;
  }

  if(dump_fh != NULL) {
    if(event->len < 3 ||
       ( !(event->buf[2] == 0 && !dump_do_fisu) &&
	 !((event->buf[2] == 1 || event->buf[2] == 2) && !dump_do_lssu) &&
	 !(event->buf[2] > 2 && !dump_do_msu)))
      return 1;
  }
  return 0;
}

void dump_event(struct mtp_event *event)
{
  FILE *dump_fh;

  ast_mutex_lock(&dump_mutex);

  if(event->dump.out) {
    dump_fh = dump_out_fh;
  } else {
    dump_fh = dump_in_fh;
  }
  if (dump_enabled(event))
      dump_pcap(dump_fh, event);
  ast_mutex_unlock(&dump_mutex);
}

static void init_pcap_file(FILE *f)
{
  unsigned int magic = 0xa1b2c3d4;  /* text2pcap does this */
  unsigned short version_major = 2;
  unsigned short version_minor = 4;
  unsigned int thiszone = 0;
  unsigned int sigfigs = 0;
  unsigned int snaplen = 102400;
  unsigned int linktype = 140;
  int res;

  res = fwrite(&magic, sizeof(magic), 1, f);
  res = fwrite(&version_major, sizeof(version_major), 1, f);
  res = fwrite(&version_minor, sizeof(version_minor), 1, f);
  res = fwrite(&thiszone, sizeof(thiszone), 1, f);
  res = fwrite(&sigfigs, sizeof(sigfigs), 1, f);
  res = fwrite(&snaplen, sizeof(snaplen), 1, f);
  res = fwrite(&linktype, sizeof(linktype), 1, f);
}


int init_dump(int fd, const char* fn, int in, int out, int fisu, int lssu, int msu)
{
  FILE *fh;

  ast_mutex_lock(&dump_mutex);
  if((in && dump_in_fh != NULL) || (out && dump_out_fh != NULL)) {
    ast_cli(fd, "Dump already running, must be stopped (with 'ss7 stop dump') "
            "before new can be started.\n");
    ast_mutex_unlock(&dump_mutex);
    return RESULT_FAILURE;
  }


  fh = fopen(fn, "w");
  if(fh == NULL) {
    ast_cli(fd, "Error opening file '%s': %s.\n", fn, strerror(errno));
    ast_mutex_unlock(&dump_mutex);
    return RESULT_FAILURE;
  }

  if(in) {
    dump_in_fh = fh;
  }
  if(out) {
    dump_out_fh = fh;
  }
  dump_do_fisu = fisu;
  dump_do_lssu = lssu;
  dump_do_msu = msu;
  init_pcap_file(fh);


  ast_mutex_unlock(&dump_mutex);
  return 0;
}


void cleanup_dump(int fd, int in, int out)
{
  ast_mutex_lock(&dump_mutex);

  if((in && !out && dump_in_fh == NULL) ||
     (out && !in && dump_out_fh == NULL) ||
     (in && out && dump_in_fh == NULL && dump_out_fh == NULL)) {
    if (fd)
      ast_cli(fd, "No dump running.\n");
    ast_mutex_unlock(&dump_mutex);
    return;
  }

  if(in && dump_in_fh != NULL) {
    if(dump_out_fh == dump_in_fh) {
      /* Avoid closing it twice. */
      dump_out_fh = NULL;
    }
    fclose(dump_in_fh);
    dump_in_fh = NULL;
  }
  if(out && dump_out_fh != NULL) {
    fclose(dump_out_fh);
    dump_out_fh = NULL;
  }
  ast_mutex_unlock(&dump_mutex);
}


void dump_status(int fd)
{
  ast_mutex_lock(&dump_mutex);

  /* ToDo: This doesn't seem to work, the output is getting lost somehow.
     Not sure why, but could be related to ast_carefulwrite() called in
     ast_cli(). */
  ast_cli(fd, "Yuck! what is going on here?!?\n");
  if(dump_in_fh != NULL) {
    ast_cli(fd, "Dump of incoming frames is running.\n");
  }
  if(dump_out_fh != NULL) {
    ast_cli(fd, "Dump of outgoing frames is running.\n");
  }
  if(dump_in_fh != NULL || dump_out_fh != NULL) {
    ast_cli(fd, "Filter:%s%s%s.\n",
            (dump_do_fisu ? " fisu" : ""),
            (dump_do_lssu ? " lssu" : ""),
            (dump_do_msu ? " msu" : ""));
  }

  ast_mutex_unlock(&dump_mutex);
}
