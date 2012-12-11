/*  cli.c - chan_ss7/mtp3d cli interface
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


#include "asterisk.h"
#include "asterisk/channel.h"
#include "asterisk/cli.h"
#include "asterisk/lock.h"

#include "astversion.h"
#include "config.h"
#include "cli.h"
#include "utils.h"
#include "mtp3io.h"
#include "mtp.h"
#include "l4isup.h"
#include "cluster.h"
#include "dump.h"


static int cmd_version(int fd, int argc, argv_type argv);
static int cmd_dump_status(int fd, int argc, argv_type argv);
static int cmd_dump_stop(int fd, int argc, argv_type argv);
static int cmd_dump_start(int fd, int argc, argv_type argv);
static char *complete_dump_stop(const char *line, const char *word, int pos, int state);
static char *complete_dump_start(const char *line, const char *word, int pos, int state);
static int cmd_link_up(int fd, int argc, argv_type argv);
static int cmd_link_down(int fd, int argc, argv_type argv);
static int cmd_link_status(int fd, int argc, argv_type argv);
static int cmd_ss7_status(int fd, int argc, argv_type argv);

static char *complete_null(const char *line, const char *word, int pos, int state)
{
  return NULL;
}


static int cmd_show_channels(int fd, int argc, argv_type argv)
{
  return cmd_linestat(fd, argc, argv);
}

#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4)

#define CLI_ENT(cmd) {{"ss7", syntx_cmd_##cmd, NULL}, cmd_##cmd, brief_cmd_##cmd, usage_cmd_##cmd descr_cmd_##cmd, compl_cmd_##cmd}
#define cli_handler(cmd)
#else

#define CLI_ENT(cmd) {				\
  .cmda = {"ss7", syntx_cmd_##cmd, NULL},			\
      .summary =  brief_cmd_##cmd,			\
	 .usage = (usage_cmd_##cmd descr_cmd_##cmd),	\
	 .handler = handle_##cmd,			\
}

#if defined(USE_ASTERISK_1_6)
#define cli_handler(cmd) \
  static char *handle_##cmd(struct ast_cli_entry *e, int clicmd, struct ast_cli_args *a) \
  {									\
    static char buf[100];				\
    char* const syntax[] = {"ss7", syntx_cmd_##cmd,NULL};		\
  switch(clicmd) {					\
  case CLI_INIT: ast_join(buf, sizeof(buf), syntax); e->command = buf; return NULL; \
  case CLI_GENERATE:  return compl_cmd_##cmd(a->line, a->word, a->pos, a->n); \
 }\
  return  (char*) (long) cmd_##cmd(a->fd, a->argc, a->argv);	\
  }
#else
#define cli_handler(cmd) \
  static char *handle_##cmd(struct ast_cli_entry *e, int clicmd, struct ast_cli_args *a) \
  {									\
    static char buf[100];				\
    const char* syntax[] = {"ss7", syntx_cmd_##cmd,NULL};		\
  switch(clicmd) {					\
  case CLI_INIT: ast_join(buf, sizeof(buf), syntax); e->command = buf; return NULL; \
  case CLI_GENERATE:  return compl_cmd_##cmd(a->line, a->word, a->pos, a->n); \
 }\
  return  (char*) (long) cmd_##cmd(a->fd, a->argc, a->argv);	\
  }
#endif
#endif


#define syntx_cmd_version "version" 
#define brief_cmd_version "Show current version of chan_ss7"
#define usage_cmd_version "Usage: ss7 version\n"
#define descr_cmd_version ""
#define compl_cmd_version complete_null
cli_handler(version)

#define syntx_cmd_dump_start "dump", "start" 
#define brief_cmd_dump_start "Start MTP2 dump to a file"
#define usage_cmd_dump_start "Usage: ss7 dump start <file> [in|out|both] [fisu] [lssu] [msu]\n"
#define descr_cmd_dump_start "       Start mtp2 dump to file. Either incoming, outgoing, or both(default).\n" \
"       Optionally specify which of fisu, lssu, and msu should be dumped.\n" \
"       The output is in PCAP format (can be read by wireshark).\n"
#define compl_cmd_dump_start complete_dump_start
cli_handler(dump_start)

#define syntx_cmd_dump_stop "dump", "stop" 
#define brief_cmd_dump_stop "Stop a running MTP2 dump"
#define usage_cmd_dump_stop "Usage: ss7 dump stop [in|out|both]\n"
#define descr_cmd_dump_stop "       Stop mtp2 dump started with \"ss7 start dump\". Either incoming,\n" \
"       outgoing, or both(default).\n"
#define compl_cmd_dump_stop complete_dump_stop
cli_handler(dump_stop)

#define syntx_cmd_dump_status "dump", "status" 
#define brief_cmd_dump_status "Stop what dumps are running"
#define usage_cmd_dump_status "Usage: ss7 dump status\n"
#define descr_cmd_dump_status ""
#define compl_cmd_dump_status complete_null
cli_handler(dump_status)

#define syntx_cmd_link_down "link", "down" 
#define brief_cmd_link_down "Stop the MTP2 link(s) [logical-link-no]..."
#define usage_cmd_link_down "Usage: ss7 link down [logical-link-no]\n"
#define descr_cmd_link_down "       Take the link(s) down it will be down until started explicitly with\n" \
"       'ss7 link up'.\n" \
"       Until then, it will continuously transmit LSSU 'OS' (out-of-service)\n" \
"       frames.\n" \
"       If no logical-link-no argument is given, all links are affected.\n"
#define compl_cmd_link_down complete_null
cli_handler(link_down)

#define syntx_cmd_link_up "link", "up" 
#define brief_cmd_link_up "Start the MTP2 link(s) [logical-link-no]..."
#define usage_cmd_link_up "Usage: ss7 link up\n"
#define descr_cmd_link_up "       Attempt to take the MTP2 link(s) up with the initial alignment procedure.\n" \
"       If no logical-link-no argument is given, all links are affected.\n"
#define compl_cmd_link_up complete_null
cli_handler(link_up)

#define syntx_cmd_link_status "link", "status" 
#define brief_cmd_link_status "Show status of the MTP2 links"
#define usage_cmd_link_status "Usage: ss7 link status\n"
#define descr_cmd_link_status "       Show the status of the MTP2 links.\n"
#define compl_cmd_link_status complete_null
cli_handler(link_status)

#define syntx_cmd_block "block" 
#define brief_cmd_block "Set circuits in local maintenance blocked mode"
#define usage_cmd_block "Usage: ss7 block <first> <count> [<linksetname>]\n"
#define descr_cmd_block "       Set <count> lines into local maintenance blocked mode, starting at circuit <first>on linkset <linksetname>\n"
#define compl_cmd_block complete_null
cli_handler(block)

#define syntx_cmd_unblock "unblock" 
#define brief_cmd_unblock "Remove local maintenance blocked mode from circuits"
#define usage_cmd_unblock "Usage: ss7 unblock <first> <count> [<linksetname>]\n"
#define descr_cmd_unblock "       Remove <count> lines from local maintenance blocked mode, starting at circuit <first> on linkset <linksetname>.\n"
#define compl_cmd_unblock complete_null
cli_handler(unblock)

#define syntx_cmd_linestat "linestat" 
#define brief_cmd_linestat "Show line states"
#define usage_cmd_linestat "Usage: ss7 linestat\n"
#define descr_cmd_linestat "       Show status for all circuits.\n"
#define compl_cmd_linestat complete_null
cli_handler(linestat)

#define syntx_cmd_show_channels "show", "channels" 
#define brief_cmd_show_channels "Show line states"
#define usage_cmd_show_channels "Usage: ss7 linestat\n"
#define descr_cmd_show_channels "       Show status for all circuits.\n"
#define compl_cmd_show_channels complete_null
cli_handler(show_channels)

#define syntx_cmd_cluster_start "cluster", "start" 
#define brief_cmd_cluster_start "Start cluster"
#define usage_cmd_cluster_start "Usage: ss7 cluster start\n"
#define descr_cmd_cluster_start "       Start the cluster.\n"
#define compl_cmd_cluster_start complete_null
cli_handler(cluster_start)

#define syntx_cmd_cluster_stop "cluster", "stop" 
#define brief_cmd_cluster_stop "Stop cluster"
#define usage_cmd_cluster_stop "Usage: ss7 cluster stop\n"
#define descr_cmd_cluster_stop "       Stop the cluster.\n"
#define compl_cmd_cluster_stop complete_null
cli_handler(cluster_stop)

#define syntx_cmd_cluster_status "cluster", "status" 
#define brief_cmd_cluster_status "Show status of the cluster"
#define usage_cmd_cluster_status "Usage: ss7 cluster status\n"
#define descr_cmd_cluster_status "       Show the status of the cluster.\n"
#define compl_cmd_cluster_status complete_null
cli_handler(cluster_status)

#define syntx_cmd_reset "reset" 
#define brief_cmd_reset "Reset all circuits"
#define usage_cmd_reset "Usage: ss7 reset\n"
#define descr_cmd_reset "       Reset all circuits.\n"
#define compl_cmd_reset complete_null
cli_handler(reset)

#define syntx_cmd_mtp_data "mtp", "data" 
#define brief_cmd_mtp_data "Copy hex encoded string to MTP"
#define usage_cmd_mtp_data "Usage: ss7 mtp data string\n"
#define descr_cmd_mtp_data "       Copy hex encoded string to MTP"
#define compl_cmd_mtp_data complete_null
cli_handler(mtp_data)

#define syntx_cmd_ss7_status "status" 
#define brief_cmd_ss7_status "Show status of ss7"
#define usage_cmd_ss7_status "Usage: ss7 status\n"
#define descr_cmd_ss7_status "       Show status/statistics of ss7"
#define compl_cmd_ss7_status complete_null
cli_handler(ss7_status)

#define syntx_cmd_testfailover "testfailover" 
#define brief_cmd_testfailover "Test the failover mechanism"
#define usage_cmd_testfailover "Usage: ss7 testfailover"
#define descr_cmd_testfailover "       Test the failover mechanism.\n"
#define compl_cmd_testfailover complete_null
cli_handler(testfailover)

#ifdef MODULETEST
#define syntx_cmd_moduletest "moduletest"
#define brief_cmd_moduletest "Run a moduletest"
#define usage_cmd_moduletest "Usage: ss7 moduletest <no>"
#define descr_cmd_moduletest "       Run moduletest <no>.\n"
#define compl_cmd_moduletest complete_null
cli_handler(moduletest)
#endif

struct ast_cli_entry my_clis[] = {
  CLI_ENT(version),
  CLI_ENT(dump_start),
  CLI_ENT(dump_stop),
  CLI_ENT(dump_status),
  CLI_ENT(link_down),
  CLI_ENT(link_up),
  CLI_ENT(link_status),
  CLI_ENT(block),
  CLI_ENT(unblock),
  CLI_ENT(linestat),
  CLI_ENT(show_channels),
  CLI_ENT(cluster_start),
  CLI_ENT(cluster_stop),
  CLI_ENT(cluster_status),
  CLI_ENT(reset),
  CLI_ENT(mtp_data),
  CLI_ENT(ss7_status),
#ifdef MODULETEST
  CLI_ENT(testfailover),
#if 0
  CLI_ENT(moduletest),
#endif
#endif
};







static int cmd_link_up_down(int fd, int argc, argv_type argv, int updown) {
  static unsigned char buf[sizeof(struct mtp_req)];
  struct mtp_req *req = (struct mtp_req *)buf;
  int i;

  req->typ = updown;
  req->len = sizeof(req->link);
  if(argc > 3) {
    for (i = 3; i < argc; i++) {
      int linkix = atoi(argv[i]);
      ast_log(LOG_DEBUG, "MTP control link %s %d\n", updown == MTP_REQ_LINK_UP ? "up" : "down", linkix);
      req->link.linkix = linkix;
      req->link.keepdown = 1;
      mtp_enqueue_control(req);
    }
  }
  else {
    for (i=0; i < this_host->n_slinks; i++) {
      ast_log(LOG_DEBUG, "MTP control link %s %d\n", updown == MTP_REQ_LINK_UP ? "up" : "down", i);
      req->link.linkix = i;
      req->link.keepdown = 1;
      mtp_enqueue_control(req);
    }
  }
  return RESULT_SUCCESS;
}


static int cmd_link_down(int fd, int argc, argv_type argv) {
  return cmd_link_up_down(fd, argc, argv, MTP_REQ_LINK_DOWN);
}


static int cmd_link_up(int fd, int argc, argv_type argv) {
  return cmd_link_up_down(fd, argc, argv, MTP_REQ_LINK_UP);
}


static int cmd_link_status(int fd, int argc, argv_type argv) {
  char buff[8192];
  int i;

  for (i = 0; i < this_host->n_slinks; i++) {
    if (cmd_mtp_linkstatus(buff, argc>3, i) == 0)
      ast_cli(fd, "%s", buff);
  }
  return RESULT_SUCCESS;
}

static char *complete_generic(const char *word, int state, char **options, int entries) {
  int which = 0;
  int i;

  for(i = 0; i < entries; i++) {
    if(0 == strncasecmp(word, options[i], strlen(word))) {
      if(++which > state) {
        return strdup(options[i]);
      }
    }
  }
  return NULL;
}

static char *dir_options[] = { "in", "out", "both", };
static char *filter_options[] = { "fisu", "lssu", "msu", };

static char *complete_dump_start(const char *line, const char *word, int pos, int state)
{
  if(pos == 4) {
    return complete_generic(word, state, dir_options,
                            sizeof(dir_options)/sizeof(dir_options[0]));
  } else if(pos > 4) {
    return complete_generic(word, state, filter_options,
                            sizeof(filter_options)/sizeof(filter_options[0]));
  } else {
    /* We won't attempt to complete file names, that's not worth it. */
    return NULL;
  }
}

static char *complete_dump_stop(const char *line, const char *word, int pos, int state)
{
  if(pos == 3) {
    return complete_generic(word, state, dir_options,
                            sizeof(dir_options)/sizeof(dir_options[0]));
  } else {
    return NULL;
  }
}

static int cmd_dump_start(int fd, int argc, argv_type argv) {
  int in, out;
  int i;
  int fisu,lssu,msu;

  if(argc < 4) {
    return RESULT_SHOWUSAGE;
  }

  if(argc == 4) {
    in = 1;
    out = 1;
  } else {
    if(0 == strcasecmp(argv[4], "in")) {
      in = 1;
      out = 0;
    } else if(0 == strcasecmp(argv[4], "out")) {
      in = 0;
      out = 1;
    } else if(0 == strcasecmp(argv[4], "both")) {
      in = 1;
      out = 1;
    } else {
      return RESULT_SHOWUSAGE;
    }
  }

  if(argc <= 5) {
    fisu = 0;
    lssu = 0;
    msu = 1;
  } else {
    fisu = 0;
    lssu = 0;
    msu = 0;
    for(i = 5; i < argc; i++) {
      if(0 == strcasecmp(argv[i], "fisu")) {
        fisu = 1;
      } else if(0 == strcasecmp(argv[i], "lssu")) {
        lssu = 1;
      } else if(0 == strcasecmp(argv[i], "msu")) {
        msu = 1;
      } else {
        return RESULT_SHOWUSAGE;
      }
    }
  }
  init_dump(fd, argv[3], in, out, fisu, lssu, msu);
  return RESULT_SUCCESS;
}

static int cmd_dump_stop(int fd, int argc, argv_type argv) {
  int in, out;

  if(argc == 3) {
    in = 1;
    out = 1;
  } else if(argc == 4) {
    if(0 == strcasecmp(argv[3], "in")) {
      in = 1;
      out = 0;
    } else if(0 == strcasecmp(argv[3], "out")) {
      in = 0;
      out = 1;
    } else if(0 == strcasecmp(argv[3], "both")) {
      in = 1;
      out = 1;
    } else {
      return RESULT_SHOWUSAGE;
    }
  } else {
    return RESULT_SHOWUSAGE;
  }
  cleanup_dump(fd, in, out);
  return RESULT_SUCCESS;
}

static int cmd_dump_status(int fd, int argc, argv_type argv)
{
  dump_status(fd);
  return RESULT_SUCCESS;
}


static int cmd_version(int fd, int argc, argv_type argv)
{
  ast_cli(fd, "chan_ss7 version %s\n", CHAN_SS7_VERSION);

  return RESULT_SUCCESS;
}


static int cmd_ss7_status(int fd, int argc, argv_type argv)
{
  cmd_linkset_status(fd, argc, argv);
  return RESULT_SUCCESS;
}







void cli_register(void)
{
  ast_cli_register_multiple(my_clis, sizeof(my_clis)/ sizeof(my_clis[0]));
}

void cli_unregister(void)
{
  ast_cli_unregister_multiple(my_clis, sizeof(my_clis)/ sizeof(my_clis[0]));
}

void cli_handle(int fd, char* cmd)
{
  char* p;
  int argc = 1;
  char* argv[10] = {"ss7", };
  int i, j, res;
  char* result = "command not understood\n";

  p = strsep(&cmd, "\n");
  while (p && *p) {
    argv[argc++] = p;
    p = strsep(&cmd, "\n");
  }
  for (i = 0; i < sizeof(my_clis) / sizeof(my_clis[0]); i++) {
    int found = 1;
    for (j = 1; my_clis[i].cmda[j]; j++) {
      if (!argv[j] || strcmp(my_clis[i].cmda[j], argv[j])) {
	found = 0;
	break;
      }
    }
    if (found) {
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4)
      my_clis[i].handler(fd, argc, argv);
#else
      struct ast_cli_args a;
      *(int*) &a.fd = fd;
      *(int*) &a.argc = argc;
      a.argv = argv;
      my_clis[i].handler(&my_clis[i], CLI_HANDLER, &a);
#endif
      return;
    }
  }
  res = write(fd, result, strlen(result));
}
