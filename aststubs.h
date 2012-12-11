/* aststubs.h - asterisk stubs
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


#include <stdio.h>
#include <pthread.h>

/* Log defines taken for asterisk/logger.h */
#define VERBOSE_PREFIX_1 " "
#define VERBOSE_PREFIX_2 "  == "
#define VERBOSE_PREFIX_3 "    -- "
#define VERBOSE_PREFIX_4 "       > "

#define _A_ __FILE__, __LINE__, __PRETTY_FUNCTION__

#ifdef LOG_DEBUG
#undef LOG_DEBUG
#endif
#define __LOG_DEBUG    0
#define LOG_DEBUG      __LOG_DEBUG, _A_

#ifdef LOG_EVENT
#undef LOG_EVENT
#endif
#define __LOG_EVENT    1
#define LOG_EVENT      __LOG_EVENT, _A_

#ifdef LOG_NOTICE
#undef LOG_NOTICE
#endif
#define __LOG_NOTICE   2
#define LOG_NOTICE     __LOG_NOTICE, _A_

#ifdef LOG_WARNING
#undef LOG_WARNING
#endif
#define __LOG_WARNING  3
#define LOG_WARNING    __LOG_WARNING, _A_

#ifdef LOG_ERROR
#undef LOG_ERROR
#endif
#define __LOG_ERROR    4
#define LOG_ERROR      __LOG_ERROR, _A_

#ifdef LOG_VERBOSE
#undef LOG_VERBOSE
#endif
#define __LOG_VERBOSE  5
#define LOG_VERBOSE    __LOG_VERBOSE, _A_

#ifdef LOG_DTMF
#undef LOG_DTMF
#endif
#define __LOG_DTMF  6
#define LOG_DTMF    __LOG_DTMF, _A_




extern char ast_config_AST_CONFIG_DIR[];
extern int option_debug;
struct ast_channel;

#undef ast_log
#undef ast_verbose
void ast_log(int level, const char *file, int line, const char *function, const char *fmt, ...)
  __attribute__ ((format (printf, 5, 6)));
void ast_verbose(const char *fmt, ...)
  __attribute__ ((format (printf, 1, 2)));

typedef int (*ast_sched_cb)(const void *data);
struct sched_context *mtp_sched_context_create(void);
void mtp_sched_context_destroy(struct sched_context *con);
int mtp_sched_add(struct sched_context *con, int when, ast_sched_cb callback, void *data);
int mtp_sched_del(struct sched_context *con, int id);
int mtp_sched_runq(struct sched_context *con);
int mtp_sched_wait(struct sched_context *con);
struct timeval ast_tvadd(struct timeval a, struct timeval b);

#ifndef AST_MUTEX_DEFINE_STATIC
#define AST_MUTEX_DEFINE_STATIC(mutex) pthread_mutex_t mutex;
#endif

#define ast_copy_string(a,b,c) snprintf(a, c, "%s", b)

struct ast_jb_conf {int flags; int max_size; int resync_threshold; char* impl;};

#define CONFIG_FLAG_NOCACHE
struct ast_flags { int flags;};
struct ast_variable {char* name; char* value; struct ast_variable* next;};
struct ast_config {struct ast_variable* first;};
#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4)
struct ast_config* ast_config_load(const char* filename);
#else
struct ast_config* ast_config_load(const char* filename, struct ast_flags flags);
#endif
void ast_config_destroy(struct ast_config* cfg);
const char* ast_category_browse(struct ast_config* cfg, const char* cat);
struct ast_variable* ast_variable_browse(struct ast_config* cfg, const char* cat);
int ast_jb_read_conf(struct ast_jb_conf *conf, const char *varname, const char *value);



struct ast_cli_entry;
#ifdef USE_ASTERISK_1_6
int ast_cli_register_multiple(struct ast_cli_entry *e, int len);
int ast_cli_unregister_multiple(struct ast_cli_entry *e, int len);
#else
void ast_cli_register_multiple(struct ast_cli_entry *e, int len);
void ast_cli_unregister_multiple(struct ast_cli_entry *e, int len);
#endif
void ast_join(char* buf, int size, char* args[]);
