/* aststubs.c - asterisk stubs
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
#include <stdarg.h>
#include <stdlib.h>
#include <pthread.h>

#include "asterisk.h"
#define AST_API_MODULE
#include <asterisk/linkedlists.h>
#include <asterisk/time.h>

#define ast_config confstate
#include "astversion.h"
#include "aststubs.h"
#include "configparser.h"

int option_debug;
struct ast_cli_entry;

int option_verbose;
int option_debug;

char ast_config_AST_CONFIG_DIR[PATH_MAX];


#undef localtime_r
#undef pthread_mutex_init
#undef pthread_mutex_lock
#undef pthread_mutex_unlock
#undef pthread_mutex_t
#undef ast_calloc
#define ast_mutex_init(m) pthread_mutex_init(m,0)
#define ast_mutex_lock pthread_mutex_lock
#define ast_mutex_unlock pthread_mutex_unlock
#define ast_mutex_t pthread_mutex_t
#define ast_calloc calloc

//define DEBUG(x) {if (option_debug) x;}
#define DEBUG(x)


int ast_safe_system(const char *s);
void ast_register_file_version(const char *file, const char *version);
void ast_unregister_file_version(const char *file);
void ast_cli(int fd, const char *fmt, ...);

int ast_safe_system(const char *s)
{
  return -1;
}

void ast_register_file_version(const char *file, const char *version)
{
}

void ast_unregister_file_version(const char *file)
{
}

#ifdef USE_ASTERISK_1_6
int ast_cli_register_multiple(struct ast_cli_entry *e, int len)
{
  return 0;
}
int ast_cli_unregister_multiple(struct ast_cli_entry *e, int len)
{
  return 0;
}
#else
void ast_cli_register_multiple(struct ast_cli_entry *e, int len)
{
}
void ast_cli_unregister_multiple(struct ast_cli_entry *e, int len)
{
}
#endif

void ast_cli(int fd, const char *fmt, ...)
{
  char buff[10240];
  va_list ap;
  int res;

  va_start(ap, fmt);
  vsprintf(buff, fmt, ap);
  res = write(fd, buff, strlen(buff));
  if (res == -1) {
  }
}

void ast_log(int level, const char *file, int line, const char *function, const char *fmt, ...)
{
  va_list ap;
  char *l;
  time_t now;
  struct tm tm;
  char tbuff[64];
  char buff[1024];

  if ((level == __LOG_DEBUG) && !option_debug)
    return;
  switch (level) {
  case __LOG_DEBUG: l= "DEBUG"; break;
  case __LOG_EVENT: l= "EVENT"; break;
  case __LOG_NOTICE: l= "NOTICE"; break;
  case __LOG_WARNING: l= "WARNING"; break;
  case __LOG_ERROR: l= "ERROR"; break;
  default: l = "unknown";
  }
  time(&now);
  localtime_r(&now, &tm);
  strftime(tbuff, sizeof(tbuff), "%b %d %H:%M:%S", &tm);
  sprintf(buff, "%s [%s] %s:%d %s %s", tbuff, l, file, line, function, fmt);
  va_start(ap, fmt);
  vprintf(buff, ap);
  fflush(stdout);
}

void ast_verbose(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  fflush(stdout);
}


#ifndef AST_LIST_INSERT_BEFORE_CURRENT
/* Asterisk 1.2.x */
#define AST_LIST_INSERT_BEFORE_CURRENT(head, elm, field) do {		\
	if (__list_prev) {						\
		(elm)->field.next = __list_prev->field.next;		\
		__list_prev->field.next = elm;				\
	} else {							\
		(elm)->field.next = (head)->first;			\
		(head)->first = (elm);					\
	}								\
	__new_prev = (elm);						\
} while (0)
#endif

#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4)
#define AST_LIST_INSERT_BEFORE_CURRENT_C(head,elm,field) AST_LIST_INSERT_BEFORE_CURRENT(head,elm,field)
#define AST_LIST_REMOVE_CURRENT_C(head,field) AST_LIST_REMOVE_CURRENT(head,field)
#else
#define AST_LIST_INSERT_BEFORE_CURRENT_C(head,elm,field) AST_LIST_INSERT_BEFORE_CURRENT(elm,field)
#define AST_LIST_REMOVE_CURRENT_C(head,field) AST_LIST_REMOVE_CURRENT(field)
#endif
struct sched {
	AST_LIST_ENTRY(sched) list;
	int id;                       /*!< ID number of event */
	struct timeval when;          /*!< Absolute time event should take place */
	int resched;                  /*!< When to reschedule */
	int variable;                 /*!< Use return value from callback to reschedule */
	void *data;                   /*!< Data */
	ast_sched_cb callback;        /*!< Callback */
};

struct sched_context {
	ast_mutex_t lock;
	unsigned int eventcnt;                  /*!< Number of events processed */
	unsigned int schedcnt;                  /*!< Number of outstanding schedule events */
	AST_LIST_HEAD_NOLOCK(, sched) schedq;   /*!< Schedule entry and main queue */

#ifdef SCHED_MAX_CACHE
	AST_LIST_HEAD_NOLOCK(, sched) schedc;   /*!< Cache of unused schedule structures and how many */
	unsigned int schedccnt;
#endif
};

#define ONE_MILLION	1000000
static struct timeval tvfix(struct timeval a)
{
	if (a.tv_usec >= ONE_MILLION) {
		ast_log(LOG_WARNING, "warning too large timestamp %ld.%ld\n",
			a.tv_sec, (long int) a.tv_usec);
		a.tv_sec += a.tv_usec / ONE_MILLION;
		a.tv_usec %= ONE_MILLION;
	} else if (a.tv_usec < 0) {
		ast_log(LOG_WARNING, "warning negative timestamp %ld.%ld\n",
			a.tv_sec, (long int) a.tv_usec);
		a.tv_usec = 0;
	}
	return a;
}

struct timeval ast_tvadd(struct timeval a, struct timeval b)
{
	/* consistency checks to guarantee usec in 0..999999 */
	a = tvfix(a);
	b = tvfix(b);
	a.tv_sec += b.tv_sec;
	a.tv_usec += b.tv_usec;
	if (a.tv_usec >= ONE_MILLION) {
		a.tv_sec++;
		a.tv_usec -= ONE_MILLION;
	}
	return a;
}

struct sched_context *mtp_sched_context_create(void)
{
	struct sched_context *tmp;

	if (!(tmp = ast_calloc(1, sizeof(*tmp))))
		return NULL;

	ast_mutex_init(&tmp->lock);
	tmp->eventcnt = 1;
	
	return tmp;
}

void mtp_sched_context_destroy(struct sched_context *con)
{
	struct sched *s;

	ast_mutex_lock(&con->lock);

#ifdef SCHED_MAX_CACHE
	/* Eliminate the cache */
	while ((s = AST_LIST_REMOVE_HEAD(&con->schedc, list)))
		free(s);
#endif

	/* And the queue */
	while ((s = AST_LIST_REMOVE_HEAD(&con->schedq, list)))
		free(s);
	
	/* And the context */
	ast_mutex_unlock(&con->lock);
	ast_mutex_destroy(&con->lock);
	free(con);
}

static struct sched *sched_alloc(struct sched_context *con)
{
	struct sched *tmp;

	/*
	 * We keep a small cache of schedule entries
	 * to minimize the number of necessary malloc()'s
	 */
#ifdef SCHED_MAX_CACHE
	if ((tmp = AST_LIST_REMOVE_HEAD(&con->schedc, list)))
		con->schedccnt--;
	else
#endif
		tmp = ast_calloc(1, sizeof(*tmp));

	return tmp;
}

static void sched_release(struct sched_context *con, struct sched *tmp)
{
	/*
	 * Add to the cache, or just free() if we
	 * already have too many cache entries
	 */

#ifdef SCHED_MAX_CACHE	 
	if (con->schedccnt < SCHED_MAX_CACHE) {
		AST_LIST_INSERT_HEAD(&con->schedc, tmp, list);
		con->schedccnt++;
	} else
#endif
		free(tmp);
}

int mtp_sched_wait(struct sched_context *con)
{
	int ms;

	DEBUG(ast_log(LOG_DEBUG, "ast_sched_wait()\n"));

	ast_mutex_lock(&con->lock);
	if (AST_LIST_EMPTY(&con->schedq)) {
		ms = -1;
	} else {
		ms = ast_tvdiff_ms(AST_LIST_FIRST(&con->schedq)->when, ast_tvnow());
		if (ms < 0)
			ms = 0;
	}
	ast_mutex_unlock(&con->lock);

	return ms;
}


static void schedule(struct sched_context *con, struct sched *s)
{
	 
	struct sched *cur = NULL;
	
	AST_LIST_TRAVERSE_SAFE_BEGIN(&con->schedq, cur, list) {
		if (ast_tvcmp(s->when, cur->when) == -1) {
			AST_LIST_INSERT_BEFORE_CURRENT_C(&con->schedq, s, list);
			break;
		}
	}
	AST_LIST_TRAVERSE_SAFE_END
	if (!cur)
		AST_LIST_INSERT_TAIL(&con->schedq, s, list);
	
	con->schedcnt++;
}

static int sched_settime(struct timeval *tv, int when)
{
	struct timeval now = ast_tvnow();

	/*ast_log(LOG_DEBUG, "TV -> %lu,%lu\n", tv->tv_sec, tv->tv_usec);*/
	if (ast_tvzero(*tv))	/* not supplied, default to now */
		*tv = now;
	*tv = ast_tvadd(*tv, ast_samp2tv(when, 1000));
	if (ast_tvcmp(*tv, now) < 0) {
		ast_log(LOG_DEBUG, "Request to schedule in the past?!?!\n");
		*tv = now;
	}
	return 0;
}

static int ast_sched_add_variable(struct sched_context *con, int when, ast_sched_cb callback, void *data, int variable)
{
	struct sched *tmp;
	int res = -1;
	DEBUG(ast_log(LOG_DEBUG, "ast_sched_add()\n"));
	if (!when) {
		ast_log(LOG_NOTICE, "Scheduled event in 0 ms?\n");
		return -1;
	}
	ast_mutex_lock(&con->lock);
	if ((tmp = sched_alloc(con))) {
		tmp->id = con->eventcnt++;
		tmp->callback = callback;
		tmp->data = data;
		tmp->resched = when;
		tmp->variable = variable;
		tmp->when = ast_tv(0, 0);
		if (sched_settime(&tmp->when, when)) {
			sched_release(con, tmp);
		} else {
			schedule(con, tmp);
			res = tmp->id;
		}
	}
#ifdef DUMP_SCHEDULER
	/* Dump contents of the context while we have the lock so nothing gets screwed up by accident. */
	if (option_debug)
		ast_sched_dump(con);
#endif
	ast_mutex_unlock(&con->lock);
	return res;
}

int mtp_sched_add(struct sched_context *con, int when, ast_sched_cb callback, void *data)
{
	return ast_sched_add_variable(con, when, callback, data, 0);
}

int mtp_sched_del(struct sched_context *con, int id)
{
	struct sched *s;

	DEBUG(ast_log(LOG_DEBUG, "ast_sched_del()\n"));
	
	ast_mutex_lock(&con->lock);
	AST_LIST_TRAVERSE_SAFE_BEGIN(&con->schedq, s, list) {
		if (s->id == id) {
			AST_LIST_REMOVE_CURRENT_C(&con->schedq, list);
			con->schedcnt--;
			sched_release(con, s);
			break;
		}
	}
	AST_LIST_TRAVERSE_SAFE_END

#ifdef DUMP_SCHEDULER
	/* Dump contents of the context while we have the lock so nothing gets screwed up by accident. */
	if (option_debug)
		ast_sched_dump(con);
#endif
	ast_mutex_unlock(&con->lock);

	if (!s) {
		if (option_debug)
			ast_log(LOG_DEBUG, "Attempted to delete nonexistent schedule entry %d!\n", id);
#ifdef DO_CRASH
		CRASH;
#endif
		return -1;
	}
	
	return 0;
}

int mtp_sched_runq(struct sched_context *con)
{
	struct sched *current;
	struct timeval tv;
	int numevents;
	int res;

	DEBUG(ast_log(LOG_DEBUG, "ast_sched_runq()\n"));
		
	ast_mutex_lock(&con->lock);

	for (numevents = 0; !AST_LIST_EMPTY(&con->schedq); numevents++) {
		/* schedule all events which are going to expire within 1ms.
		 * We only care about millisecond accuracy anyway, so this will
		 * help us get more than one event at one time if they are very
		 * close together.
		 */
		tv = ast_tvadd(ast_tvnow(), ast_tv(0, 1000));
		if (ast_tvcmp(AST_LIST_FIRST(&con->schedq)->when, tv) != -1)
			break;
		
		current = AST_LIST_REMOVE_HEAD(&con->schedq, list);
		con->schedcnt--;

		/*
		 * At this point, the schedule queue is still intact.  We
		 * have removed the first event and the rest is still there,
		 * so it's permissible for the callback to add new events, but
		 * trying to delete itself won't work because it isn't in
		 * the schedule queue.  If that's what it wants to do, it 
		 * should return 0.
		 */
			
		ast_mutex_unlock(&con->lock);
		res = current->callback(current->data);
		ast_mutex_lock(&con->lock);
			
		if (res) {
		 	/*
			 * If they return non-zero, we should schedule them to be
			 * run again.
			 */
			if (sched_settime(&current->when, current->variable? res : current->resched)) {
				sched_release(con, current);
			} else
				schedule(con, current);
		} else {
			/* No longer needed, so release it */
		 	sched_release(con, current);
		}
	}

	ast_mutex_unlock(&con->lock);
	
	return numevents;
}


int ast_jb_read_conf(struct ast_jb_conf *conf, const char *varname, const char *value)
{
  return 0;
}


#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4)
struct ast_config* ast_config_load(const char* filename)
#else
struct ast_config* ast_config_load(const char* filename, struct ast_flags flags)
#endif
{
  struct confstate* c;
  int res;
  res = confinitparser(&c, ast_config_AST_CONFIG_DIR, filename);
  if (res < 0)
    return NULL;
  return c;
}

void ast_config_destroy(struct ast_config* cfg)
{
  confend(cfg);
}

const char* ast_category_browse(struct ast_config* cfg, const char* cat)
{
  return confnextsection(cfg);
}

struct ast_variable* ast_variable_browse(struct ast_config* cfg, const char* cat)
{
  const char* key;
  struct ast_variable* var;
  struct ast_variable* first = NULL;
  struct ast_variable* prev = NULL;
  while ((key = confnextkey(cfg)) != 0) {
    var = malloc(sizeof(*var));
    var->name = strdup(key);
    var->value = strdup(confgetvalue(cfg));
    if (prev)
      prev->next = var;
    else
      first = var;
    prev = var;
  }
  if (prev)
    prev->next = NULL;
  return first;
}


void ast_join(char* buf, int size, char* args[])
{
  int f = 1;
  *buf = 0;
  while (*args) {
    int l = strlen(*args);
    if (l < size) {
      if (!f++)
	strcat(buf, " ");
      strcat(buf, *args++);
    }
  }
}
