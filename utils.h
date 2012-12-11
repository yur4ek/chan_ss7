/* utils.h - Handling of timers, locks, threads and stuff
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


int timers_wait(void);
int start_timer(int msec, int (*cb)(const void *), void *data);
void stop_timer(int tid);
void run_timers(void);
int timers_init(void);
int timers_cleanup(void);
void lock_global(void);
void unlock_global(void);
int start_thread(pthread_t* t, void* (*thread_main)(void*data), int* running, int prio);
void stop_thread(pthread_t* t, int* running);

const char* inaddr2s(struct in_addr addr);


static inline int timediff_usec(struct timeval t1, struct timeval t2)
{
  return (t1.tv_sec - t2.tv_sec) * 1000000 + (t1.tv_usec - t2.tv_usec);
}

static inline int timediff_msec(struct timeval t1, struct timeval t2)
{
  return (t1.tv_sec - t2.tv_sec) * 1000 + (t1.tv_usec - t2.tv_usec) / 1000;
}
