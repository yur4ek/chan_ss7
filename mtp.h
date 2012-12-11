/* mtp.h - MTP2 and MTP3 functionality.
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


struct mtp_req;
struct mtp_event;

/* Must be called once to initialize MTP, before starting the MTP thread.
   Returns 0 on ok, -1 on error. */

int mtp_init(void);

void mtp_cleanup(void);
void *mtp_thread_main(void *data);
void mtp_thread_signal_stop(void);
struct lffifo *mtp_get_receive_fifo(void);
struct lffifo **mtp_get_send_fifo(void);
struct lffifo *mtp_get_control_fifo(void);
void mtp3_put_label(int sls, ss7_variant variant, int opc, int dpc, unsigned char *buf);
int mtp_has_inservice_schannels(struct link*);
int mtp2_slink_inservice(int linkix);
int cmd_mtp_linkstatus(char* buff, int details, int timeslot);
int cmd_mtp_data(int fd, int argc, argv_type argv);
int cmd_testfailover(int fd, int argc, argv_type argv);

int get_receive_pipe(void);
void mtp_enqueue_control(struct mtp_req *req);

