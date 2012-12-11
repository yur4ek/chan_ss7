/* cluster.h - chan_ss7 clustering/redundancy
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


extern int cluster_init(void (*isup_event_handler_callback)(struct mtp_event*),
			void (*isup_block_handler_callback)(struct link*));
extern void cluster_mtp_received(struct link* link, struct mtp_event*);
extern void cluster_mtp_sent(struct link* link, struct mtp_req*);
extern void cluster_mtp_forward(struct mtp_req*);
extern int cluster_receivers_alive(struct linkset*);
extern void cluster_cleanup(void);
extern int cmd_cluster_start(int fd, int argc, argv_type argv);
extern int cmd_cluster_stop(int fd, int argc, argv_type argv);
extern int cmd_cluster_status(int fd, int argc, argv_type argv);
