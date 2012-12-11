/* l4isup.h - ISUP protocol
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


int isup_init(void);
int isup_cleanup(void);
int cmd_block(int fd, int argc, argv_type argv);
int cmd_unblock(int fd, int argc, argv_type argv);
int cmd_linestat(int fd, int argc, argv_type argv);
int cmd_reset(int fd, int argc, argv_type argv);
int cmd_linkset_status(int fd, int argc, argv_type argv);
void l4isup_inservice(struct link* link);
void l4isup_event(struct mtp_event* event);
void l4isup_link_status_change(struct link* link, int up);

