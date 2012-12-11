/* fifo.h - Lock-free FIFO for use in chan_ss7.

   Copyright (C) 2005-2011, Netfors ApS.

   Author: Kristian Nielsen <kn@sifira.dk>

   This file is part of chan_ss7.

   chan_ss7 is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   chan_ss7 is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with chan_ss7; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

/* Opaque struct used to implement lock-free fifo's. */
struct lffifo;

/* Public functions. */
struct lffifo *lffifo_alloc(int size);
void lffifo_free(struct lffifo *fifo);
/* Put and get data to/from the fifo.
   
   The idea is that one thread may put and one other thread may get without
   synchronisation, and still get correct behaviour.

   Put may fail if fifo is full; likewise get may fail if fifo is empty.
*/

/* Puts a frame, returns zero if ok, non-zero if full. */
int lffifo_put(struct lffifo *fifo, unsigned char *data, int size);
/* Gets a single frame, returns frame size or zero if fifo is empty.
   Returns negative number if caller buffer is too small. */
int lffifo_get(struct lffifo *fifo, unsigned char *buf, int bufsize);
