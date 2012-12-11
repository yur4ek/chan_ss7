/* transport.h - MTP/audio transport
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


/* We read audio in chunks of 160 bytes = 20 msec. */
#define AUDIO_READSIZE 160
/* We run the signalling link in clear channel mode, since we have seen
   unreliable behaviour with the zaptel HDLC/FCS code, and since it gives
   more control of buffering and better diagnostics (raw bit dumps ...).

   Use 4 buffers of 16 bytes each; that amounts to around 8 msecs of
   latency of write and of read slack before packet loss. An 8 byte buffer
   size is the minimum allowed, giving maximum responsiveness.
*/
enum {
  NUM_ZAP_BUF = 4,
#ifdef MTP_OVER_UDP
  ZAP_BUF_SIZE = 64,
#else
  ZAP_BUF_SIZE = 16,
#endif
};

int openchannel(struct link* link, int channel);
void flushchannel(int fd, int cic);
int adjust_buffers(int fd, int cic);
int openschannel(struct link* link, int ts, int* sigtype);
int adjust_schannel_buffers(int fd, struct link* link, int ts, int bufcount, int bufsize);
int io_get_dahdi_event(int fd, int* e);
int io_enable_echo_cancellation(int fd, int cic, int echocan_taps, int echocan_train);
void io_disable_echo_cancellation(int fd, int cic);
int io_send_dtmf(int fd, int cic, char digit);
void set_audiomode(int fd);
void clear_audiomode(int fd);
