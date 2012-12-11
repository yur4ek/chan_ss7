/* mtp3io.h - MTP transport over mtp3d sockets interface
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

#pragma pack(push,4)

#define MTP3_SOCKETTYPE SOCK_STREAM
#define MTP3_IPPROTO IPPROTO_TCP
//define MTP3_SOCKETTYPE SOCK_SEQPACKET
//#define MTP3_IPPROTO IPPROTO_SCTP

#define SS7_PROTO_ISUP 5
#define SS7_PROTO_SCCP 3

/* Max. MTP2 packet size, including sequence numbers, CRC, and two flags. */
#define MTP_MAX_PCK_SIZE 280

/* Structure used to send requests to the MTP thread. */
#define MTP_REQ_MAX_SIZE (sizeof(struct mtp_req) + MTP_MAX_PCK_SIZE)

struct mtp_req {
  /* The "typ" field determines which element in the union is used. */
  enum {
    MTP_REQ_ISUP,               /* Queue ISUP MSU for sending on link */
    MTP_REQ_SCCP,               /* Queue SCCP MSU for sending on link */
    MTP_REQ_ISUP_FORWARD,       /* ISUP event to be sent on MTP */
    MTP_REQ_LINK_DOWN,          /* Take link out of service */
    MTP_REQ_LINK_UP,            /* Start initial alignment procedure */
    MTP_REQ_REGISTER_L4,	/* Register layer 4 protocol */
    MTP_REQ_CLI,                /* CLI interaction request */
  } typ;

  unsigned char infversion[4];
  unsigned int seq_no;
  unsigned int padding0[8];

  union {
    struct {
      int opc;
      int dpc;
      short slc;
      short slinkix;
      struct link* slink;
      struct link* link;
    } isup;
    struct {
      int opc;
      int dpc;
      short slc;
      short slinkix;
      struct link* slink;
    } sccp;
    struct {
      short linkix;
      short keepdown;
    } link;
    struct {
      short ss7_protocol;
      short host_ix;
      short linkix;
      union {
	struct {
	  short subsystem;
	} sccp;
      };
    } regist;
    struct {
      unsigned char padding[72];
    } padding;
  };

  int len;
  unsigned char buf[0];
};

/* Structure used to return events from the MTP thread. */
#define MTP_EVENT_MAX_SIZE (sizeof(struct mtp_event) + 1000)
struct mtp_event {
  /* The "typ" field determines which element in the union is used. */
  enum {
    MTP_EVENT_ALIVE = 10,       /* Enum value above this indicate MTP_EVENT_... */
    MTP_EVENT_ISUP,             /* ISUP MSU received on link */
    MTP_EVENT_SCCP,             /* SCCP MSU received on link */
    MTP_EVENT_REQ_REGISTER,	/* Require register */
    MTP_EVENT_LOG,              /* Log message for ast_log() */
    MTP_EVENT_DUMP,             /* Link data for frame-level debug dump */
    MTP_EVENT_STATUS,           /* F.ex. "link down". */
    MTP_EVENT_LAST,             /* Placeholder, Must be last in enumeration */
  } typ;

  unsigned char infversion[4];
  unsigned int seq_no;
  unsigned int padding0[8];

  union {
    struct {
      int opc;
      int dpc;
      short slc;
      short slinkix;
      struct link* slink;
      struct link* link;
    } isup;
    struct {
      int opc;
      int dpc;
      short slc;
      short slinkix;
      struct link* slink;
    } sccp;

    struct {
      short ss7_protocol;
      short host_ix;
      union {
	struct {
	  short slinkix;
	} isup;
      };
    } regist;

    struct {
      int level;
      int line;
      const char *file;
      const char *function;
    } log;

    struct {
      int out;                  /* True if sent packet, false if received */
      int sls;		/* Signalling link selector */
      struct timeval stamp;        /* Timestamp */
    } dump;

    struct {
      enum {
	MTP_EVENT_STATUS_LINK_UP,
	MTP_EVENT_STATUS_LINK_DOWN,
	MTP_EVENT_STATUS_INSERVICE
      } link_state;
      struct link* link;
    } status;
    struct {
      unsigned char padding[40];
    } padding;
  };

  int len;
  unsigned char buf[0];
};

extern int mtp3_sockettype;
extern int mtp3_ipproto;

int mtp3_setup_socket(int port, int schannel);
int mtp3_connect_socket(const char* host, const char* port);
int mtp3_send(int s, const unsigned char* buff, unsigned int len);
void mtp3_reply(int s, const unsigned char* buff, unsigned int len, const struct sockaddr* to, socklen_t tolen);
int mtp3_register_isup(int s, int linkix);
int mtp3_register_sccp(int s, int subsystem, int linkix);

#pragma pack(pop)
