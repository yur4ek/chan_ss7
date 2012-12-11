/* config.h - chan_ss7 configuration
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


#define AST_MODULE "chan_ss7"

#if defined(USE_ASTERISK_1_2) || defined(USE_ASTERISK_1_4) || defined(USE_ASTERISK_1_6)
#define argv_type char**
#else
#define argv_type const char* const*
#endif



typedef enum {ITU_SS7, ANSI_SS7, CHINA_SS7} ss7_variant;

/* Hunting policy. */
typedef enum { HUNT_ODD_LRU, HUNT_EVEN_MRU, HUNT_SEQ_LTH, HUNT_SEQ_HTL } hunting_policy;
typedef enum { BL_LM=1, BL_LH=2, BL_RM=4, BL_RH=8, BL_UNEQUIPPED=0x10, BL_LINKDOWN=0x20, BL_NOUSE=0x40 } block;

/* Upper bounds only determined by installed hardware, use decent values */
#define MAX_E1_CONNECTOR_NO 32
#define MAX_TIMESLOT 32
#define MAX_CIC 4096
#define MAX_LINKSETS 16
#define MAX_LINKS 128
#define MAX_LINKS_PER_LINKSET 128
#define MAX_LINKS_PER_HOST 32
#define MAX_SPANS_PER_HOST 32
#define MAX_SCHANNELS 32
#define MAX_SCHANNELS_PER_LINKSET 16
#define MAX_IFS_PER_HOST 2
#define MAX_HOSTS 16
#define MAX_ROUTES_PER_HOST 16

/* Echo cancellation constants */
enum {EC_DISABLED, EC_ALLWAYS, EC_31SPEECH};

typedef enum {STATE_UNKNOWN, STATE_ALIVE, STATE_DEAD} alivestate;
typedef enum {LOADSHARE_NONE, LOADSHARE_LINKSET, LOADSHARE_COMBINED_LINKSET} loadshare_type;
typedef enum {INTERFACE_TYPE_E1, INTERFACE_TYPE_T1} interface_type;

/* Linkset-groups: Each linkset in a group, has a pointer (group_linkset) 
   to a master linkset. This master linkset has a pointer to a linked list
   of idle channels (idle_list) for the whole group */

struct linkset {
  char* name;
  int n_links;
  struct link* links[MAX_LINKS_PER_LINKSET];
  char* context;
  char* language;
  ss7_variant variant;
  char* group;			/* dial group name */
  char* combined;		/* combined linkset name */
  int noa;			/* nature of address */
  loadshare_type loadshare;
  hunting_policy hunt_policy;
  int opc;
  int dpc;
  int enabled;
  int use_connect;
  int enable_st;
  int subservice;
  int t35_value;
  int t35_action;
  int lsi;
  int n_slinks;
  int n_schannels;
  int dni_chunk_limit;
  int grs;
  struct link* slinks[MAX_LINKS_PER_LINKSET];
  int first_cic, last_cic;
  int init_grs_done;		/* GRS sent? */
  struct linkset* group_linkset;
  /* Global circuit list. Protected by glock. */
  struct ss7_chan *cic_list[MAX_CIC];
  struct ss7_chan *idle_list;
  block blocked[MAX_CIC];
  int inservice;
  int incoming_calls;
  int outgoing_calls;
};

struct link {
  char* name;
  interface_type iftype;
  struct {unsigned int mask;} schannel;
  int n_schannels;
  int slinkix;
  int remote;
  int first_zapid;
  unsigned long channelmask;
  int first_cic;
  int sls[MAX_SCHANNELS_PER_LINKSET];
  int enabled;
  int send_sltm;
  int auto_block;
  int linkix;
  int echocancel;
  int echocan_taps;
  int echocan_train;
  int initial_alignment;
  int dpc;
  float rxgain;
  float txgain;
  int relaxdtmf;
  struct linkset* linkset;
  struct mtp2_state* mtp;
  struct host* on_host;
  struct receiver* receiver;
  char mtp3server_host[100];
  char mtp3server_port[8];
  int mtp3fd;
};

struct ipinterface {
  char* name;
  struct in_addr addr;
};

struct receiver {
  int n_targets;
  int receiverix;
  struct {
    struct host* host;
    struct ipinterface* inf;
  } targets[2*MAX_HOSTS];
};

struct host {
  char* name;
  int host_ix;
  /* Hosts point code */
  int opc;
  /* Destination point codes */
  int dpc[MAX_LINKSETS];
  /* Default linkset */
  struct linkset* default_linkset;
  /* SCCP address */
  int ssn;
  struct {unsigned char translation_type, nature_of_address, numbering_plan, encoding_scheme; char addr[21];} global_title;
  int n_routes;
  struct {char* destaddr; struct linkset* destlinkset;} routes[MAX_ROUTES_PER_HOST];

  int n_peers;
  struct {struct link* link; char* hostname;} peers[MAX_LINKS_PER_HOST];
  /* IP interfaces */
  int n_ifs;
  struct ipinterface ifs[MAX_IFS_PER_HOST];
  int n_spans;

  /* E1/T1 connections */
  struct {
    struct link* links[MAX_TIMESLOT];
    int n_links;
    int connector;
  } spans[MAX_SPANS_PER_HOST];

  int n_slinks;
  struct link* slinks[MAX_LINKS_PER_HOST];

  /* Receivers, per link */
  int n_receivers;
  struct receiver receivers[MAX_LINKS_PER_HOST];

  alivestate state;
  int has_signalling_receivers;
  int enabled;
};

extern int is_mtp3d;
extern int n_linksets;
extern int n_links;
extern struct linkset linksets[MAX_LINKSETS];

extern struct host* this_host;

extern struct link links[];

extern int clusterlistenport;

int load_config(int reload);
void destroy_config(void);
int timeslots(struct link* link);
int has_linkset_group(char* name);
struct linkset* lookup_linkset_for_group(const char* name, int no);
int is_combined_linkset(struct linkset* ls1, struct linkset* ls2);
struct linkset* find_linkset_for_dpc(int pc, int cic);
struct linkset* lookup_linkset(const char* name);
struct host* lookup_host_by_addr(struct in_addr);
struct host* lookup_host_by_id(int hostix);
struct ast_jb_conf *ss7_get_global_jbconf(void);
