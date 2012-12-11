/* config.c - chan_ss7 configuration
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


#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/param.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/ioctl.h>

#include "astversion.h"
#ifdef MTP_STANDALONE
#include "aststubs.h"
#else
#include "asterisk.h"
#include "asterisk/config.h"
#include "asterisk/logger.h"
#include "asterisk/strings.h"
#include "asterisk/abstract_jb.h"

#endif

#include "config.h"

int is_mtp3d = 0;

struct host* this_host;

int n_linksets;
struct linkset linksets[MAX_LINKSETS];
int n_links;
struct link links[MAX_LINKS];
int n_hosts;
struct host hosts[MAX_HOSTS];

int clusterlistenport;

/*! Global jitterbuffer configuration - by default, jb is disabled */
static struct ast_jb_conf default_jbconf =
{
  .flags = 0,
  .max_size = -1,
  .resync_threshold = -1,
  .impl = "",
};

static struct ast_jb_conf global_jbconf;


int timeslots(struct link* link)
{
  return (link->iftype == INTERFACE_TYPE_E1) ? 32 : 25;
}

int has_linkset_group(char* name) {
  int i;
  for (i = 0; i < n_linksets; i++) {
    if (linksets[i].group && !strcmp(linksets[i].group, name))
      return 1;
  }
  return 0;
}

struct linkset* lookup_linkset_for_group(const char* name, int no) {
  int i, cnt;
  for (i = 0, cnt = 0; i < n_linksets; i++) {
    if (linksets[i].enabled)
      if (linksets[i].group && !strcmp(linksets[i].group, name)) {
	if (cnt == no)
	  return &linksets[i];
	cnt++;
      }
  }
  return NULL;
}

int is_combined_linkset(struct linkset* ls1, struct linkset* ls2)
{
  if (ls1 == ls2)
    return 1;
  if ((ls1->combined && *ls1->combined) && ls2->combined &&
      (strcmp(ls1->combined, ls2->combined) == 0))
    return 1;
  return 0;
}

static int load_config_jitter(struct ast_config *cfg)
{
  struct ast_variable *v;

  /* Copy the default jb config over global_jbconf */
  memcpy(&global_jbconf, &default_jbconf, sizeof(struct ast_jb_conf));

  v = ast_variable_browse(cfg, "jitter");
  while(v != NULL) {
    ast_jb_read_conf(&global_jbconf, v->name, v->value);
    v = v->next;
  }

  return 0;
}

struct ast_jb_conf *ss7_get_global_jbconf() {
  return &global_jbconf;
}



/* Lookup linkset for destination point code */
struct linkset* find_linkset_for_dpc(int pc, int cic)
{
  int i;

  for (i = 0; i < n_linksets; i++)
    if ((linksets[i].dpc == pc) && (cic >= linksets[i].first_cic) && (cic <= linksets[i].last_cic))
      return &linksets[i];
  return NULL;
}

struct linkset* lookup_linkset(const char* name) {
  int i;
  for (i = 0; i < n_linksets; i++) {
    if (!strcmp(linksets[i].name, name))
      return &linksets[i];
  }
  return NULL;
}

static struct link* lookup_link(const char* name) {
  int i;
  for (i = 0; i < n_links; i++) {
    if (!strcmp(links[i].name, name))
      return &links[i];
  }
  return NULL;
}

static int make_group_linksets(void)
{
  int j, k, l;

  for (k = 0, j = 0; k < this_host->n_spans; k++) {
    for (l = 0; l < this_host->spans[k].n_links; l++) {
      struct link* link = this_host->spans[k].links[l];
      struct linkset* linkset = link->linkset;
      int lsi;
      if (link->enabled && linkset->enabled) {
	if (linkset->group && *linkset->group) {
	  linkset->group_linkset = lookup_linkset_for_group(linkset->group, 0);
	  for (lsi = 0; lsi < n_linksets; lsi++) {
	    struct linkset* ls = &linksets[lsi];
	    if (ls->group && (!strcmp(linkset->group, ls->group))) {
	      if (linkset->hunt_policy != ls->hunt_policy) {
		ast_log(LOG_ERROR, "Linksets %s and %s in group %s have different hunting policies\n", linkset->name, ls->name, linkset->group);
		return -1;
	      }
	    }
	  }
	}
	else
	  linkset->group_linkset = linkset;
      }
    }
  }
  return 0;
}

static struct host* lookup_host(const char* name) {
  int i;
  for (i = 0; i < n_hosts; i++)
    if (!strcmp(hosts[i].name, name))
      return &hosts[i];
  return NULL;
}

struct host* lookup_host_by_addr(struct in_addr addr)
{
  int i, j;
  for (i = 0; i < n_hosts; i++)
    for (j = 0; j < hosts[i].n_ifs; j++)
      if (memcmp(&hosts[i].ifs[j].addr, &addr, sizeof(addr)) == 0)
	return &hosts[i];
  return NULL;
}

struct host* lookup_host_by_id(int hostix)
{
  if (hostix >= n_hosts)
    return NULL;
  return &hosts[hostix];
}

static int make_host_slinks(void)
{
  int k, l;

  struct link* llink = NULL;
  if (this_host->n_spans == 0) {
    ast_log(LOG_ERROR, "No links defined in configuration for host '%s'.\n", this_host->name);
    return -1;
  }

  for (k = 0; k < this_host->n_spans; k++) {
    for (l = 0; l < this_host->spans[k].n_links; l++) {
      struct link* link = this_host->spans[k].links[l];
      int connector = this_host->spans[k].connector;
      link->first_zapid = (connector-1) * timeslots(link) - (connector-1);
      if (link->enabled) {
	llink = link;
	if ((link->schannel.mask != 0) && (!link->remote)) {
	  link->slinkix = this_host->n_slinks;
	  this_host->slinks[this_host->n_slinks++] = link;
	}
      }
    }
  }
  if (!llink) {
    ast_log(LOG_ERROR, "No links enabled on host '%s'.\n", this_host->name);
    return -1;
  }
  return 0;
}

static struct host* find_my_host(void)
{
  struct host* host;
  char buf[128];

  gethostname(buf, sizeof(buf)-1);
  if ((host = lookup_host(buf)) == NULL) {
    ast_log(LOG_ERROR, "Unable to find host configuration for host '%s'.\n", buf);
  }
  return host;
}

static void show_config(void)
{
  int i;

  for (i = 0; i < n_hosts; i++) {
    ast_log(LOG_DEBUG, "Host %s, links %d, ifs %d\n", hosts[i].name, hosts[i].n_spans, hosts[i].n_ifs);
  }
}

static int load_config_linkset(struct ast_config *cfg, const char* cat)
{
  struct ast_variable *v;
  const char *context = "default";
  const char *language = "";
  const char *linkset_name = &cat[strlen("linkset-")];
  struct linkset* linkset = &linksets[n_linksets];
  int has_context = 0, has_language = 0, has_hunt_policy = 0, has_use_connect = 0, has_enable_st = 0, has_subservice = 0;
  int i;

  if (n_linksets == MAX_LINKSETS) {
    ast_log(LOG_ERROR, "Too many linksets defined. Max %d\n", MAX_LINKSETS);
    return -1;
  }
  linkset->enabled = 1;
  linkset->n_slinks = 0;
  linkset->n_schannels = 0;
  linkset->t35_value = 15000;
  linkset->t35_action = 0;
  linkset->context = NULL;
  linkset->language = NULL;
  linkset->opc = 0;
  linkset->dpc = 0;
  linkset->dni_chunk_limit = 0;
  linkset->loadshare = LOADSHARE_COMBINED_LINKSET;
  linkset->inservice = 0;
  linkset->combined = 0;
  linkset->group = 0;
  linkset->group_linkset = NULL;
  linkset->variant = ITU_SS7;
  linkset->noa = -1;
  linkset->grs = 1;
  for (i = 0; i < MAX_CIC; i++)
    linkset->blocked[i] = 0;

  context = "default";
  language = "";
  v = ast_variable_browse(cfg, cat);
  while(v != NULL) {
    if(0 == strcasecmp(v->name, "context")) {
      context = v->value;
      has_context = 1;
    } else if(0 == strcasecmp(v->name, "language")) {
      language = v->value;
      has_language = 1;
    } else if(0 == strcasecmp(v->name, "variant")) {
      if(0 == strcasecmp(v->value, "CHINA")) {
	linkset->variant = CHINA_SS7;
      } else if(0 == strcasecmp(v->value, "ITU")) {
	linkset->variant = ITU_SS7;
      } else if(0 == strcasecmp(v->value, "ANSI")) {
	linkset->variant = ANSI_SS7;
      } else {
	ast_log(LOG_ERROR, "Error invalid SS7 variant '%s'.\n", v->value);
	return -1;
      }
    } else if(0 == strcasecmp(v->name, "group")) {
      linkset->group = strdup(v->value);
    } else if(0 == strcasecmp(v->name, "combined")) {
      linkset->combined = strdup(v->value);
    }
    else if(0 == strcasecmp(v->name, "hunting_policy")) {
      if(0 == strcasecmp(v->value, "odd_lru")) {
	linkset->hunt_policy = HUNT_ODD_LRU;
      } else if(0 == strcasecmp(v->value, "even_mru")) {
	linkset->hunt_policy = HUNT_EVEN_MRU;
      } else if(0 == strcasecmp(v->value, "seq_lth")) {
	linkset->hunt_policy = HUNT_SEQ_LTH;
      } else if(0 == strcasecmp(v->value, "seq_htl")) {
	linkset->hunt_policy = HUNT_SEQ_HTL;
      } else {
	ast_log(LOG_ERROR, "Error invalid hunting policy '%s'.\n", v->value);
	return -1;
      }
      has_hunt_policy = 1;
    } else if(0 == strcasecmp(v->name, "enabled")) {
      if ((strcasecmp(v->value, "yes") != 0) && (strcasecmp(v->value, "no") != 0)) {
	ast_log(LOG_ERROR, "Invalid value '%s' for enabled entry for linkset '%s'.\n", v->value, linkset_name);
	return -1;
      }
      linkset->enabled = strcasecmp(v->value, "yes") == 0;
    } else if(0 == strcasecmp(v->name, "use_connect")) {
      if ((strcasecmp(v->value, "yes") != 0) && (strcasecmp(v->value, "no") != 0)) {
	ast_log(LOG_ERROR, "Invalid value '%s' for use_connect entry for linkset '%s'.\n", v->value, linkset_name);
	return -1;
      }
      linkset->use_connect = strcasecmp(v->value, "yes") == 0;
      has_use_connect = 1;
    } else if(0 == strcasecmp(v->name, "enable_st")) {
      if ((strcasecmp(v->value, "yes") != 0) && (strcasecmp(v->value, "no") != 0)) {
	ast_log(LOG_ERROR, "Invalid value '%s' for enable_st entry for linkset '%s'.\n", v->value, linkset_name);
	return -1;
      }
      linkset->enable_st = strcasecmp(v->value, "yes") == 0;
      has_enable_st = 1;
    } else if(0 == strcasecmp(v->name, "subservice")) {
      if (strcasecmp(v->value, "auto") == 0) {
	linkset->subservice = -1;
      }
      else if (strcasecmp(v->value, "international") == 0) {
	linkset->subservice = 0;
      }
      else if (strcasecmp(v->value, "national") == 0) {
	linkset->subservice = 0x8;
      }
      else if(sscanf(v->value, "%i", &linkset->subservice) == 1) {}
      else {
	ast_log(LOG_ERROR, "Invalid value '%s' for subservice entry for linkset '%s'.\n", v->value, linkset_name);
	return -1;
      }
      has_subservice = 1;
    } else if(0 == strcasecmp(v->name, "noa")) {
      if(sscanf(v->value, "0x%x", &linkset->noa) == 1) {}
      else if(sscanf(v->value, "%d", &linkset->noa) == 1) {}
      else {
	ast_log(LOG_ERROR, "Invalid value '%s' for noa entry for linkset '%s'.\n", v->value, linkset_name);
	return -1;
      }
    } else if(0 == strcasecmp(v->name, "loadshare")) {
      if (strcasecmp(v->value, "none") == 0) {
	linkset->loadshare = LOADSHARE_NONE;
      }
      else if (strcasecmp(v->value, "linkset") == 0) {
	linkset->loadshare = LOADSHARE_LINKSET;
      }
      else if (strcasecmp(v->value, "combined") == 0) {
	linkset->loadshare = LOADSHARE_COMBINED_LINKSET;
      }
      else {
	ast_log(LOG_ERROR, "Invalid value '%s' for loadshare entry for linkset '%s'.\n", v->value, linkset_name);
	return -1;
      }
    } else if(0 == strcasecmp(v->name, "t35")) {
      char action_buf[100];
      if(sscanf(v->value, "%d,%s", &linkset->t35_value, action_buf) != 2) {
	ast_log(LOG_ERROR, "Invalid synax in '%s' for t35 entry for linkset '%s'.\n", v->value, linkset_name);
	return -1;
      }
      if (strcasecmp(action_buf, "st") == 0)
	linkset->t35_action = 1;
      else if (strcasecmp(action_buf, "timeout") == 0)
	linkset->t35_action = 0;
      else {
	ast_log(LOG_ERROR, "Invalid t35 action '%s'.\n", action_buf);
	return -1;
      }
    } else if(0 == strcasecmp(v->name, "dni_chunk_limit")) {
      if(sscanf(v->value, "%d", &linkset->dni_chunk_limit) != 1) {
	ast_log(LOG_ERROR, "Invalid synax in '%s' for dni_chunk_limit entry for linkset '%s'.\n", v->value, linkset_name);
	return -1;
      }
      if (linkset->dni_chunk_limit < 0 || linkset->dni_chunk_limit > 99) {
        ast_log(LOG_ERROR, "Invalid value '%s' for config option '%s', aborting.\n", v->value, v->name);
        return -1;
      }
    } else if(0 == strcasecmp(v->name, "grs")) {
      if ((strcasecmp(v->value, "no") != 0) && (strcasecmp(v->value, "yes") != 0) &&
	  (strcasecmp(v->value, "0") != 0)  && (strcasecmp(v->value, "1") != 0))
	{
	  ast_log(LOG_ERROR, "Invalid value '%s' for grs entry for linkset '%s'.\n", v->value, linkset_name);
	  return -1;
	}
      if ((strcasecmp(v->value, "0") == 0) || (strcasecmp(v->value, "no") == 0)) {
	linkset->grs = 0;
      }
    } else if((0 == strcasecmp(v->name, "blockin")) || (0 == strcasecmp(v->name, "blockout"))) {
      block b = (0 == strcasecmp(v->name, "blockin")) ? BL_LM : BL_NOUSE;
      char block_spec_buf[10000] = {0,};
      char *p;
      char *spec;

      ast_copy_string(block_spec_buf, v->value, sizeof(block_spec_buf));
      spec = &block_spec_buf[0];
      p = strsep(&spec, ",");
      while(p && *p) {
	int i, first, last;
	if(sscanf(p, "%d-%d", &first, &last) != 2 ||
	   first < 0 || first > last || last > MAX_CIC) {
	  ast_log(LOG_DEBUG, "Block range '%s' is %d %d \n", p, first,last);
	  ast_log(LOG_ERROR, "Illegal block range '%s' for "
		  "channel specification for link '%s'.\n", p, linkset_name);
	  return -1;
	}
	for (i = first; i <= last; i++)
	  linkset->blocked[i] |= b;
	p = strsep(&spec, ",");
      }
    } else if (strcasecmp(v->name, "opc") == 0) {
      if(sscanf(v->value, "%i", &linkset->opc) != 1) {
	ast_log(LOG_ERROR, "Invalid value '%s' for opc for linkset '%s'.\n", v->value, linkset_name);
	return -1;
      }
    } else if (strcasecmp(v->name, "dpc") == 0) {
      if(sscanf(v->value, "%i", &linkset->dpc) != 1) {
	ast_log(LOG_ERROR, "Invalid value '%s' for dpc for linkset '%s'.\n", v->value, linkset_name);
	return -1;
      }
    } else if(0 == strcasecmp(v->name, "gt")) {
    } else if(0 == strcasecmp(v->name, "transport")) {
    } else {
      ast_log(LOG_ERROR, "Unknown config option '%s', aborting.\n", v->name);
      return -1;
    }
    
    v = v->next;
  }

  if (!has_hunt_policy) {
    ast_log(LOG_ERROR, "Missing hunting_policy entry for linkset '%s'\n", linkset_name);
    return -1;
  }
  if (!has_use_connect) {
    ast_log(LOG_ERROR, "Missing use_connect entry for linkset '%s'\n", linkset_name);
    return -1;
  }
  if (!has_enable_st) {
    ast_log(LOG_ERROR, "Missing enable_st entry for linkset '%s'\n", linkset_name);
    return -1;
  }
  if (!has_subservice) {
    ast_log(LOG_ERROR, "Missing subservice entry for linkset '%s'\n", linkset_name);
    return -1;
  }
  linkset->context = strdup(context);
  linkset->language = strdup(language);
  if (!has_context)
    ast_log(LOG_NOTICE, "Using default context '%s' for linkset '%s'\n", linkset->context, linkset_name);
  if (!has_language)
    ast_log(LOG_NOTICE, "Using default language '%s' for linkset '%s'\n", linkset->language, linkset_name);

  linkset->name = strdup(linkset_name);
  linkset->n_links = 0;
  linkset->lsi = n_linksets;
  linkset->init_grs_done = 0;
  linkset->first_cic = MAX_CIC+1;
  linkset->last_cic = 0;
  linkset->init_grs_done = 0;
  linkset->idle_list = NULL;
  for (i = 0; i < MAX_CIC; i++)
    linkset->cic_list[i] = NULL;
  n_linksets++;
  return 0;
}


static int load_config_link(struct ast_config *cfg, const char* cat)
{
  struct ast_variable *v;

  char *p;
  char *spec;
  const char *link_name = &cat[strlen("link-")];
  char chan_spec_buf[1000] = {0,};
  struct linkset* linkset = NULL;
  struct link* link = &links[n_links];
  int i;
  int firstcic = 0x7ffffff, lastcic = 0;
  int has_linkset = 0, has_firstcic = 0, has_channels = 0, has_schannel = 0, has_sls = 0;

  if (lookup_link(link_name)) {
    ast_log(LOG_ERROR, "Links '%s' defined twice.\n", link_name);
    return -1;
  }
  if (n_links == MAX_LINKS) {
    ast_log(LOG_ERROR, "Too many links defined while parsing config for link '%s' (max %d).\n", link_name, MAX_LINKS);
    return -1;
  }

  link->enabled = 1;
  link->iftype = INTERFACE_TYPE_E1;
  link->first_cic = MAX_CIC+1;
  link->schannel.mask = 0;
  link->n_schannels = 0;
  link->slinkix = -1;
  link->send_sltm = 1;
  link->auto_block = 0;
  /* Echo cancellation default values */
  link->echocancel = EC_DISABLED;
  link->echocan_taps  = 128; /* echo cancellation taps, 128 default */
  link->echocan_train = 300; /* echo cancellation training, 300ms default */
  link->mtp = NULL;
  link->initial_alignment = 1;
  link->dpc = 0;
  link->rxgain = 0.0;
  link->txgain = 0.0;
  link->relaxdtmf = 0;
  *link->mtp3server_host = 0;
  *link->mtp3server_port = 0;
  link->mtp3fd = -1;

  v = ast_variable_browse(cfg, cat);
  while(v != NULL) {
    if(0 == strcasecmp(v->name, "iftype")) {
      if (strcasecmp(v->value, "E1") == 0)
	link->iftype = INTERFACE_TYPE_E1;
      else if (strcasecmp(v->value, "T1") == 0)
	link->iftype = INTERFACE_TYPE_T1;
      else {
        ast_log(LOG_ERROR, "Invalid value '%s' for iftype entry for link '%s' (must be E1 or T1)\n", v->value, link_name);
        return -1;
      }
    } else if(0 == strcasecmp(v->name, "linkset")) {
      linkset = lookup_linkset(v->value);
      if (!linkset) {
	ast_log(LOG_ERROR, "Linkset '%s' not found while parsing link '%s'.\n", v->value, link_name);
	return -1;
      }
      has_linkset = 1;
    } else if(0 == strcasecmp(v->name, "enabled")) {
      if ((strcasecmp(v->value, "yes") != 0) && (strcasecmp(v->value, "no") != 0)) {
	ast_log(LOG_ERROR, "Invalid value '%s' for enabled entry for link '%s'.\n", v->value, link_name);
	return -1;
      }
      link->enabled = strcasecmp(v->value, "yes") == 0;
    } else if(0 == strcasecmp(v->name, "relaxdtmf")) {
      if ((strcasecmp(v->value, "yes") != 0) && (strcasecmp(v->value, "no") != 0)) {
        ast_log(LOG_ERROR, "Invalid value '%s' for enabled entry for link '%s'.\n", v->value, link_name);
        return -1;
      }
      link->relaxdtmf = strcasecmp(v->value, "yes") == 0;
    } else if(0 == strcasecmp(v->name, "sltm")) {
      if ((strcasecmp(v->value, "yes") != 0) && (strcasecmp(v->value, "no") != 0)) {
	ast_log(LOG_ERROR, "Invalid value '%s' for sltm entry for link '%s'.\n", v->value, link_name);
	return -1;
      }
      link->send_sltm = strcasecmp(v->value, "yes") == 0;
    } else if(0 == strcasecmp(v->name, "auto_block")) {
      if ((strcasecmp(v->value, "yes") != 0) && (strcasecmp(v->value, "no") != 0)) {
	ast_log(LOG_ERROR, "Invalid value '%s' for auto_block entry for link '%s'.\n", v->value, link_name);
	return -1;
      }
      link->auto_block = strcasecmp(v->value, "yes") == 0;
    } else if(0 == strcasecmp(v->name, "firstcic")) {
      if(sscanf(v->value, "%d", &link->first_cic) != 1) {
	ast_log(LOG_ERROR, "Invalid firstcic entry '%s' for link '%s'.\n", v->value, link_name);
	return -1;
      }
      has_firstcic = 1;
    } else if(0 == strcasecmp(v->name, "sls")) {
      int n_sls = 0;
      ast_copy_string(chan_spec_buf, v->value, sizeof(chan_spec_buf));
      spec = &chan_spec_buf[0];
      p = strsep(&spec, ",");
      while(p && *p) {
	int i, first, last;
	if(sscanf(p, "%d-%d", &first, &last) == 2) {
	  if (first < 0 || first > last || last > 31) {
	    ast_log(LOG_DEBUG, "SLS range '%s' is %d %d \n", p, first,last);
	    ast_log(LOG_ERROR, "Illegal SLS range '%s' for SLS specification for link '%s'.\n", p, link_name);
	    return -1;
	  }
	}
	else {
	  if((sscanf(p, "%d", &first) != 1) || (first < 0) || (first > 31)) {
	    ast_log(LOG_ERROR, "Illegal SLS value '%s' for SLS specification for link '%s'.\n", p, link_name);
	    return -1;
	  }
	  last = first;
	}
	for (i = first; i <= last; i++) {
	  link->sls[n_sls++] = i;
	}
	p = strsep(&spec, ",");
      }
      has_sls = 1;
    } else if(0 == strcasecmp(v->name, "channels")) {
      link->channelmask = 0;
      ast_copy_string(chan_spec_buf, v->value, sizeof(chan_spec_buf));
      spec = &chan_spec_buf[0];
      p = strsep(&spec, ",");
      while(p && *p) {
	int i, first, last;
	if((sscanf(p, "%d-%d", &first, &last) == 2) && (first > 0 && first <= last && last <= 31)) {
	}
	else if((sscanf(p, "%d", &first) == 1) && (first > 0 && first <= 31)) {
	  last = first;
	}
	else {
	  ast_log(LOG_ERROR, "Illegal channel range '%s' for "
		  "channel specification for link '%s'.\n", p, link_name);
	  return -1;
	}
	for (i = first; i <= last; i++)
	  link->channelmask |= 1 << (i-1);
	p = strsep(&spec, ",");
      }
      has_channels = 1;
    } else if(0 == strcasecmp(v->name, "schannel")) {
      link->remote = 0;
      spec = &chan_spec_buf[0];
      if (strcmp(v->value, "")) {
	if ((sscanf(v->value, "%[^@]@%[^:]:%s", chan_spec_buf, link->mtp3server_host, link->mtp3server_port) == 3) || (sscanf(v->value, "%[^@]@%[^:]", chan_spec_buf, link->mtp3server_host) == 2)) {
	  if (!is_mtp3d)
	    link->remote = 1;
	} else
	  snprintf(chan_spec_buf, sizeof(chan_spec_buf), "%s", v->value);
	p = strsep(&spec, ",");
	while(p && *p) {
	  int i, first, last;
	  if(sscanf(p, "%d-%d", &first, &last) == 2) {
	    if (first < 0 || first > last || last > 31) {
	      ast_log(LOG_DEBUG, "Schannel range '%s' is %d %d \n", p, first,last);
	      ast_log(LOG_ERROR, "Illegal schannel range '%s' for schannel specification for link '%s'.\n", p, link_name);
	      return -1;
	    }
	  }
	  else {
	    if((sscanf(p, "%d", &first) != 1) || (first < 0) || (first > 31)) {
	      ast_log(LOG_ERROR, "Illegal schannel value '%s' for schannel specification for link '%s'.\n", p, link_name);
	      return -1;
	    }
	    last = first;
	  }
	  for (i = first; i <= last; i++)
	    link->schannel.mask |= 1 << (i-1);
	  p = strsep(&spec, ",");
	}
	for (i = 0; i < 32; i++)
	  if (link->schannel.mask & (1 << i))
	    link->n_schannels++;
      }
      has_schannel = 1;
    } else if(0 == strcasecmp(v->name, "echocancel")) {
      if (strcasecmp(v->value, "no") == 0) {
        link->echocancel = EC_DISABLED;
      } else if (strcasecmp(v->value, "31speech") == 0) {
        link->echocancel = EC_31SPEECH;
      } else if (strcasecmp(v->value, "allways") == 0) {
        link->echocancel = EC_ALLWAYS;
      } else {
        ast_log(LOG_ERROR, "Invalid value '%s' for echocancel entry for link '%s'.\n", v->value, link_name);

        return -1;
      }
    } else if(0 == strcasecmp(v->name, "echocan_train")) {
      if(sscanf(v->value, "%d", &link->echocan_train) != 1 || 
         link->echocan_train < 10 || link->echocan_train > 1000)
      {
        ast_log(LOG_ERROR, "Invalid value '%s' for echocan_train entry for "
                           "link '%s'. should be between 10 and 1000\n",
                            v->value, link_name);
        return -1;
      }
    } else if(0 == strcasecmp(v->name, "echocan_taps")) {
      if(!(sscanf(v->value, "%d", &link->echocan_taps) == 1 &&
          (link->echocan_taps == 32  || link->echocan_taps == 64 ||
           link->echocan_taps == 128 || link->echocan_taps == 256)))
      {
        ast_log(LOG_ERROR, "Invalid value '%s' for echocan_taps entry for "
                           "link '%s'. should be 32, 64, 128 or 256\n",
                            v->value, link_name);
        return -1;
      }
    } else if(0 == strcasecmp(v->name, "rxgain")) {
        if (sscanf(v->value, "%f", &link->rxgain) != 1) {
            ast_log(LOG_WARNING, "Invalid rxgain: %s\n", v->value);
            link->rxgain = 0.0;
        }

    } else if(0 == strcasecmp(v->name, "txgain")) {
        if (sscanf(v->value, "%f", &link->txgain) != 1) {
            ast_log(LOG_WARNING, "Invalid txgain: %s\n", v->value);
            link->txgain = 0.0;
        }
    } else if(0 == strcasecmp(v->name, "initial_alignment")) {
      if ((strcasecmp(v->value, "yes") != 0) && (strcasecmp(v->value, "no") != 0)) {
	ast_log(LOG_ERROR, "Invalid value '%s' for initial_alignment entry for link '%s'.\n", v->value, link_name);
	return -1;
      }
      link->initial_alignment = strcasecmp(v->value, "yes") == 0;
    } else if (strcasecmp(v->name, "stp") == 0) {
      if(sscanf(v->value, "%i", &link->dpc) != 1) {
	ast_log(LOG_ERROR, "Invalid value '%s' for stp for link '%s'.\n", v->value, link_name);
	return -1;
      }
    } else if(0 == strcasecmp(v->name, "rc")) {
    } else if(0 == strcasecmp(v->name, "bandwidth")) {
    } else if (strcasecmp(v->name, "erlang") == 0) {
    } else {
      ast_log(LOG_ERROR, "Unknown config option '%s', aborting.\n", v->name);
      return -1;
    }
    v = v->next;
  }
  if (!has_linkset) {
    ast_log(LOG_ERROR, "Missing linkset entry for link '%s'.\n", link_name);
    return -1;
  }
  if (!has_firstcic) {
    if (link->channelmask) {
      ast_log(LOG_ERROR, "Missing firstcic entry for link '%s'.\n", link_name);
      return -1;
    }
  }
  if (!has_channels) {
    ast_log(LOG_ERROR, "Missing channels entry for link '%s'.\n", link_name);
    return -1;
  }
  if (!has_schannel) {
    ast_log(LOG_ERROR, "Missing schannel entry for link '%s'.\n", link_name);
    return -1;
  }

  if (linkset->n_links == MAX_LINKS_PER_LINKSET) {
    ast_log(LOG_ERROR, "Too many links defined for linkset '%s' for link '%s' (max %d).\n", linkset->name, link_name, MAX_LINKS_PER_LINKSET);
    return -1;
  }
  if (!has_sls) {
    for (i = 0; i < link->n_schannels; i++)
      link->sls[i] = linkset->n_schannels + i;
  }
  link->name = strdup(link_name);
  link->linkset = linkset;
  link->on_host = NULL;
  link->receiver = NULL;
  link->first_zapid = -1;
  if (link->enabled) {
    if (linkset->enabled) {
      linkset->links[linkset->n_links++] = link;
      if (link->schannel.mask != 0) {
	linkset->slinks[linkset->n_slinks++] = link;
      }
    }
    else {
      ast_log(LOG_NOTICE, "Disabling link '%s' on disabled linkset '%s'\n", link->name, linkset->name);
      link->enabled = 0;
    }
  }
  ast_log(LOG_NOTICE, "%s link '%s' on linkset '%s', firstcic=%d\n", link->enabled ? "Configured" : "Ignoring disabled", link->name, linkset->name, link->first_cic);
  if (link->enabled) {
    for (i = 0; i < 32; i++)
      if (link->schannel.mask & (1<<i))
	linkset->n_schannels++;
    if (linkset->n_schannels > MAX_SCHANNELS_PER_LINKSET) {
      ast_log(LOG_ERROR, "Too many schannels for linkset '%s', %d, max %d.\n", linkset->name, linkset->n_schannels, MAX_SCHANNELS_PER_LINKSET);
      return -1;
    }
  }
  for (i = 1; i <= 31; i++) {
    if (link->channelmask & (1 << (i-1))) {
      int cic = link->first_cic + i - 1;
      if (cic > lastcic)
	lastcic = cic;
      if (cic < firstcic)
	firstcic = cic;
    }
  }
  if (linkset->first_cic > firstcic)
    linkset->first_cic = firstcic;
  if (linkset->last_cic < lastcic)
    linkset->last_cic = lastcic;
  link->linkix = n_links;
  n_links++;
  return 0;
}

static int load_config_host(struct ast_config *cfg, const char* cat)
{
  struct ast_variable *v;

  char *p;
  char *spec;
  const char *host_name = &cat[strlen("host-")];
  struct host* host = &hosts[n_hosts];
  char links_spec_buf[1000] = {0,};
  int i, j, l;
  int has_links = 0, has_enabled = 0, has_if = 0;

  if (n_hosts == MAX_HOSTS) {
    ast_log(LOG_ERROR, "Too many hosts defined while parsing config for host '%s' (max %d).\n", host_name, MAX_HOSTS);
    return -1;
  }
  host->opc = 0;
  memset(host->dpc, 0, sizeof(host->dpc));
  memset(host->receivers, 0, sizeof(host->receivers));
  host->name = strdup(host_name);
  host->host_ix = n_hosts;
  host->default_linkset = NULL;
  host->n_slinks = 0;
  host->n_peers = 0;
  host->ssn = 0;
  host->n_routes = 0;

  memset(&host->global_title, 0, sizeof(host->global_title));
  v = ast_variable_browse(cfg, cat);
  while(v != NULL) {
    if(0 == strcasecmp(v->name, "opc")) {
      char *endptr;
      host->opc = strtoul(v->value, &endptr, 0);
      if(endptr == v->value || *endptr != '\0') {
	ast_log(LOG_ERROR, "Error: Invalid number '%s' for "
		"config option own_pc.\n", v->value);
	return -1;
      }
    } else if(0 == strcasecmp(v->name, "dpc")) {
      char dpc_spec_buf[1000] = {0,};
      char linkset_name_buf[1000];
      char dpc_buf[20];

      ast_copy_string(dpc_spec_buf, v->value, sizeof(dpc_spec_buf));
      spec = &dpc_spec_buf[0];
      p = strsep(&spec, ",");
      while(p && *p) {
	int dpc;
	struct linkset* linkset;
	struct link* link;
	if(sscanf(p, "%[^:]:%s", linkset_name_buf, dpc_buf) != 2) {
	  ast_log(LOG_ERROR, "Invalid DPC specification '%s' for host '%s'", p, host_name);
	  return -1;
	}
	if (strncmp(v->value, "0x", 2) == 0)
	  dpc = strtol(dpc_buf+2, NULL, 16);
	else
	  dpc = strtol(dpc_buf, NULL, 0);
	if (!dpc) {
	  ast_log(LOG_ERROR, "Invalid DPC value '%s' for linkset '%s' for host '%s'", dpc_buf, linkset_name_buf, host_name);
	  return -1;
	}
	linkset = lookup_linkset(linkset_name_buf);
	if (!linkset) {
	  link = lookup_link(linkset_name_buf);
	  if (!link) {
	    ast_log(LOG_ERROR, "Unknown link/linkset '%s' for host '%s'", linkset_name_buf, host_name);
	    return -1;
	  }
	  link->dpc = dpc;
	}
	else
	  host->dpc[linkset->lsi] = dpc;
	p = strsep(&spec, ",");
      }
    } else if(0 == strcasecmp(v->name, "peers")) {
      char peer_spec_buf[500] = {0,};
      ast_copy_string(peer_spec_buf, v->value, sizeof(peer_spec_buf));
      ast_log(LOG_DEBUG, "peers '%s' \n", peer_spec_buf);
      spec = &peer_spec_buf[0];
      p = strsep(&spec, ",");
      while(p && *p) {
	char link_buf[100];
	char host_buf[100];
	struct link* link;
	if (host->n_peers == MAX_LINKS_PER_HOST) {
	  ast_log(LOG_ERROR, "Too many routes defined for host '%s' (max %d).\n", host->name, MAX_LINKS_PER_HOST);
	  return -1;
	}
	while ((*p == ' ') || (*p == '\t'))
	  p++;
	if(sscanf(p, "%[^:]:%s", link_buf, host_buf) != 2) {
	  ast_log(LOG_ERROR, "Invalid peer specification '%s' for host '%s'.\n", p, host_name);
	  return -1;
	}
	link = lookup_link(link_buf);
	if (!link) {
	  ast_log(LOG_ERROR, "Unknown link '%s' for peers '%s' for host '%s'", link_buf, p, host_name);
	  return -1;
	}
	host->peers[host->n_peers].link = link;
	host->peers[host->n_peers].hostname = strdup(host_buf);
	host->n_peers++;
	p = strsep(&spec, ",");
      }
    } else if(0 == strcasecmp(v->name, "enabled")) {
      if ((strcasecmp(v->value, "yes") != 0) && (strcasecmp(v->value, "no") != 0)) {
	ast_log(LOG_ERROR, "Invalid value '%s' for enabled entry for host '%s'.\n", v->value, host_name);
	return -1;
      }
      host->enabled = strcasecmp(v->value, "yes") == 0;
      has_enabled = 1;
    } else if(0 == strcasecmp(v->name, "default_linkset")) {
      host->default_linkset = lookup_linkset(v->value);
      if (!host->default_linkset)
	host->default_linkset = lookup_linkset_for_group(v->value, 0);
      if (!host->default_linkset) {
	ast_log(LOG_ERROR, "Unknown default_linkset or group '%s' for host '%s'.\n", v->value, host_name);
	return -1;
      }
    } else if(0 == strcasecmp(v->name, "links")) {
      ast_copy_string(links_spec_buf, v->value, sizeof(links_spec_buf));
      ast_log(LOG_DEBUG, "links '%s' \n", links_spec_buf);
      spec = &links_spec_buf[0];
      p = strsep(&spec, ",");
      while(p && *p) {
	char linkname_buf[100];
	struct link* link = NULL;
	if (host->n_spans == MAX_LINKS_PER_HOST) {
	  ast_log(LOG_ERROR, "Too many links defined for host '%s' (max %d).\n", host->name, MAX_LINKS_PER_HOST);
	  return -1;
	}
	if(sscanf(p, "%[^:]:%d", linkname_buf, &host->spans[host->n_spans].connector) != 2) {
	  ast_log(LOG_DEBUG, "linkname '%s', no %d \n", linkname_buf, host->spans[host->n_spans].connector);
	  ast_log(LOG_ERROR, "Invalid link specification '%s' for host '%s'.\n", p, host_name);
	  return -1;
	}
	if ((host->spans[host->n_spans].connector < 1) || (host->spans[host->n_spans].connector > MAX_E1_CONNECTOR_NO)) {
	  ast_log(LOG_ERROR, "Connector no. %d for link '%s' not in range 1..%d.\n", host->spans[host->n_spans].connector, v->value, MAX_E1_CONNECTOR_NO);
	  return -1;
	}
	ast_log(LOG_DEBUG, "linkname '%s', no %d \n", linkname_buf, host->spans[host->n_spans].connector);
	link = lookup_link(linkname_buf);
	if (!link) {
	  ast_log(LOG_ERROR, "Link '%s' not found while parsing host '%s'.\n", linkname_buf, host_name);
	  return -1;
	}
	if (link->on_host) {
	  ast_log(LOG_ERROR, "Link '%s' belongs to both  host '%s' and '%s'.\n", linkname_buf, host_name, host->spans[i].links[l]->on_host->name);
	  return -1;
	}
	for (i = 0; i < host->n_spans; i++, l = 0) {
	  if (host->spans[i].connector == host->spans[host->n_spans].connector) {
	    break;
	  }
	}
	if (i == host->n_spans)
	  host->n_spans++;
	link->on_host = host;
	host->spans[i].links[host->spans[i].n_links++] = link;
	ast_log(LOG_DEBUG, "host n_spans %d \n", host->n_spans);
	p = strsep(&spec, ",");
      }
      has_links = 1;
    } else if(0 == strncasecmp(v->name, "if-", 3)) {
      in_addr_t addr;
      if (host->n_ifs == MAX_IFS_PER_HOST) {
	ast_log(LOG_ERROR, "Too many interfaces defined for host '%s' (max %d).\n", host->name, MAX_IFS_PER_HOST);
	return -1;
      }
      if ((addr = inet_addr(v->value)) == INADDR_NONE) {
	ast_log(LOG_ERROR, "Invalid IP address '%s' for interface '%s' for host '%s'.\n", v->value, v->value, host_name);
	return -1;
      }
      memcpy(&host->ifs[host->n_ifs].addr, &addr, sizeof(addr));
      host->ifs[host->n_ifs].name = strdup(&v->name[3]);
      host->n_ifs++;
      has_if = 1;
    } else if(0 == strcasecmp(v->name, "ssn")) {
      if(sscanf(v->value, "%i", &host->ssn) != 1) {
	  ast_log(LOG_ERROR, "Invalid ssn value '%s' for host '%s'.\n", v->value, host_name);
	  return -1;
	}
    } else if(0 == strcasecmp(v->name, "globaltitle")) {
      if(sscanf(v->value, "%hhi, %hhi, %hhi, %s", &host->global_title.translation_type, &host->global_title.nature_of_address, &host->global_title.numbering_plan, host->global_title.addr) != 4) {
	  ast_log(LOG_ERROR, "Invalid globaltitle value '%s' for host '%s'.\n", v->value, host_name);
	  return -1;
      }
    } else if(0 == strcasecmp(v->name, "route")) {
      char route_spec_buf[500] = {0,};
      ast_copy_string(route_spec_buf, v->value, sizeof(route_spec_buf));
      ast_log(LOG_DEBUG, "route '%s' \n", route_spec_buf);
      spec = &route_spec_buf[0];
      p = strsep(&spec, ",");
      while(p && *p) {
	char dest_buf[100];
	char linkset_buf[100];
	struct linkset* linkset;
	if (host->n_routes == MAX_ROUTES_PER_HOST) {
	  ast_log(LOG_ERROR, "Too many routes defined for host '%s' (max %d).\n", host->name, MAX_ROUTES_PER_HOST);
	  return -1;
	}
	while ((*p == ' ') || (*p == '\t'))
	  p++;
	if(sscanf(p, "%[0-9]:%s", dest_buf, linkset_buf) != 2) {
	  if(sscanf(p, ":%s", linkset_buf) != 1) {
	    ast_log(LOG_ERROR, "Invalid route specification '%s' for host '%s'.\n", p, host_name);
	    return -1;
	  }
	  *dest_buf = '\0';
	}
	linkset = lookup_linkset(linkset_buf);
	if (!linkset) {
	  ast_log(LOG_ERROR, "Unknown linkset '%s' for route '%s' for host '%s'\n", linkset_buf, p, host_name);
	  return -1;
	}
	host->routes[host->n_routes].destaddr = strdup(dest_buf);
	host->routes[host->n_routes].destlinkset = linkset;
	host->n_routes++;
	p = strsep(&spec, ",");
      }
    } else {
      ast_log(LOG_ERROR, "Unknown config option '%s', aborting.\n", v->name);
      return -1;
    }
    v = v->next;
  }
  for (i = 0; i < host->n_spans; i++, l = 0) {
    for (j = 0; j < host->spans[i].n_links; j++) {
      struct link* link = host->spans[i].links[j];
      for (l = j+1; l < host->spans[i].n_links; l++) {
	struct link* link1 = host->spans[i].links[l];
	unsigned int m = (link->schannel.mask & link1->schannel.mask);
	if (!link->enabled || !link->linkset->enabled || !link1->enabled || !link1->linkset->enabled)
	  continue;
	if (m != 0) {
	  ast_log(LOG_ERROR, "Connector no. %d specified twice for host '%s.' with overlapping signaling time slots: mask: 0x%08x, links: %s and %s\n", host->spans[host->n_spans].connector, host->name, m, link->name, link1->name);
	  return -1;
	}
	m = (link->channelmask & link1->channelmask);
	if (m != 0) {
	  ast_log(LOG_ERROR, "Connector no. %d specified twice for host '%s.' with overlapping CIC time slots: mask: 0x%08x\n", host->spans[host->n_spans].connector, host->name, m);
	  return -1;
	}
      }
    }
  }
  if (!has_links) {
    ast_log(LOG_ERROR, "Missing links entry for host '%s'.\n", host_name);
    return -1;
  }
  if (!has_enabled) {
    ast_log(LOG_ERROR, "Missing enabled entry for host '%s'.\n", host_name);
    return -1;
  }
  if (!has_if) {
    ast_log(LOG_WARNING, "Missing interface entries for host '%s'.\n", host_name);
  }
  host->n_receivers = 0;
  host->state = STATE_UNKNOWN;
  host->has_signalling_receivers = 0;
  ast_log(LOG_DEBUG, "host %s, n_spans %d \n", host->name, host->n_spans);
  n_hosts++;
  return 0;
}

static int load_config_cluster(struct ast_config *cfg)
{
  struct ast_variable *v;
  struct link* link;
  struct host* host;
  struct receiver* receiver;
  int i, j, l;
  char *p;

  char *spec;
  char dup_spec_buf[100] = {0,};
  int has_port = 0;

  v = ast_variable_browse(cfg, "cluster");
  while(v != NULL) {
    if (strcasecmp(v->name, "port") == 0) {
      if(sscanf(v->value, "%d", &clusterlistenport) != 1) {
	ast_log(LOG_ERROR, "The port entry '%s' in cluster section is not valid.\n", v->name);
	return -1;
      }
      has_port = 1;
      v = v->next;
      continue;
    }
    if ((link = lookup_link(v->name)) == NULL) {
      ast_log(LOG_ERROR, "The link '%s' is not defined while parsing cluster category.\n", v->name);
      return -1;
    }
    host = NULL;
    for (i = 0; i < n_hosts; i++) {
      for (j = 0; j < hosts[i].n_spans; j++) {
	for (l = 0; l < hosts[i].spans[j].n_links; l++) {
	  if (hosts[i].spans[j].links[l] == link) {
	    host = &hosts[i];
	    break;
	  }
	}
      }
    }
    if (link->enabled) {
      if (host) {
	if (host->n_receivers == MAX_LINKS_PER_HOST) {
	  ast_log(LOG_ERROR, "Too many receivers defined for host '%s' (max %d).\n", host->name, MAX_LINKS_PER_HOST);
	  return -1;
	}
	ast_log(LOG_DEBUG, "found link '%s'  on %s\n", v->name, host->name);
	receiver = &host->receivers[host->n_receivers];
	receiver->receiverix = host->n_receivers++;
	receiver->n_targets = 0;
	link->receiver = receiver;
	ast_copy_string(dup_spec_buf, v->value, sizeof(dup_spec_buf));
	spec = &dup_spec_buf[0];
	p = strsep(&spec, ",");
	while(p) {
	  char host_name_buf[100];
	  char if_name_buf[100];
	  struct host* target_host;
	  struct ipinterface* target_if = NULL;
	  char* if_name = &if_name_buf[3];

	  if(sscanf(p, "%[^#]#%s", host_name_buf, if_name_buf) != 2) {
	    ast_log(LOG_ERROR, "Invalid host#if specification '%s'.\n", p);
	    return -1;
	  }
	  if ((target_host = lookup_host(host_name_buf)) == NULL) {
	    ast_log(LOG_ERROR, "Host '%s' not found in dup spec '%s'.\n", host_name_buf, p);
	    return -1;
	  }
	  if (strncasecmp(if_name_buf, "if-", 3)) {
	    ast_log(LOG_ERROR, "Invalid interface name: '%s' in dup spec '%s'.\n", host_name_buf, p);
	    return -1;
	  }
	  for (i = 0; i < n_hosts; i++) {
	    if (!strcmp(hosts[i].name, host_name_buf)) {
	      for (j = 0; j < hosts[i].n_ifs; j++) {
		if (!strcmp(hosts[i].ifs[j].name, if_name)) {
		  target_if = &hosts[i].ifs[j];
		  break;
		}
	      }
	    }
	  }
	  if (!target_if) {
	    ast_log(LOG_ERROR, "Interface '%s' not found for host '%s'.\n", if_name_buf, host_name_buf);
	    return -1;
	  }
	  if (receiver->n_targets == 2*MAX_HOSTS) {
	    ast_log(LOG_ERROR, "Too many targets defined for link '%s' (max %d).\n", link->name, 2*MAX_HOSTS);
	    return -1;
	  }
	  receiver->targets[receiver->n_targets].host = target_host;
	  receiver->targets[receiver->n_targets].inf = target_if;
	  receiver->n_targets++;
	  ast_log(LOG_DEBUG, "Added target %s#%s for link %s on host %s \n", target_host->name, target_if->name, link->name, host->name);
	  p = strsep(&spec, ",");
	}
      }
      else {
	ast_log(LOG_WARNING, "The link '%s' is not used by any host.\n", v->name);
      }
    }
    v = v->next;
  }
  if (!has_port) {
    ast_log(LOG_WARNING, "Missing port entry in cluster section");
    return -1;
  }
  return 0;
}

int load_config(int reload)
{
  struct ast_config *cfg;
  static const char conffile_name[] = "ss7.conf";
  const char* prevcat = NULL;
  int i, j, k, l;

#if defined(USE_ASTERISK_1_2) ||  defined(USE_ASTERISK_1_4)
  cfg = ast_config_load(conffile_name);
#else
  struct ast_flags config_flags = {CONFIG_FLAG_NOCACHE};
  cfg = ast_config_load(conffile_name, config_flags);
#endif
  if(cfg == NULL) {
    ast_log(LOG_ERROR, "Unable to load config '%s'.\n", conffile_name);
    return -1;
  }


  memset(linksets, 0, sizeof(linksets));
  memset(hosts, 0, sizeof(hosts));
  memset(links, 0, sizeof(links));
  n_linksets = 0;
  n_links = 0;
  n_hosts = 0;

  while ((prevcat = ast_category_browse(cfg, prevcat)) != NULL) {
    if (strncasecmp(prevcat, "linkset-", 8) == 0) {
      if (load_config_linkset(cfg, prevcat))
	goto fail;
    }
    else if (strncasecmp(prevcat, "link-", 5) == 0) {
      if (load_config_link(cfg, prevcat))
	goto fail;
    }
    else if (strncasecmp(prevcat, "host-", 5) == 0) {
      if (load_config_host(cfg, prevcat))
	goto fail;
    }
    else if (strcasecmp(prevcat, "cluster") == 0) {
      if (load_config_cluster(cfg))
	goto fail;
    }
    else if (strcasecmp(prevcat, "jitter") == 0) {
      if (load_config_jitter(cfg))
       goto fail;
    }
    else {
      ast_log(LOG_ERROR, "Error invalid config category '%s'.\n", prevcat);
      goto fail;
    }
  }
  if ((this_host = find_my_host()) == NULL)
    goto fail;
  for (i = 0; i < n_linksets; i++) {
    if (!linksets[i].enabled)
      continue;
    if ((linksets[i].dpc) && (this_host->dpc[linksets[i].lsi])) {
      ast_log(LOG_ERROR, "DPC is specified in both host section and linkset section, linkset: %s'.\n", linksets[i].name);
      goto fail;
    }
    if ((linksets[i].opc) && (this_host->opc)) {
      ast_log(LOG_ERROR, "OPC is specified in both host section and linkset section, linkset: %s'.\n", linksets[i].name);
      goto fail;
    }
    if (!linksets[i].dpc)
      linksets[i].dpc = this_host->dpc[linksets[i].lsi];
    if (!linksets[i].opc)
      linksets[i].opc = this_host->opc;
    ast_log(LOG_NOTICE, "Configuring OPC %d, DPC %d for linkset '%s'.\n", linksets[i].opc, linksets[i].dpc, linksets[i].name);
  }
  for (i = 0; i < n_linksets; i++) {
    int any = 0;
    if (!linksets[i].enabled)
      continue;
    for (j = 0; j < linksets[i].n_links; j++) {
      for (k = 0; k < this_host->n_spans; k++) {
	for (l = 0; l < this_host->spans[k].n_links; l++) {
	  if (this_host->spans[k].links[l] == linksets[i].links[j]) {
	    if (!linksets[i].opc) {
	      ast_log(LOG_ERROR, "No OPC specified for linkset '%s'.\n", linksets[i].name);
	      goto fail;
	    }
	    if (!linksets[i].dpc) {
	      ast_log(LOG_ERROR, "No DPC specified for linkset '%s'.\n", linksets[i].name);
	      goto fail;
	    }
	    any = any || linksets[i].links[j]->enabled;
	  }
	}
      }
    }
    linksets[i].enabled = any;
    ast_log(LOG_DEBUG, "Setting linkset %d '%s' enabled %d\n", i, linksets[i].name, any);
  }
  if (!this_host->enabled) {
    ast_log(LOG_ERROR, "Host '%s' not enabled, quitting!\n", this_host->name);
    goto fail;
  }
  if (this_host->default_linkset) {
    int haslinkset = 0;
    for (k = 0; k < this_host->n_spans; k++) {
      for (l = 0; l < this_host->spans[k].n_links; l++) {
	if (this_host->spans[k].links[l]->enabled && this_host->spans[k].links[l]->linkset->enabled &&
	    (this_host->spans[k].links[l]->linkset == this_host->default_linkset))
	  haslinkset = 1;
      }
    }
    if (!haslinkset) {
      ast_log(LOG_ERROR, "Default linkset '%s' for host '%s' is not configured for this host!\n", this_host->default_linkset->name, this_host->name);
      goto fail;
    }
  }
  else {
    struct linkset* linkset = NULL;
    for (k = 0; k < this_host->n_spans; k++) {
      for (l = 0; l < this_host->spans[k].n_links; l++) {
	if (this_host->spans[k].links[l]->linkset->enabled) {
	  if (linkset && (linkset != this_host->spans[k].links[l]->linkset)) {
	    ast_log(LOG_ERROR, "Host '%s' has multiple linksets, no default_linkset specified, using '%s'\n", this_host->name, linkset->name);
	    goto foundone;
	  }
	  linkset = this_host->spans[k].links[l]->linkset;
	}
      }
    }
  foundone:
    this_host->default_linkset = linkset;
  }
  if (make_host_slinks())
    goto fail;
  if (make_group_linksets())
    goto fail;

  show_config();

  ast_config_destroy(cfg);
  return 0;

 fail:
  ast_config_destroy(cfg);
  return -1;
}

static void destroy_linksets(void)
{
  while (n_linksets-- > 0) {
    free(linksets[n_linksets].name);
    free(linksets[n_linksets].context);
    free(linksets[n_linksets].language);
    free(linksets[n_linksets].combined);
  }
}

static void destroy_links(void)
{
  while (n_links-- > 0) {
    free(links[n_links].name);
  }
}

static void destroy_hosts(void)
{
  while (n_hosts-- > 0) {
    free(hosts[n_hosts].name);
  }
}

void destroy_config(void)
{
  destroy_linksets();
  destroy_links();
  destroy_hosts();
}
