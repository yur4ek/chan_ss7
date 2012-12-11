/* isup.c - ISUP stuff.
 *
 * Copyright (C) 2005-2011, Netfors ApS.
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

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>

#include "asterisk.h"
#include "asterisk/logger.h"


#include <netinet/in.h>
#include "config.h"
#include "isup.h"
#include "mtp.h"


/* Generic ISUP message parameter decoding.
   First two parameters are the raw bytes of the SIF field and the length of it.
   Then comes quadruples of (PARAMETER, SIZE, DECODER, DATA) for the mandatory
   fixed part, followed by a single `0'.
   Then comes triples of (PARAMETER, DECODER, DATA) for the mandatory variable
   part, followed by a single `0'.
   Finally triples of (PARAMETER, DECODER, DATA) for the optional part, followed
   by a single `0'. */
int param_decode(unsigned char *buf, int buflen, ...) {
  va_list args;
  struct {
    enum isup_parameter_code param_type;
    decoder_t decoder;
    void *decoder_data;
  } opt_decoders[100];
  int num_opt_decoders;
  enum isup_parameter_code type;
  int i, j;
  int res;

  va_start(args, buflen);
  i = 0;

  /* First do the mandatory fixed part. */
  while((type = va_arg(args, typeof(type))) != 0) {
    int param_len = va_arg(args, int);
    decoder_t decoder = va_arg(args, decoder_t);
    void *data = va_arg(args, void *);

    if(i + param_len > buflen) {
      ast_log(LOG_NOTICE, "Short ISUP message for parameter type %d, "
              "len %d < %d.\n", type, buflen, i + param_len);
      return 0;
    }

    if(decoder != NULL) {
      res = (*decoder)(&(buf[i]), param_len, data);
      if(!res) {
        return res;
      }
    }

    i += param_len;
  }

  /* Next do the mandatory variable part. */
  while((type = va_arg(args, typeof(type))) != 0) {
    decoder_t decoder = va_arg(args, decoder_t);
    void *data = va_arg(args, void *);
    int param_start, param_len;

    if(i >= buflen) {
      ast_log(LOG_NOTICE, "Short ISUP message for parameter type %d, "
              "len %d < %d.\n", type, buflen, i + 1);
      return 0;
    }
    param_start = i + buf[i];
    if(i >= buflen) {
      ast_log(LOG_NOTICE, "Short ISUP message for parameter type %d, "
              "len %d < %d.\n", type, buflen, i + 1);
      return 0;
    }
    param_len = buf[param_start++];
    if(param_start + param_len > buflen) {
      ast_log(LOG_NOTICE, "Short ISUP message for parameter type %d, "
              "len %d < %d.\n", type, buflen, param_start + param_len);
      return 0;
    }
    if(decoder != NULL) {
      res = (*decoder)(&(buf[param_start]), param_len, data);
      if(!res) {
        return res;
      }
    }

    i++;
  }

  /* Finally do the optional part. First build a list of all decoders. */
  for(j = 0; (type = va_arg(args, typeof(type))) != 0; j++) {
    if(j >= sizeof(opt_decoders)/sizeof(opt_decoders[0])) {
      ast_log(LOG_ERROR, "Fatal: too many decoders.\n");
      return 0;
    }
    opt_decoders[j].param_type = type;
    opt_decoders[j].decoder = va_arg(args, decoder_t);
    opt_decoders[j].decoder_data = va_arg(args, void *);
  }
  va_end(args);
  num_opt_decoders = j;

  if(num_opt_decoders == 0) {
    /* There are no optional parameters needed, so we are done. */
    return 1;
  }

  /* Find the start of the optional part. */
  if(i >= buflen) {
    ast_log(LOG_NOTICE, "Short ISUP message for optional part, len %d < %d.\n",
            buflen, i + 1);
    return 0;
  }
  if(buf[i] == 0) {
    /* No optional parameters are present in the message. */
    return 1;
  }
  i = i + buf[i];

  /* Loop over each parameter in the optional section. */
  for(;;) {
    enum isup_parameter_code type;
    int param_len;

    if(i + 1 > buflen) {
      ast_log(LOG_NOTICE, "Short ISUP message for optional part, len %d < %d.\n",
              buflen, i + 1);
      return 0;
    }
    type = buf[i];
    if(type == 0) {
      /* End of optional parameters. */
      return 1;
    }
    if(i + 2 > buflen) {
      ast_log(LOG_NOTICE, "Short ISUP message for optional parameter type %d, "
              "len %d < %d.\n", type, buflen, i + 2);
      return 0;
    }
    param_len = buf[i + 1];
    if(i + 2 + param_len > buflen) {
      ast_log(LOG_NOTICE, "Short ISUP message for optional parameter type %d, "
              "len %d < %d.\n", type, buflen, i + 2 + param_len);
      return 0;
    }

    /* Call any matching decoder. */
    for(j = 0; j < num_opt_decoders; j++) {
      if(opt_decoders[j].param_type == type) {
        if(opt_decoders[j].decoder != NULL) {
          res = (*(opt_decoders[j].decoder))(&(buf[i + 2]), param_len, opt_decoders[j].decoder_data);
          if(!res) {
            return res;
          }
        }
        break;
      }
    }
    i = i + 2 +param_len;
  }
}

/* Decode parameter 0x29, "optional backward call indicators" (Q.763 (3.37)). */
static int decode_optional_backward_call_indicators(unsigned char *p, int len, void *data) {
  int *event_info_ptr = data;

  if(len < 1) {
    ast_log(LOG_NOTICE, "Short parameter 'optional backward call indicator', len %d < 1.\n", len);
    return 0;
  }
  *event_info_ptr = p[0] & 0xf;
  return 1;
}

/* Decode parameter 0x24, "event information" (Q.763 (3.21)). */
static int decode_event_info(unsigned char *p, int len, void *data) {
  int *event_info_ptr = data;

  if(len < 1) {
    ast_log(LOG_NOTICE, "Short parameter 'event information', len %d < 1.\n", len);
    return 0;
  }
  *event_info_ptr = p[0] & 0x7f;
  return 1;
}

/* Decode parameter 0x12 "cause indicators" (Q.763 (see Q.850 for values). */
static int decode_rel_cause(unsigned char *p, int len, void *data) {
  int *cause_ptr = data;

  if(len < 2) {
    ast_log(LOG_NOTICE, "Short parameter 'cause indicators', len %d < 2.\n", len);
    return 0;
  }
  *cause_ptr = p[1] & 0x7f;
  return 1;
}

/* Decode parameter 0x22 "suspend resume indicators" (Q.763 (3.52). */
static int decode_suspend_resume(unsigned char *p, int len, void *data) {
  int *indicator = data;

  if(len < 1) {
    ast_log(LOG_NOTICE, "Short parameter 'suspend/resume indicators', len %d < 1.\n", len);
    return 0;
  }
  *indicator = p[0];
  return 1;
}

/* Decode parameter 0x11, "backwards call indicators" (Q.763 (3.5)). */
static int decode_backwards_ind(unsigned char *p, int len, void *data) {
  struct isup_backwards_call_ind *ind_ptr = data;

  if(len < 2) {
    ast_log(LOG_NOTICE, "Short parameter 'cause indicators', len %d < 2.\n", len);
    return 0;
  }
  ind_ptr->called_party_status = (p[0] >> 2) & 0x3;
  ind_ptr->charge_indicator = p[0] & 0x3;
  return 1;
}

/* Decode parameter 0x16 "range and status". */
static int decode_range_and_status(unsigned char *p, int len, void *data) {
  struct isup_range_and_status *parm = data;
  int status_len;

  if(len < 1) {
    ast_log(LOG_NOTICE, "Short parameter 'range and status', len %d < 1.\n", len);
    return 0;
  }
  parm->range = p[0];

  if(parm->range == 0) {
    ast_log(LOG_NOTICE, "Invalid range 0 (must be >= 1) in range and status.\n");
    return 0;
  }

  status_len = ((parm->range + 1) + 7)/8;
  if(len < 1 + status_len) {
    ast_log(LOG_NOTICE, "Short parameter 'range and status', len %d < %d.\n",
            len, 1 + status_len);
    return 0;
  }

  memcpy(parm->status, &p[1], status_len);
  return 1;
}

/* Decode parameter 0x16 "range and status", in the variant used in the GRS
   message type where status is missing. */
static int decode_range_no_status(unsigned char *p, int len, void *data) {
  int *range_ptr = data;

  if(len < 1) {
    ast_log(LOG_NOTICE, "Short parameter 'range and no status', len %d < 1.\n", len);
    return 0;
  }
  *range_ptr = p[0];
  return 1;
}

/* Decode parameter 0x15 "circuit group supervision message type indicator"
   (Q.763 (3.13)). */
static int decode_cgsmti(unsigned char *p, int len, void *data) {
  int *cgsmti_ptr = data;
  int cgsmti;

  if(len < 1) {
    ast_log(LOG_NOTICE, "Short parameter 'circuit group supervision message "
            "type indicator', len %d < 1.\n", len);
    return 0;
  }
  cgsmti = p[0] & 0x3;
  if(cgsmti != 0 && cgsmti != 1) {
    ast_log(LOG_NOTICE, "Unimplemented 'circuit group supervision message "
            "type indicator' value %d.\n", cgsmti);
    return 0;
  }
  *cgsmti_ptr = cgsmti;
  return 1;
}

/* Decode parameter 0x6 "nature of connection indicators" (Q.763 (3.35)).
   For now, only decodes the "continuity check required" part. */
static int decode_noci_contcheck(unsigned char *p, int len, void *data) {
  struct iam *iam = data;

  if(len < 1) {
    ast_log(LOG_NOTICE, "Short parameter 'nature of connection indicators', "
            "len %d < 1.\n", len);
    return 0;
  }
  iam->contcheck   = ((p[0] >> 2) & 0x3) == 0x1;
  iam->echocontrol =  (p[0] >> 4) & 0x1;
  return 1;
}


static int decode_transmission_medium(unsigned char *p, int len, void *data) {
  struct iam *iam = data;

  if(len < 1) {
    ast_log(LOG_NOTICE, "Short parameter 'Transmission medium requirement', "
            "len %d < 1.\n", len);
    return 0;
  }
  iam->trans_medium = p[0];
  return 1;
}


/* Decode parameter 0x13 "redirection information" (Q.763 (3.45)). */
static int decode_redir_inf(unsigned char *p, int len, void *data) {
  struct isup_redir_info *redir_inf_ptr = data;

  if(len < 1) {
    ast_log(LOG_NOTICE, "Short parameter 'redirection information', "
            "len %d < 1.\n", len);
    return 0;
  }

  redir_inf_ptr->is_redirect = p[0];
  if(len >= 2) {
    redir_inf_ptr->reason = (p[1] >> 4) & 0xf;
  } else {
    redir_inf_ptr->reason = 0;
  }

  return 1;
}

static void clear_isup_phonenum(struct isup_phonenum *num) {
  num->present = 0;
  num->restricted = 0;
  num->complete = 0;
  memset(num->num, 0, sizeof(num->num));
}

static int decode_isup_sni(unsigned char *p, int len, void *data) {
  static char digits[] = "0123456789ABCDE.";
  struct isup_phonenum *n = data;
  int i, j;
  int num_dig;

  if(len < 2) {
    ast_log(LOG_NOTICE, "Short parameter for ISUP phone number, len %d < 2.\n",
            len);
    return 0;
  }

  /* Two digits per byte, but only one digit in last byte if odd number of
     digits. */
  num_dig = (len-1)*2 - (p[0] & 0x80 ? 1 : 0);

  i = 0;
  /* Handle international number. */

  if(num_dig > PHONENUM_MAX) {
    ast_log(LOG_NOTICE, "Too many digits in phone number %d > %d, truncated.\n",
            num_dig, PHONENUM_MAX);
    num_dig = PHONENUM_MAX;
  }

  /* TODO: if p[0]=128 -> only first digit! */
  j = 1;
  while(i < num_dig) {
    int dig = p[j] & 0x0f;
    if(dig == 0xf) {
      n->complete = 1;
      break;
    }
    n->num[i++] = digits[dig];
    if(i < num_dig) {
      int dig = (p[j++] >> 4) & 0xf;
      if(dig == 0xf) {
        n->complete = 1;
        break;
      }
      n->num[i++] = digits[dig];
    }
  }
  n->num[i] = '\0';

  return 1;
}

/* Decode ISUP phonenum parameters:
     0x4 "called party number" (Q.763 (3.9))
     0xa "calling party number" (Q.763 (3.10))
     0xb "redirecting number" (Q.763 (3.44)) */
int decode_isup_phonenum(int with_presentation_restrict, unsigned char *p, int len, void *data) {
  static char digits[] = "0123456789ABCDE.";
  struct isup_phonenum *n = data;
  int i, j;
  int num_dig;
  int nature_of_adr_ind;

  if(len < 2) {
    ast_log(LOG_NOTICE, "Short parameter for ISUP phone number, len %d < 2.\n",
            len);
    return 0;
  }

  if(with_presentation_restrict) {
    switch((p[1] >> 2) & 0x3) {
      case 0:                   /* Presentation allowed */
        n->present = 1;
        n->restricted = 0;
        n->complete = 0;
        break;

      case 1:                   /* Presentation restricted */
        n->present = 1;
        n->restricted = 1;
        n->complete = 0;
        break;

      case 2:                   /* Address not available */
        n->present = 0;
        n->restricted = 0;
        n->complete = 1;
        break;

      case 3:                   /* Reserved */
        ast_log(LOG_NOTICE, "Found presentation restrict type 0x3, assuming "
                "not restricted and not complete.\n");
        n->present = 1;
        n->restricted = 0;
        n->complete = 0;
        break;

      default:
        ast_log(LOG_ERROR, "This cannot happen!?!.\n");
    }
  } else {
    n->present = 1;
    n->restricted = 0;
    n->complete = 0;
  }

  memset(n->num, 0, sizeof(n->num));
  if(len == 2) {
    ast_log(LOG_DEBUG, "No digits in phone number.\n");
    return 1;
  }

  /* Two digits per byte, but only one digit in last byte if odd number of
     digits. */
  num_dig = (len - 2)*2 - (p[0] & 0x80 ? 1 : 0);

  i = 0;
  // Handle international number.
  nature_of_adr_ind = p[0] & 0x7f;
  switch(nature_of_adr_ind) {
    case 0x70:                  // Hong Kong CSL
    case 0x03:                  // National (significant) number.
      break;
    case 0x01:                  // Subscriber local number. Getting this has
                                // got to be wrong, but we've seen it 'in the
                                // wild' where they looked like international.

    case 0x02:                  // Unknown; again experience suggests
                                // this should be international.
      ast_log(LOG_NOTICE,"National (significant) or unknown nature of address "
              "indicator (%d), assuming international.\n", nature_of_adr_ind);
      // Intentionally fall-through.

    case 0x04:                  // International -> add '00'.
      num_dig++;
      n->num[i++] = '0';
      num_dig++;
      n->num[i++] = '0';
      break;
    default:
      ast_log(LOG_NOTICE, "unknown nature of address indicator 0x%0x.\n",
              nature_of_adr_ind);
      return 0;
  }

  if(num_dig > PHONENUM_MAX) {
    ast_log(LOG_NOTICE, "Too many digits in phone number %d > %d, truncated.\n",
            num_dig, PHONENUM_MAX);
    num_dig = PHONENUM_MAX;
  }

  j = 2;
  while(i < num_dig) {
    int dig = p[j] & 0x0f;
    if(dig == 0xf) {
      n->complete = 1;
      break;
    }
    n->num[i++] = digits[dig];
    if(i < num_dig) {
      int dig = (p[j++] >> 4) & 0xf;
      if(dig == 0xf) {
        n->complete = 1;
        break;
      }
      n->num[i++] = digits[dig];
    }
  }
  n->num[i] = '\0';

  return 1;
}

static int decode_dni(unsigned char *p, int len, void *data) {
  return decode_isup_phonenum(0, p, len, data);
}

static int decode_sni(unsigned char *p, int len, void *data) {
  return decode_isup_sni(p, len, data);
}

static int decode_ani_rni(unsigned char *p, int len, void *data) {
  return decode_isup_phonenum(1, p, len, data);
}

/* Decode parameter 0xc0 "generic number" (Q.763 (3.26)). */
static int decode_generic_number(unsigned char *p, int len, void *data) {
  struct generic_number *gni = data;
  unsigned char gnqi = *p;

  if(len < 4) {
    ast_log(LOG_NOTICE, "Short parameter 'generic number' len %d < 4.\n", len);
    return 0;
  }
  p++; len--;
  switch (gnqi) {
  case 1: /* Additional called number (national use) */
    return decode_isup_phonenum(1, p, len, &gni->dni);
  case 4: /* Reserved for additional redirecting termination number (national use) */
    return decode_isup_phonenum(1, p, len, &gni->rni);
  case 5: /* Additional connected number */
    return decode_isup_phonenum(1, p, len, &gni->dni);
  case 6: /* Additional calling party number */
    return decode_isup_phonenum(1, p, len, &gni->ani);
  case 7: /* Reserved for additional original called number */
  case 8: /* Reserved for additional redirecting number */
  case 9: /* Reserved for additional redirection number */
    ast_log(LOG_DEBUG, "Unhandled generic number qualifier indicator %d\n", gnqi);
    break;
  default:
    ast_log(LOG_NOTICE, "Unknown/reserved generic number qualifier indicator %d\n", gnqi);
  }
  return 1;
}

/* Decode raw SIF field into ISUP message.
   Returns true on success, false on error. */
int decode_isup_msg(struct isup_msg *msg, ss7_variant variant, unsigned char *buf, int len) {
  
  int i;
  memset(msg, 0, sizeof(*msg));
  
  if(variant==ITU_SS7)
  	i = 7;
  else if(variant==ANSI_SS7)
  	i = 10;
  else
  	i =10;
  
  if(len < i) {
    ast_log(LOG_NOTICE, "Got short ISUP message (len=%d < %d).\n", len, i);
    return 0;
  }

  if(variant==ITU_SS7) {
    msg->dpc = buf[0] | ((buf[1] & 0x3f) << 8);
    msg->opc = ((buf[1] & 0xc0) >> 6) | (buf[2] << 2) | ((buf[3] & 0x0f) << 10);
    msg->sls = (buf[3] & 0xf0) >> 4;

    msg->cic = buf[4] | ((buf[5] & 0x0f) << 8);
    msg->typ = buf[6];
    buf += 7;
    len -= 7;
  }
  else if(variant==ANSI_SS7) {
    msg->dpc = buf[0] | ((buf[1] & 0xff) << 8) | ((buf[2] & 0xff) << 16);
    msg->opc = buf[3] | ((buf[4] & 0xff) << 8) | ((buf[5] & 0xff) << 16);
    msg->sls = buf[6] & 0x0f;

    msg->cic = buf[7] | ((buf[8] & 0x0f) << 8);
    msg->typ = buf[9];

    buf += 10;
    len -= 10;
  } else { /* CHINA SS7 */
    msg->dpc = buf[0] | ((buf[1] & 0xff) << 8) | ((buf[2] & 0xff) << 16);
    msg->opc = buf[3] | ((buf[4] & 0xff) << 8) | ((buf[5] & 0xff) << 16);
    msg->sls = buf[6] & 0x0f;

    msg->cic = buf[7] | ((buf[8] & 0x0f) << 8);
    msg->typ = buf[9];

    buf += 10;
    len -= 10;
  }

  switch(msg->typ) {
    case ISUP_IAM:
      /* Must initialize optional parameters, in case they are no
         present in message. */
      clear_isup_phonenum(&msg->iam.ani);
      clear_isup_phonenum(&msg->iam.rni);
      msg->iam.redir_inf.is_redirect = 0;
      msg->iam.redir_inf.reason = 0;
      if(variant==ANSI_SS7)
	return param_decode(buf, len,
			    IP_NATURE_OF_CONNECTION_INDICATORS, 1, decode_noci_contcheck, &msg->iam,
			    IP_FORWARD_CALL_INDICATORS, 2, NULL, NULL,
			    IP_CALLING_PARTYS_CATEGORY, 1, NULL, NULL,
			    0,
			    IP_USER_SERVICE_INFORMATION, NULL, NULL,
			    IP_CALLED_PARTY_NUMBER, decode_dni, &msg->iam.dni,
			    0,
			    IP_CALLING_PARTY_NUMBER, decode_ani_rni, &msg->iam.ani,
			    IP_REDIRECTING_NUMBER, decode_ani_rni, &msg->iam.rni,
			    IP_REDIRECTION_INFORMATION, decode_redir_inf, &msg->iam.redir_inf,
			    IP_GENERIC_NUMBER, decode_generic_number, &msg->iam.gni,
			    0);
      else
	return param_decode(buf, len,
			    IP_NATURE_OF_CONNECTION_INDICATORS, 1, decode_noci_contcheck, &msg->iam,
			    IP_FORWARD_CALL_INDICATORS, 2, NULL, NULL,
			    IP_CALLING_PARTYS_CATEGORY, 1, NULL, NULL,
			    IP_TRANSMISSION_MEDIUM_REQUIREMENT, 1, decode_transmission_medium, &msg->iam,
			    0,
			    IP_CALLED_PARTY_NUMBER, decode_dni, &msg->iam.dni,
			    0,
			    IP_CALLING_PARTY_NUMBER, decode_ani_rni, &msg->iam.ani,
			    IP_REDIRECTING_NUMBER, decode_ani_rni, &msg->iam.rni,
			    IP_REDIRECTION_INFORMATION, decode_redir_inf, &msg->iam.redir_inf,
			    IP_GENERIC_NUMBER, decode_generic_number, &msg->iam.gni,
			    0);

    case ISUP_SAM:
      /* Must initialize optional parameters, in case they are not
	 present in message. */
      clear_isup_phonenum(&msg->sam.sni);
      return param_decode(buf, len,
			  0,
			  IP_SUBSEQUENT_NUMBER, decode_sni, &msg->sam.sni,
			  0,
			  0);

    case ISUP_ACM:
      return param_decode(buf, len,
                          IP_BACKWARD_CALL_INDICATORS, 2, decode_backwards_ind, &(msg->acm.back_ind),
                          0,
                          0,
			  IP_OPTIONAL_BACKWARD_CALL_INDICATORS, decode_optional_backward_call_indicators, &(msg->acm.obc_ind),
                          0);

    case ISUP_BLK:
      return param_decode(buf, len,
                          0,
                          0,
                          0);

    case ISUP_BLA:
      return param_decode(buf, len,
                          0,
                          0,
                          0);

    case ISUP_CON:
      return param_decode(buf, len,
                          IP_BACKWARD_CALL_INDICATORS, 2, decode_backwards_ind, &(msg->con.back_ind),
                          0,
                          0,
			  IP_OPTIONAL_BACKWARD_CALL_INDICATORS, decode_optional_backward_call_indicators, &(msg->anm.obc_ind),
                          0);

    case ISUP_ANM:
      return param_decode(buf, len,
                          0,
                          0,
                          IP_BACKWARD_CALL_INDICATORS, NULL, NULL,
			  IP_OPTIONAL_BACKWARD_CALL_INDICATORS, decode_optional_backward_call_indicators, &(msg->anm.obc_ind),
                          0);

    case ISUP_REL:
      return param_decode(buf, len,
                          0,
                          IP_CAUSE_INDICATORS, decode_rel_cause, &(msg->rel.cause),
                          0,
                          IP_REDIRECTION_NUMBER, decode_dni, &msg->rel.rdni,
                          IP_REDIRECTION_INFORMATION, decode_redir_inf, &msg->rel.redir_inf,
                          0);

    case ISUP_RLC:
      if(variant==ANSI_SS7)
	return param_decode(buf, len,
			    0,
			    0,
			    0,
			    0);
      else
	return param_decode(buf, len,
			    0,
			    0,
			    IP_CAUSE_INDICATORS, NULL, NULL,
			    0);

    case ISUP_SUS:
      return param_decode(buf, len,
                          IP_SUSPEND_RESUME_INDICATORS, 1, decode_suspend_resume, &(msg->sus.indicator),
                          0,
                          0,
                          0);

    case ISUP_RES:
      return param_decode(buf, len,
                          IP_SUSPEND_RESUME_INDICATORS, 1, decode_suspend_resume, &(msg->sus.indicator),
                          0,
                          0,
                          0);

    case ISUP_RSC:
      return param_decode(buf, len,
                          0,
                          0,
                          0);

    case ISUP_GRS:
      return param_decode(buf, len,
                          0,    /* End of mandatory fixed part */
                          IP_RANGE_AND_STATUS, decode_range_no_status, &(msg->grs.range),
                          0,    /* End of mandatory variable part */
                          0);   /* End of optional part */

    case ISUP_GRA:
      return param_decode(buf, len,
                          0,
                          IP_RANGE_AND_STATUS, decode_range_and_status, &(msg->gra.range_status),
                          0,
                          0);

    case ISUP_CGB:
      return param_decode(buf, len,
                          IP_CIRCUIT_GROUP_SUPERVISION_MESSAGE_TYPE_INDICATOR, 1, decode_cgsmti, &(msg->cgb.cgsmti),
                          0,
                          IP_RANGE_AND_STATUS, decode_range_and_status, &(msg->cgb.range_status),
                          0,
                          0);

    case ISUP_CGA:
      return param_decode(buf, len,
                          IP_CIRCUIT_GROUP_SUPERVISION_MESSAGE_TYPE_INDICATOR, 1, decode_cgsmti, &(msg->cgb.cgsmti),
                          0,
                          IP_RANGE_AND_STATUS, decode_range_and_status, &(msg->cgb.range_status),
                          0,
                          0);

    case ISUP_CGU:
      return param_decode(buf, len,
                          IP_CIRCUIT_GROUP_SUPERVISION_MESSAGE_TYPE_INDICATOR, 1, decode_cgsmti, &(msg->cgu.cgsmti),
                          0,
                          IP_RANGE_AND_STATUS, decode_range_and_status, &(msg->cgu.range_status),
                          0,
                          0);

    case ISUP_CUA:
      return param_decode(buf, len,
                          IP_CIRCUIT_GROUP_SUPERVISION_MESSAGE_TYPE_INDICATOR, 1, decode_cgsmti, &(msg->cua.cgsmti),
                          0,
                          IP_RANGE_AND_STATUS, decode_range_and_status, &(msg->cua.range_status),
                          0,
                          0);

    case ISUP_CPR:
      return param_decode(buf, len,
                          IP_EVENT_INFORMATION, 1, decode_event_info, &(msg->cpr.event_info),
                          0,
                          0,
			  IP_OPTIONAL_BACKWARD_CALL_INDICATORS, decode_optional_backward_call_indicators, &(msg->cpr.obc_ind),
                          0);

    case ISUP_UBL:
      return param_decode(buf, len,
                          0,
                          0,
                          0);

    case ISUP_UBA:
      return param_decode(buf, len,
                          0,
                          0,
                          0);

    case ISUP_UEC:
      return param_decode(buf, len,
                          0,
                          0,
                          0);

    case ISUP_CCR:
      return param_decode(buf, len,
                          0,
                          0,
                          0);

    case ISUP_COT:
      return param_decode(buf, len,
                          0,
                          0,
                          0);

    default:
      ast_log(LOG_DEBUG, "Got unknown ISUP message type %d.\n", msg->typ);
      return 0;
  }
}

void isup_msg_init(unsigned char *buf, int buflen, ss7_variant variant, int opc, int dpc, int cic,
                   enum isup_msg_type msg_type, int *current) {
  if(buflen < 7) {
    ast_log(LOG_ERROR, "Buffer too small, size %d < 7.\n", buflen);
    return;
  }

  *current = 0;
  mtp3_put_label((cic & 0x000f), variant, opc, dpc, &(buf[*current]));
  if(variant==ITU_SS7) {
    *current += 4;
    buf[(*current)++] = cic & 0xff;
    buf[(*current)++] = (cic & 0x0f00) >> 8;
    buf[(*current)++] = msg_type;
  }
  else if(variant==ANSI_SS7) {
    *current += 7;
    buf[(*current)++] = cic & 0xff;
    buf[(*current)++] = (cic & 0x0f00) >> 8;
    buf[(*current)++] = msg_type;
  } else { /* CHINA SS7 */
    *current += 7;
    buf[(*current)++] = cic & 0xff;
    buf[(*current)++] = (cic & 0x0f00) >> 8;
    buf[(*current)++] = msg_type;
  }
}

void isup_msg_add_fixed(unsigned char *buf, int buflen, int *current,
                        unsigned char *param, int param_len) {
  if(param_len < 0 || param_len > 255) {
    ast_log(LOG_ERROR, "Unreasonable size of parameter %d.\n", param_len);
    return;
  }
  if(*current + param_len > buflen) {
    ast_log(LOG_ERROR, "Buffer too small for fixed parameter, size "
            "%d < %d.\n", buflen, *current + param_len);
    return;
  }
  memcpy(&(buf[*current]), param, param_len);
  *current += param_len;
}

void isup_msg_start_variable_part(unsigned char *buf, int buflen,
                                  int *variable_ptr, int *current,
                                  int num_variable, int optional) {
  int needed_size = num_variable + (optional ? 1 : 0);
  if(*current + needed_size > buflen) {
    ast_log(LOG_ERROR, "Buffer too small for variable part of ISUP message, "
            "size %d < %d.\n", buflen, *current + needed_size);
    return;
  }
  *variable_ptr = *current;
  memset(&(buf[*current]), 0, needed_size);
  *current += needed_size;
}

/* The value to be passed for VARIABLE_PTR is initalized by the call
   to isup_msg_start_variable_part(). */
void isup_msg_add_variable(unsigned char *buf, int buflen, int *variable_ptr,
                           int *current, unsigned char *param, int param_len) {
  if(param_len < 0 || param_len > 255) {
    ast_log(LOG_ERROR, "Unreasonable size of parameter length %d.\n", param_len);
    return;
  }
  if(*variable_ptr >= *current) {
    ast_log(LOG_ERROR, "Internal: variable_ptr=%d >= current=%d.\n",
            *variable_ptr, *current);
    return;
  }
  if(*current + 1 + param_len > buflen) {
    ast_log(LOG_ERROR, "Buffer too small for variable parameter, size "
            "%d < %d.\n", buflen, *current + 1 + param_len);
    return;
  }
  if(*current - *variable_ptr > 255) {
    ast_log(LOG_ERROR, "Too much data in variable part, %d > 255.\n",
            *current - *variable_ptr);
    return;
  }

  buf[*variable_ptr] = *current - *variable_ptr;
  (*variable_ptr)++;
  buf[(*current)++] = param_len;
  memcpy(&(buf[*current]), param, param_len);
  *current += param_len;
}

/* Only call this if there will follow calls to isup_msg_add_optional().
   If optional parameters are allowed for the message type, but none will be
   included in this particular message, pass 1 for OPTIONAL in the call to
   isup_msg_start_variable_part(), but do not call isup_msg_start_optional_part().
*/
void isup_msg_start_optional_part(unsigned char *buf, int buflen, int *variable_ptr,
                                int *current) {
  if(*variable_ptr >= *current) {
    ast_log(LOG_ERROR, "Internal: variable_ptr=%d >= current=%d.\n",
            *variable_ptr, *current);
    return;
  }
  if(*current + 1 > buflen) {   /* The "+1" is room for the end marker */
    ast_log(LOG_ERROR, "Buffer too small for optional parameter, size "
            "%d < %d.\n", buflen, *current + 1);
    return;
  }
  if(*current - *variable_ptr > 255) {
    ast_log(LOG_ERROR, "Too much data in variable part, %d > 255.\n",
            *current - *variable_ptr);
    return;
  }

  buf[*variable_ptr] = *current - *variable_ptr;
  (*variable_ptr)++;
}

void isup_msg_add_optional(unsigned char *buf, int buflen, int *current,
                           enum isup_parameter_code param_type,
                           unsigned char *param, int param_len) {
  if(param_len < 0 || param_len > 255) {
    ast_log(LOG_ERROR, "Unreasonable size of parameter length %d.\n", param_len);
    return;
  }
  if(*current + 2 + param_len > buflen) {
    ast_log(LOG_ERROR, "Buffer too small for optional parameter, "
            "size %d < %d.\n", buflen, *current + 2 + param_len);
    return;
  }

  buf[(*current)++] = param_type;
  buf[(*current)++] = param_len;
  memcpy(&(buf[*current]), param, param_len);
  *current += param_len;
}

/* Only call this if at least one optional parameter was added. */
void isup_msg_end_optional_part(unsigned char *buf, int buflen, int *current) {
  if(*current + 1 > buflen) {
    ast_log(LOG_ERROR, "Buffer too small for optional parameter end marker, "
            "size %d < %d.\n", buflen, *current + 1);
    return;
  }

  buf[(*current)++] = 0;
}

char* isupmsg(int typ)
{
  switch (typ) {
  case ISUP_IAM: return "IAM";
  case ISUP_SAM: return "SAM";
  case ISUP_INR: return "INR";
  case ISUP_COT: return "COT";
  case ISUP_ACM: return "ACM";
  case ISUP_CON: return "CON";
  case ISUP_ANM: return "ANM";
  case ISUP_REL: return "REL";
  case ISUP_SUS: return "SUS";
  case ISUP_RES: return "RES";
  case ISUP_RLC: return "RLC";
  case ISUP_CCR: return "CCR";
  case ISUP_RSC: return "RSC";
  case ISUP_BLK: return "BLK";
  case ISUP_UBL: return "UBL";
  case ISUP_BLA: return "BLA";
  case ISUP_UBA: return "UBA";
  case ISUP_GRS: return "GRS";
  case ISUP_CGB: return "CGB";
  case ISUP_CGU: return "CGU";
  case ISUP_CGA: return "CGA";
  case ISUP_CUA: return "CUA";
  case ISUP_GRA: return "GRA";
  case ISUP_CPR: return "CPR";
  case ISUP_UEC: return "UEC";
  default: {
    /* This is non reentrant! */
    static char buf[30];
    sprintf(buf, "unknown(%d)", typ);
    return buf;
  }
  }
}
