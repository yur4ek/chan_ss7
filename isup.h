/* isup.h - ISUP stuff.
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


/* ISUP message types. Q.763 table references in parenthesis. */
enum isup_msg_type {
  ISUP_IAM = 0x01,      /* Initial address (32) */
  ISUP_SAM = 0x02,      /* Subsequent address (35) */
  ISUP_INR = 0x03,      /* Information request (31) */
  ISUP_COT = 0x05,	/* Continuity (28) */
  ISUP_ACM = 0x06,      /* Address complete (21) */
  ISUP_CON = 0x07,      /* Connect (27) */
  ISUP_ANM = 0x09,      /* Answer (22) */
  ISUP_REL = 0x0c,      /* Release (33) */
  ISUP_SUS = 0x0d,	/* Suspend (38) */
  ISUP_RES = 0x0e,	/* Resume (38) */
  ISUP_RLC = 0x10,      /* Release complete (34) */
  ISUP_CCR = 0x11,	/* Continuity Check Request (39) */
  ISUP_RSC = 0x12,      /* Reset circuit (39) */
  ISUP_BLK = 0x13,      /* Blocking (39) */
  ISUP_UBL = 0x14,      /* Unblocking (39) */
  ISUP_BLA = 0x15,      /* Blocking acknowledgement (39) */
  ISUP_UBA = 0x16,      /* Unblocking acknowledgement (39) */
  ISUP_GRS = 0x17,      /* Circuit group reset (41) */
  ISUP_CGB = 0x18,      /* Curciut group blocking (40) */
  ISUP_CGU = 0x19,      /* Curciut group unblocking (40) */
  ISUP_CGA = 0x1a,      /* Curciut group blocking acknowledgement (40) */
  ISUP_CUA = 0x1b,      /* Curciut group unblocking acknowledgement (40) */
  ISUP_GRA = 0x29,      /* Circuit group reset acknowledgement (25) */
  ISUP_CPR = 0x2c,      /* Call progress (23) */
  ISUP_UEC = 0x2e,      /* Unequipped CIC (39) */
};

/* ISUP parameters. Q.763 section references in parenthesis. */

enum isup_parameter_code {
  IP_TRANSMISSION_MEDIUM_REQUIREMENT = 0x2,                   /* (3.54) */
  IP_CALLED_PARTY_NUMBER = 0x4,                               /* (3.9) */
  IP_SUBSEQUENT_NUMBER = 0x5,                                 /* (3.51) */
  IP_NATURE_OF_CONNECTION_INDICATORS = 0x6,                   /* (3.35) */
  IP_FORWARD_CALL_INDICATORS = 0x7,                           /* (3.23) */
  IP_CALLING_PARTYS_CATEGORY = 0x9,                           /* (3.11) */
  IP_CALLING_PARTY_NUMBER = 0xa,                              /* (3.10) */
  IP_REDIRECTING_NUMBER = 0xb,                                /* (3.44) */
  IP_REDIRECTION_NUMBER = 0xc,                                /* (3.46) */
  IP_BACKWARD_CALL_INDICATORS = 0x11,                         /* (3.5) */
  IP_CAUSE_INDICATORS = 0x12,                                 /* (3.12) */
  IP_REDIRECTION_INFORMATION = 0x13,                          /* (3.45) */
  IP_CIRCUIT_GROUP_SUPERVISION_MESSAGE_TYPE_INDICATOR = 0x15, /* (3.13) */
  IP_RANGE_AND_STATUS = 0x16,                                 /* (3.43) */
  IP_EVENT_INFORMATION = 0x24,                                /* (3.21) */
  IP_OPTIONAL_BACKWARD_CALL_INDICATORS = 0x29,                /* (3.5) */
  IP_SUSPEND_RESUME_INDICATORS = 0x22,                        /* (3.21) */
  IP_ECHO_CONTROL_INFORMATION = 0x37,                         /* (3.19) */
  IP_USER_SERVICE_INFORMATION = 0x1d,                         /* (3.57) */
  IP_ACCESS_TRANSPORT = 0x03,                                 /* (3.3) */
  IP_GENERIC_NUMBER = 0xc0,                                   /* (3.26) */
};

#define PHONENUM_MAX 20

/* Decoding of ISUP phone numbers. */
struct isup_phonenum {
  int present;                  /* If set, the number was present in message */
  int restricted;               /* Set if "presentation restrict" */
  int complete;                 /* Set if seen '.' terminator */
  char num[PHONENUM_MAX + 1];   /* Digits of the number, zero terminated */
};

/* Fields in a "release cause" parameter in REL ISUP message. */
struct isup_rel_cause {
  int coding_standard;
  int location;
  int cause_value;
};

/* Fields in a "backwards call indicators" parameter (ACM). */
struct isup_backwards_call_ind {
  int called_party_status;
  int charge_indicator;
};

/* Fields in "redirection information" parameter. */
struct isup_redir_info {
  int is_redirect;
  int reason;
  int count;
};

/* Fields in "range and status" parameter. */
struct isup_range_and_status {
  int range;                    /* Number of bits in status */
  unsigned char status[32];     /* Min. 2 and max. 256 status bits */
};

/* Possible values for generic number. */
struct generic_number {
  struct isup_phonenum dni;
  struct isup_phonenum ani;
  struct isup_phonenum rni;
};

/* Structure used to store decoded ISUP messages. */
struct isup_msg {
  int dpc;                      /* Destination point code */
  int opc;                      /* Originating point code */
  int sls;                      /* Signalling link selection */
  int cic;                      /* Circuit identification code */
  enum isup_msg_type typ;       /* Message type (IAM, ACM, ANM, ...) */
  union {
    /* Parameters for ISUP_IAM. */
    struct iam {
      struct isup_phonenum dni;
      struct isup_phonenum ani;
      struct isup_phonenum rni;
      struct isup_redir_info redir_inf;
      struct generic_number gni;
      int contcheck;
      int echocontrol;
      unsigned char trans_medium;
    } iam;
    struct {
      struct isup_phonenum sni;
    } sam;
    /* Parameters for ISUP_ACM. */
    struct {
      struct isup_backwards_call_ind back_ind;
      int obc_ind;
    } acm;
    /* Parameters for ISUP_ANM */
    struct {
      int obc_ind;
    } anm;
    /* Parameters for ISUP_CON */
    struct {
      struct isup_backwards_call_ind back_ind;
      int obc_ind;
    } con;
    /* Parameters for ISUP_REL. */
    struct {
      int cause;
      struct isup_phonenum rdni;
      struct isup_redir_info redir_inf;
    } rel;
    /* Parameters for ISUP_GRS. */
    struct {
      int range;
    } grs;
    /* Parameters for ISUP_GRA. */
    struct {
      struct isup_range_and_status range_status;
    } gra;
    /* Parameters for ISUP_CGB. */
    struct {
      int cgsmti;
      struct isup_range_and_status range_status;
    } cgb;
    /* Parameters for ISUP_CGU. */
    struct {
      int cgsmti;
      struct isup_range_and_status range_status;
    } cgu;
    /* Parameters for ISUP_CUA. */
    struct {
      int cgsmti;
      struct isup_range_and_status range_status;
    } cua;
    /* Parameters for ISUP_CPR. */
    struct {
      int event_info;
      int obc_ind;
    } cpr;
    /* Parameters for ISUP_SUS and ISUP_RES. */
    struct {
      int indicator;
    } sus;
  };
};


int decode_isup_msg(struct isup_msg *msg, ss7_variant variant, unsigned char *buf, int len);

/* Contruction of ISUP messages.
   Typical usage:

  unsigned char msg[MTP_MAX_PCK_SIZE];
  int current;
  int varpart_start;

  isup_msg_init(msg, sizeof(msg), opc, dpc, cic, typ, &current);
  isup_msg_add_fixed(msg, sizeof(msg), &current, fixed1, sizeof(fixed1));
  isup_msg_start_variable_part(msg, sizeof(msg), &varpart_start, &current,
                               1, // Number of variable length parameters
                               1); // True if an optional part is allowed by message type
  isup_msg_add_variable(msg, sizeof(msg), &varpart_start, &current,
                        variable1, sizeof(variable1));
  // The rest only if optional parameters are present.
  isup_msg_start_optional_part(msg, sizeof(msg), &varpart_start, &current);
  isup_msg_add_optional(msg, sizeof(msg), &current,
                        optional1_type, optional1, sizeof(optional1));
  isup_msg_end_optional_part(msg, sizeof(msg), &current);
  // Now current holds the total size of the message.

*/
void isup_msg_init(unsigned char *buf, int buflen, ss7_variant variant, int opc, int dpc, int cic,
                   enum isup_msg_type msg_type, int *current);
void isup_msg_add_fixed(unsigned char *buf, int buflen, int *current,
                        unsigned char *param, int param_len);
void isup_msg_start_variable_part(unsigned char *buf, int buflen,
                                  int *variable_ptr, int *current,
                                  int num_variable, int optional);
void isup_msg_add_variable(unsigned char *buf, int buflen, int *variable_ptr,
                           int *current, unsigned char *param, int param_len);
void isup_msg_start_optional_part(unsigned char *buf, int buflen, int *variable_ptr,
                                int *current);
void isup_msg_add_optional(unsigned char *buf, int buflen, int *current,
                           enum isup_parameter_code param_type,
                           unsigned char *param, int param_len) ;
void isup_msg_end_optional_part(unsigned char *buf, int buflen, int *current);
char* isupmsg(int typ);
int decode_isup_phonenum(int with_presentation_restrict, unsigned char *p, int len, void *data);
typedef int (*decoder_t)(unsigned char *, int, void *);
int param_decode(unsigned char *buf, int buflen, ...);
