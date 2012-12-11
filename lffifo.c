/* fifo.c - Lock-free FIFO for use in chan_ss7.

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

/* Lock-free FIFO. Used to communicate between the real-time MTP2 thread and
   the rest of Asterisk.

   Uses lock-free operation to avoid priority inversion and other problems that
   could cause delay in the real-time MTP2 thread and thereby lead to line
   errors.

   Uses special marker bytes for free buffer space; this avoids the needs for
   non-portable memory barriers to avoid load/store reordering messing up the
   inter-thread synchronisation.
*/

#include <stdlib.h>
#include <string.h>

#include "lffifo.h"


/* Escape bytes used to mark unused space, for framing, etc. Chosen to be
   fairly infrequent in typical data, to save on escaping overhead. */
#define BYT_EMPTY 0xfe
#define BYT_ESCAPE 0xfd
/* These bytes are used after BYT_ESCAPE to denote special values.
   They MUST be different from BYT_EMPTY. */
#define BYT_ESCAPED_EMPTY 0x00
#define BYT_ESCAPED_ESCAPE 0x01
#define BYT_ESCAPED_FRAME_END 0x02


struct lffifo {
  int size;
  int start;
  int end;
  unsigned char buf[0];
};


/* Public functions. */

struct lffifo *lffifo_alloc(int size) {
  struct lffifo *p;

  if(size <= 0 || size > 1e9) {
    return NULL;
  }

  p = malloc(sizeof(*p) + size);
  if(p == NULL) {
    return NULL;
  }

  p->size = size;
  p->start = 0;
  p->end = 0;
  memset(p->buf, BYT_EMPTY, p->size);

  return p;
}

void lffifo_free(struct lffifo *fifo) {
  free(fifo);
}

int lffifo_put(struct lffifo *fifo, unsigned char *data, int size) {
  int i,j;
  int x;
  int iteration;

  /* Sanity check */
  if(size <= 0 || size > 0x10000000) {
    return 1;
  }

  /* Do this twice: first to check that there is room, and after to actually
     put the data into the buffer. We don't want to worry about reader
     issues with partial frames that do not fit in the fifo. */
  for(iteration = 0; iteration < 2; iteration++) {
    i = fifo->end;
    for(j = 0; j <= size; j++) {
      /* We do one extra iteration at the end to insert the frame end marker. */
      x = (j == size ? -1 : data[j]);

      if(iteration == 0 && fifo->buf[i] != BYT_EMPTY) {
        return 1;               /* FIFO is full */
      }
      if(x == BYT_EMPTY || x == BYT_ESCAPE || x == -1) {
        if(iteration == 1) {
          fifo->buf[i] = BYT_ESCAPE;
        }
        i++;
        if(i >= fifo->size) {
          i = 0;
        }
        if(iteration == 0 && fifo->buf[i] != BYT_EMPTY) {
          return 1;             /* FIFO is full */
        }
        if(x == BYT_EMPTY) {
          x = BYT_ESCAPED_EMPTY;
        } else if(x == BYT_ESCAPE) {
          x = BYT_ESCAPED_ESCAPE;
        } else {                /* Frame end */
          x = BYT_ESCAPED_FRAME_END;
        }
      }
      if(iteration == 1) {
        fifo->buf[i] = x;
      }

      i++;
      if(i >= fifo->size) {
        i = 0;
      }
    }
  }

  fifo->end = i;
  return 0;
}

int lffifo_get(struct lffifo *fifo, unsigned char *buf, int bufsize) {
  int i,j;
  int x;
  int iteration;

  /* Do this twice: first to check that a full frame is available and will fit
     in the buffer; second to remove the frame by writing BYT_EMPTY over it. */
  for(iteration = 0; iteration < 2; iteration++) {
    i = fifo->start;
    j = 0;
    for(;;) {
      x = fifo->buf[i];
      if(iteration == 0) {
        if(x == BYT_EMPTY) {
          return 0;           /* FIFO is empty */
        }
      } else {
        fifo->buf[i] = BYT_EMPTY;
      }

      if(x == BYT_ESCAPE) {
        i++;
        if(i >= fifo->size) {
          i = 0;
        }
        x = fifo->buf[i];
        if(iteration == 0) {
          if(x == BYT_EMPTY) {
            return 0;           /* FIFO is empty */
          }
        } else {
          fifo->buf[i] = BYT_EMPTY;
        }

        if(x == BYT_ESCAPED_EMPTY) {
          x = BYT_EMPTY;
        } else if(x == BYT_ESCAPED_ESCAPE) {
          x = BYT_ESCAPE;
        } else {                /* Assume frame end */
          x = -1;
        }
      }
      i++;
      if(i >= fifo->size) {
        i = 0;
      }

      if(x == -1) {             /* Frame end */
        if(j > bufsize) {
          if(iteration == 1) {  /* Sanity check */
            fifo->start = i;
          }
          return bufsize - j;   /* Passed buffer is too small */
        }
        break;
      } else {
        if(iteration == 1) {
          if(j < bufsize) {     /* Sanity check */
            buf[j] = x;
          }
        }
        j++;
      }

      if(j > fifo->size) {      /* Sanity check */
        /* This should never happen (would mean a missing frame end
           termination), but handle it here anyway just to not code what looks
           like an infinite loop. */
        fifo->start = fifo->end;
        if(iteration == 0) {
          break;
        } else {
          return 0;
        }
      }
    }
  }

  fifo->start = i;
  return j;
}

#ifdef LFFIFO_INCLUDE_TEST_CODE
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv) {
  struct lffifo *fifo = lffifo_alloc(10000);
  unsigned char buf[1024];

  printf("put: %d\n", lffifo_put(fifo, "hej med dig", 12));
  printf("get: %d\n", lffifo_get(fifo, buf, sizeof(buf)));
  printf("Data: '%s'.\n", buf);
  lffifo_free(fifo);
}
#endif
