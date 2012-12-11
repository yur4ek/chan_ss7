/*
 * Copyright (C) 2007-2011, Netfors ApS.
 * Anders Baekgaard <ab@netfors.com>
 */

/* This version is released as part of chan_ss7. See LICENSE file */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "configparser.h"

struct confstate {
  FILE* f;
  char config_fn[PATH_MAX];
  char* line;
  char buf[1024];
  unsigned int bufp;
  unsigned int bufl;
  char* section;
  char* key;
  char* value;
  int lineno;
};


static int confreset(struct confstate* c)
{
  if (c->f)
    fclose(c->f);
  c->f = fopen(c->config_fn, "r");
  if (!c->f) {
    fprintf(stderr, "Cannot open '%s': error %d: %s\n", c->config_fn, errno, strerror(errno));
    return -1;
  }
  c->bufp = 0;
  c->bufl = 0;
  c->line = NULL;
  c->section = NULL;
  c->key = NULL;
  c->value = NULL;
  c->lineno = 0;
  return 0;
}

int confinitparser(struct confstate** ci, const char* config_dir, const char* fn)
{
  struct confstate* c = malloc(sizeof(*c));

  *ci = c;
  sprintf(c->config_fn, "%s/%s", config_dir, fn);
  c->f = NULL;
  confreset(c);
  return 0;
}


static void confnextline(struct confstate* c)
{
  int n;
  char* p;

  c->line = NULL;
  if (!c->f && !c->bufl) {
    return;
  }
  memcpy(c->buf, &c->buf[c->bufp], c->bufl-c->bufp);
  c->bufl -= c->bufp;
  c->bufp = 0;
  if (c->f) {
    n = fread(&c->buf[c->bufl], sizeof(*c->buf), sizeof(c->buf)-c->bufl, c->f);
    if (n <= 0) {
      if (n < 0)
	fprintf(stderr, "Error reading '%s': error %d: %s\n", c->config_fn, errno, strerror(errno));
      fclose(c->f);
      c->f = NULL;
      if (n < 0)
	return;
    }
    c->bufl += n;
  }
  for(; (c->bufp < c->bufl) && (c->buf[c->bufp] != '\n'); c->bufp++);
  c->lineno++;
  if (!c->bufl)
    return;
  if (c->buf[c->bufp] != '\n') {
    fprintf(stderr, "Line %d too long in '%s'\n", c->lineno, c->config_fn);
    return;
  }
  c->buf[c->bufp] = 0;
  for(p = c->buf; (*p == ' ') || (*p == '\t'); p++);
  c->line = p;
  for (p = &c->buf[c->bufp]-1; (p >= c->buf) && ((*p == ' ') || (*p == '\t')); *p-- = 0);
  c->bufp++;
  if (*c->line) {
    if ((*c->line == ';') || (*c->line == '#'))
      confnextline(c);
  }
  else
    confnextline(c);
}

const char* confnextsection(struct confstate* c)
{
  char* p;

  if (!c->line)
    confnextline(c);
  if (!c->line)
    return NULL;
  if (*c->line != '[') {
    fprintf(stderr, "Invalid section header: '%s', skipping, line %d '%s'\n", c->line, c->lineno, c->config_fn);
    c->line = NULL;
    return confnextsection(c);
  }
  for (p = c->line;  (*p && (*p != ']')); p++);
  if (*p != ']') {
    fprintf(stderr, "Invalid section header: '%s', line %d in '%s'\n", c->line, c->lineno, c->config_fn);
    return NULL;
  }
  *p = 0;
  p = c->line+1;
  c->line = NULL;
  return strdup(p);
}

void conffindsection(struct confstate* c, char* section)
{
  const char* s;
  confreset(c);
  while ((s = confnextsection(c)) != NULL)
    if (strcmp(s, section) == 0)
      return;
}


const char* confnextkey(struct confstate* c)
{
  char* p;
  char* q;

  if (!c->line)
    confnextline(c);
  if (!c->line)
    return NULL;
  if (*c->line == '[')
    return NULL;
  for (p = c->line;  (*p && (*p != '=')); p++);
  if (*p != '=') {
    fprintf(stderr, "Invalid key-value: '%s', line %d in '%s'\n", c->line, c->lineno, c->config_fn);
    return NULL;
  }
  *p = 0;
  for (q = p-1; (q >= c->line) && ((*q == ' ') || (*q == '\t')); *q-- = 0);
  *p = 0;
  if (*(p+1) == '>')
    *p++ = 0;
  for (p++; *p && ((*p == ' ') || (*p == '\t')); *p++ = 0);
  c->key = c->line;
  c->value = p;
  c->line = NULL;
  return strdup(c->key);
}

const char* confgetvalue(struct confstate* c)
{
  if (c->value)
    return strdup(c->value);
  return NULL;
}

int conflineno(struct confstate* c)
{
  return c->lineno;
}

void confend(struct confstate* c)
{
}

