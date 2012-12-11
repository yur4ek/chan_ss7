/*
 * Copyright (C) 2007-2011, Netfors ApS.
 * Anders Baekgaard <ab@netfors.com>
 */

/* This version is released as part of chan_ss7. See LICENSE file */
struct confstate;
extern int confinitparser(struct confstate** c, const char* config_dir, const char* fn);
extern const char* confnextsection(struct confstate* c);
extern void conffindsection(struct confstate* c, char* section);
extern const char* confnextkey(struct confstate* c);
extern const char* confgetvalue(struct confstate* c);
extern int conflineno(struct confstate* c);
extern void confend(struct confstate* c);

