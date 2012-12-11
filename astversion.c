/* astversion.c - Determine which asterisk version to use
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


#include "asterisk.h"
#include "asterisk/config.h"
#include "asterisk/module.h"
#include "asterisk/cli.h"

#ifdef AST_MODULE_INFO
#include "asterisk/version.h"
#ifdef AST_CLI_DEFINE
#ifdef AST_CLI_YESNO
#  define USE_ASTERISK_1_8
#else
#  define USE_ASTERISK_1_6
#endif
#else
#define USE_ASTERISK_1_4
#endif
#else
#define USE_ASTERISK_1_2
#endif

int main(int argc, char* argv[])
{
#ifdef USE_ASTERISK_1_2
  printf("#define USE_ASTERISK_1_2\n");
#else
#ifdef USE_ASTERISK_1_4
  printf("#define USE_ASTERISK_1_4\n");
#else
#ifdef USE_ASTERISK_1_6
  printf("#define USE_ASTERISK_1_6\n");
#else
#ifdef USE_ASTERISK_1_8
  printf("#define USE_ASTERISK_1_8\n");
#else
  fprintf(stderr, "Unknown asterisk version\n");
  return -1;
#endif
#endif
#endif
#endif
  return 0;
}
