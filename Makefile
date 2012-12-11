# INSTALL_PREFIX may be overridden to install elsewhere from /usr.
INSTALL_PREFIX = /usr/local/ss7

VERSION=2.1.1b

# INCLUDE may be overridden to find asterisk and zaptel includes in
# non-standard places.
#INCLUDE+=-I../source/telephony/zaptel/kernel
#CFLAGS+=-DUSE_ZAPTEL
ASTERISK_PATH=../source/telephony/asterisk
INCLUDE+=-I../source/telephony/dahdi/include
INCLUDE+=-I$(ASTERISK_PATH)/include
ASTERISK_VERSION = $(shell cat astversion.h)
ifeq ($(findstring 1_8,$(ASTERISK_VERSION)),1_8)
  ASTERISK_1_8_OBJS = $(ASTERISK_PATH)/main/lock.o
endif

CC=gcc
CFLAGS+=$(INCLUDE) -g -pipe -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -D_REENTRANT -D_GNU_SOURCE -DPIC -fpic  -finline-functions
#CFLAGS+=-O4
#CFLAGS+=-pg
CFLAGS+=-DCHAN_SS7_VERSION=\"$(VERSION)\"
#CFLAGS+=-DMTP_OVER_UDP
#CFLAGS+=-DTESTINPUT

# -DMODULETEST

SOLINK=-shared

ifneq (${MODULETEST},)
MODTOBJS = moduletest.o
CFLAGS += -DMODULETEST
endif
MODTHDRS = $(MODTOBJS:.o=.h)
MODTSRCS = $(MODTOBJS:.o=.c)

HDRS = l4isup.h isup.h mtp.h utils.h config.h configparser.h cluster.h lffifo.h cli.h dump.h transport.h aststubs.h mtp3io.h $(MODTHDRS)
SRCS = chan_ss7.c l4isup.c isup.c mtp.c utils.c config.c configparser.c cluster.c lffifo.c transport.c cli.c dump.c mtp3io.c $(MODTSRCS)
ALLSRCS = $(SRCS) astversion.c configparser.c aststubs.c mtp3io.c mtp3d.c mtp3cli.c

OBJS = $(SRCS:.c=.o)
ALLOBJS = $(ALLSRCS:.c=.o)


.PHONY: prepare all install clean release

default: all mtp3d mtp3cli

prepare:

all: chan_ss7.so mtp3d


chan_ss7.so: $(OBJS)
	$(CC) $(SOLINK) -o $@ $^

mtp3d: mtp3d.o mtp3io.o aststubs.o mtp_standalone.o transport_standalone.o utils_standalone.o lffifo.o config_standalone.o configparser.o isup.o cli.o dump.o $(ASTERISK_1_8_OBJS)
	$(CC) -o $@ $^ -lpthread

mtp3cli: mtp3cli.o
	$(CC) $(LDFLAGS) -o $@ $^ -lpthread

astversion: astversion.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ -lpthread

astversion.h: astversion
	./$^ > $@.tmp && mv -f $@.tmp $@

mtp3io.o: mtp3io.c
	$(CC) -c $(CFLAGS) -o $@ $<

mtp3dmain.o: mtp3dmain.c
	$(CC) -c $(CFLAGS) -o $@ $<

aststubs.o: aststubs.c
	$(CC) -c $(CFLAGS) -o $@ $<

mtp_standalone.o: mtp.c
	$(CC) -c -DMTP_STANDALONE $(CFLAGS) -o $@ $<

transport_standalone.o: transport.c
	$(CC) -c -DMTP_STANDALONE $(CFLAGS) -o $@ $<

utils_standalone.o: utils.c
	$(CC) -c -DMTP_STANDALONE $(CFLAGS) -o $@ $<

config_standalone.o: config.c
	$(CC) -c -DMTP_STANDALONE $(CFLAGS) -o $@ $<

chan_ss7.o: chan_ss7.c
	$(CC) -c $(CFLAGS) -o $@ $<

moduletest.o: moduletest.c
	$(CC) -c $(CFLAGS) -o $@ $<

lffifo.o: lffifo.c
	$(CC) -c $(CFLAGS) -o $@ $<

mtp.o: mtp.c
	$(CC) -c $(CFLAGS) -o $@ $<

isup.o: isup.c
	$(CC) -c $(CFLAGS) -o $@ $<

utils.o: utils.c
	$(CC) -c $(CFLAGS) -o $@ $<

config.o: config.c
	$(CC) -c $(CFLAGS) -o $@ $<

cluster.o: cluster.c
	$(CC) -c $(CFLAGS) -o $@ $<

release-install: ss7-mtp-$(VERSION).tar.gz ss7-isup-$(VERSION).tar.gz
	tar xvzf ss7-mtp-$(VERSION).tar.gz -C /
	tar xvzf ss7-isup-$(VERSION).tar.gz -C /

install: chan_ss7.so
	install -m 755 -d $(INSTALL_PREFIX)/lib/modules
	install -m 644 chan_ss7.so $(INSTALL_PREFIX)/lib/modules
	install -m 755 mtp3d $(INSTALL_PREFIX)/sbin

clean:
	rm -f chan_ss7.so mtp3d mtp3cli astversion $(ALLOBJS) mtp_standalone.o transport_standalone.o utils_standalone.o config_standalone.o .depend
	rm -f instdir/sbin/mtp3d \
		instdir/sbin/safe_mtp3d \
		instdir/etc/init.d/mtp3d \
		instdir/etc/ss7.conf \
		instdir/lib/modules/chan_ss7.so \
		etc/init.d/mtp3d \
		ss7-mtp-$(VERSION).tar.gz
	rmdir instdir/sbin instdir/etc/init.d instdir/lib/modules instdir/etc || true
	rmdir -p instdir/lib || true
	rmdir -p etc/init.d || true


source: chan_ss7-$(VERSION).tar.gz

chan_ss7-$(VERSION).tar.gz: COPYING NEWS INSTALL ASTERISK_VARIABLES README Makefile asterisk_safe \
	ss7.conf.template.single-link ss7.conf.template.two-links ss7.conf.template.two-linksets ss7.conf.template.two-hosts \
	$(ALLSRCS) $(HDRS) \
	safe_mtp3d mtp3d.rc ss7.conf
	tar -c --transform='s,\(.*\),chan_ss7-$(VERSION)/\1,' -zf $@ $^

release: ss7-mtp-$(VERSION).tar.gz ss7-isup-$(VERSION).tar.gz

ss7-mtp-$(VERSION).tar.gz: instdir/sbin/mtp3d \
	instdir/sbin/safe_mtp3d \
	instdir/etc/init.d/mtp3d \
	etc/init.d/mtp3d
	tar -c  --transform='s,instdir/,$(INSTALL_PREFIX)/,' --owner=root --group=root  -zf $@ $^

ss7-isup-$(VERSION).tar.gz: instdir/lib/modules/chan_ss7.so \
	instdir/etc/ss7.conf
	tar -c  --transform='s,instdir/,$(INSTALL_PREFIX)/,' --owner=root --group=root  -zf $@ $^

web: chan_ss7-$(VERSION).tar.gz NEWS
	cp -p chan_ss7-$(VERSION).tar.gz /srv/apache/sites/netfors/media/download/chan_ss7-$(VERSION).tar.gz
	cp -p NEWS                       /srv/apache/sites/netfors/media/download/NEWS-$(VERSION).txt

instdir/sbin/mtp3d: mtp3d
	install -D -m 755 $^ $@

instdir/sbin/safe_mtp3d: safe_mtp3d
	install -D -m 755 $^ $@

instdir/etc/init.d/mtp3d: mtp3d.rc
	install -D -m 755 $^ $@

instdir/etc/ss7.conf: ss7.conf
	install -D -m 644 $^ $@

instdir/lib/modules/chan_ss7.so: chan_ss7.so
	install -D -m 755 $^ $@

etc/init.d/mtp3d:
	install -m 755 -d `dirname $@`
	if [ ! -L "$@" ]; then ln -sf $(INSTALL_PREFIX)/etc/init.d/mtp3d $@; fi

include .depend

.depend: astversion.h $(ALLSRCS) $(HDRS)
	gcc -MM -E $(CFLAGS) $^ > $@.new && mv -f $@.new $@ || rm -f $@.new
