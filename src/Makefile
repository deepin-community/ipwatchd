# IPwatchD - IP conflict detection tool for Linux
# Copyright (C) 2007-2018 Jaroslav Imrich <jariq(at)jariq(dot)sk>

CC= gcc
CFLAGS= -g -Wall -O2
LIBS= -lpcap -lnet  $(shell pkg-config --libs dbus-1 polkit-gobject-1 json-c)
override CFLAGS +=  $(shell pkg-config --cflags dbus-1 polkit-gobject-1)
override CFLAGS +=  $(shell pkg-config --cflags json-c)
override CFLAGS += -fPIC -fstack-protector-all -z relro -z noexecstack -z now -pie

all: analyse.o config.o daemonize.o devinfo.o genarp.o ipwatchd.o message.o signal.o dbus.o securityloader.o utils.o
	$(CC) $(CFLAGS) $(LDFLAGS) analyse.o config.o daemonize.o devinfo.o genarp.o \
	ipwatchd.o message.o signal.o dbus.o securityloader.o utils.o -o ipwatchd $(LIBS)


analyse.o: analyse.c ipwatchd.h
	$(CC) $(CFLAGS) -c analyse.c -o analyse.o

config.o: config.c ipwatchd.h
	$(CC) $(CFLAGS) -c config.c -o config.o

daemonize.o: daemonize.c ipwatchd.h
	$(CC) $(CFLAGS) -c daemonize.c -o daemonize.o

devinfo.o: devinfo.c ipwatchd.h
	$(CC) $(CFLAGS) -c devinfo.c -o devinfo.o

genarp.o: genarp.c ipwatchd.h
	$(CC) $(CFLAGS) -c genarp.c -o genarp.o

ipwatchd.o: ipwatchd.c ipwatchd.h
	$(CC) $(CFLAGS) -c ipwatchd.c -o ipwatchd.o

message.o: message.c ipwatchd.h
	$(CC) $(CFLAGS) -c message.c -o message.o

signal.o: signal.c ipwatchd.h
	$(CC) $(CFLAGS) -c signal.c -o signal.o

dbus.o: dbus.c ipwatchd.h
	$(CC) $(CFLAGS) -c dbus.c -o dbus.o

securityloader.o: securityloader.c ipwatchd.h
	$(CC) $(CFLAGS) -c securityloader.c -o securityloader.o

utils.o: utils.c ipwatchd.h
	$(CC) $(CFLAGS) -c utils.c -o utils.o

test: check

check:
	$(MAKE) -C ../tests check

clean:
	-rm -f *.o ipwatchd
	$(MAKE) -C ../tests clean

distclean: clean


install:
	mkdir -p $(DESTDIR)/etc
	mkdir -p $(DESTDIR)/lib/systemd/system
	mkdir -p $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/usr/share/man/man8
	mkdir -p $(DESTDIR)/usr/share/man/man5
	mkdir -p $(DESTDIR)/usr/share/man/man1
	mkdir -p ${DESTDIR}/usr/share/dbus-1/system.d
	mkdir -p ${DESTDIR}/usr/share/polkit-1/actions
	cp ipwatchd $(DESTDIR)/usr/sbin
	cp ipwatchd-script $(DESTDIR)/usr/sbin
	cp ipwatchd.service $(DESTDIR)/lib/systemd/system
	cp ipwatchd.conf $(DESTDIR)/etc
	cp misc/conf/*.conf ${DESTDIR}/usr/share/dbus-1/system.d/
	cp -r misc/system-services ${DESTDIR}/usr/share/dbus-1/
	cp misc/polkit-1/actions/*.policy ${DESTDIR}/usr/share/polkit-1/actions/
	cp ../doc/ipwatchd.8.gz $(DESTDIR)/usr/share/man/man8
	cp ../doc/ipwatchd.conf.5.gz $(DESTDIR)/usr/share/man/man5
	cp ../doc/ipwatchd-script.1.gz $(DESTDIR)/usr/share/man/man1



uninstall:
	rm $(DESTDIR)/usr/sbin/ipwatchd
	rm $(DESTDIR)/usr/sbin/ipwatchd-script
	rm $(DESTDIR)/lib/systemd/system/ipwatchd.service
	rm $(DESTDIR)/etc/ipwatchd.conf
	rm $(DESTDIR)/usr/share/man/man8/ipwatchd.8.gz
	rm $(DESTDIR)/usr/share/man/man5/ipwatchd.conf.5.gz
	rm $(DESTDIR)/usr/share/man/man1/ipwatchd-script.1.gz

.PHONY: all check clean distclean install test uninstall
