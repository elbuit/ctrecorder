#	Copyright (C) 2004-2005 Bart³omiej Korupczynski <bartek@klolik.org>
#	
#	This program is free software; you can redistribute it and/or 
#	modify it under the terms of the GNU General Public License 
#	as published by the Free Software Foundation; either 
#	version 2 of the License, or (at your option) any later 
#	version.
#	
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#	
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

sbin_PROGRAMS = ctrecorder
#noinst_PROGRAMS = md5-test

#sbin_PROGRAMS = conntrack-collector conntrack-reader ctrecorder
#conntrack_collector_CFLAGS = -I${top_srcdir}/
#conntrack_collector_LDFLAGS = -lnetfilter_conntrack
#conntrack_collector_SOURCES = \
#	conntrack-collector.c \
#	events.h \
#	confvars.c confvars.h \
#	conffile.c conffile.h \
#	daemon.c daemon.h \
#	util.c util.h \
#	compat.c compat.h \
#	options.h
#
#conntrack_reader_SOURCES = \
#	conntrack-reader.c \
#	events.h \
#	util.c util.h \
#	compat.c compat.h \
#	options.h

if ENABLE_CAPTURE
ctrecorder_LDFLAGS = -lnetfilter_conntrack -lnfnetlink
endif
ctrecorder_CFLAGS = -I${top_srcdir}/
ctrecorder_SOURCES = \
	util.c util.h \
	daemon.c daemon.h \
	compat.c compat.h \
	ctrecorder.c ctrecorder.h \
	options.h

#ctlog_LDADD =
#ctlog_LDFLAGS = -lresolv


