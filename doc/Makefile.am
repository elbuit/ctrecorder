#	Copyright (C) 2004-2005 Bartłomiej Korupczynski <bartek@klolik.org>
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

HTML = ctrecorder.html ctrecorder.conf.html
src_MANS = ctrecorder.t2t ctrecorder.conf.t2t
man_MANS = ctrecorder.8 ctrecorder.conf.5
EXTRA_DIST = $(man_MANS) $(src_MANS) $(HTML)
DISTCLEANFILES = $(man_MANS) $(HTML)

# http://txt2tags.sourceforge.net/docs.html

if TXT2TAGS
%.html: %.t2t
	txt2tags -t xhtml -i $< -o $@

%.5: %.t2t
	txt2tags -t man -i $< -o $@

%.8: %.t2t
	txt2tags -t man -i $< -o $@
endif

