# $Id$

bin_PROGRAMS = bin-search gz-elide-bad-chunks

bin_search_SOURCES = \
	bin-search.c	

bin_search_CPPFLAGS = \
	-I$(top_srcdir)		\
	$(DISABLE_DEPRECATED)	\
	$(AM_CPPFLAGS)

bin_search_CFLAGS = \
	$(GLIB_CFLAGS)	\
	$(WARN_CFLAGS)		\
	$(AM_CFLAGS)

bin_search_LDFLAGS = \
	$(AM_LDFLAGS)

bin_search_LDADD = \
	$(GLIB_LIBS)	\
 	$(INTLLIBS)

gz_elide_bad_chunks_SOURCES = \
	gz-elide-bad-chunks.c

gz_elide_bad_chunks_CPPFLAGS = \
	-I$(top_srcdir)		\
	$(DISABLE_DEPRECATED)	\
	$(AM_CPPFLAGS)

gz_elide_bad_chunks_CFLAGS = \
	$(GLIB_CFLAGS)	\
	$(WARN_CFLAGS)		\
	$(AM_CFLAGS)

gz_elide_bad_chunks_LDFLAGS = \
	$(AM_LDFLAGS)

gz_elide_bad_chunks_LDADD = \
	$(ZLIB_LIBS)	\
	$(GLIB_LIBS)	\
 	$(INTLLIBS)

EXTRA_DIST = autogen.sh
