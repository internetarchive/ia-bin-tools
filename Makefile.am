# $Id$

bin_PROGRAMS = bin-search gzip-chunks whoiz

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

gzip_chunks_SOURCES = \
	gzip-chunks.c

gzip_chunks_CPPFLAGS = \
	-I$(top_srcdir)		\
	$(DISABLE_DEPRECATED)	\
	$(AM_CPPFLAGS)

gzip_chunks_CFLAGS = \
	$(GLIB_CFLAGS)	\
	$(WARN_CFLAGS)		\
	$(AM_CFLAGS)

gzip_chunks_LDFLAGS = \
	$(AM_LDFLAGS)

gzip_chunks_LDADD = \
	$(ZLIB_LIBS)	\
	$(GLIB_LIBS)	\
 	$(INTLLIBS)

whoiz_SOURCES = \
	whoiz.c

whoiz_CPPFLAGS = \
	-I$(top_srcdir)		\
	$(DISABLE_DEPRECATED)	\
	$(AM_CPPFLAGS)

whoiz_CFLAGS = \
	$(GLIB_CFLAGS)	\
	$(WARN_CFLAGS)	\
	$(AM_CFLAGS)

whoiz_LDFLAGS = \
	$(AM_LDFLAGS)

whoiz_LDADD = \
	$(GLIB_LIBS)	\
 	$(INTLLIBS)

EXTRA_DIST = autogen.sh
