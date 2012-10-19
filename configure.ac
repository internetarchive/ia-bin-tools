AC_INIT([Internet Archive Binary Tools],[1.0],[mailto:nlevitt@archive.org],[ia-bin-tools])

AM_INIT_AUTOMAKE([1.9 foreign dist-bzip2])

AC_CONFIG_SRCDIR([bin-search.c])
AC_CONFIG_HEADERS([config.h])

AM_MAINTAINER_MODE

AC_PROG_CC
AC_ISC_POSIX
AC_HEADER_STDC
AC_PROG_LIBTOOL

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.21
                           gio-2.0 >= 2.21
                           gobject-2.0 >= 2.21])

AC_CHECK_HEADER([zlib.h], [], AC_MSG_ERROR([zlib header file zlib.h not found]))
AC_CHECK_LIB([z], [inflate], [ZLIB_LIBS=-lz], AC_MSG_ERROR([zlib library libz not found]))
AC_SUBST([ZLIB_LIBS])

AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
