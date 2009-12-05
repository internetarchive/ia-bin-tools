#!/bin/sh
#
# $Id$ 
#
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

PKG_NAME="ia-tools"

which gnome-autogen.sh || {
    echo "You need to install gnome-common from the GNOME SVN repository"
    exit 1
}

REQUIRED_AUTOMAKE_VERSION=1.9
REQUIRED_INTLTOOL_VERSION=0.40.0
USE_COMMON_DOC_BUILD=yes

. gnome-autogen.sh
