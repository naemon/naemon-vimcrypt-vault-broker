AC_PREREQ([2.59])
AC_INIT([naemon-vimvault], m4_esyscmd([./version.sh]), [naemon-dev@monitoring-lists.org])
AC_CONFIG_SRCDIR([module.c])
AM_INIT_AUTOMAKE([-Wall -Werror foreign -Wno-portability])

AC_CONFIG_HEADERS([config.h])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs
AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AM_PROG_AR
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

AM_CFLAGS=$naemon_CFLAGS
AM_CPPFLAGS=-D_GNU_SOURCE

AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])

PKG_CHECK_MODULES(NAEMON, [naemon >= 1.3.0],
                  [naemon_cfg=`$PKG_CONFIG --variable=mainconf naemon`])
PKG_CHECK_MODULES([openssl], [openssl >= 1.0])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIR([m4])

AC_ARG_WITH(naemon-config-dir, AS_HELP_STRING([--with-naemon-config-dir], [Install vimvault' naemon config into this directory (default is your naemon.cfg directory)]), [naemonconfdir=$withval], [naemonconfdir=`AS_DIRNAME([${naemon_cfg}])`])
AC_SUBST(naemonconfdir)

AC_ARG_WITH(broker-module-options, AS_HELP_STRING([--with-broker-module-options], [Additional broker module options for the default configuration in vimvault.cfg]), [brokeroptions="$withval"], [brokeroptions="vault=/etc/naemon/vault.cfg"])
AC_SUBST(brokeroptions)


AC_OUTPUT
