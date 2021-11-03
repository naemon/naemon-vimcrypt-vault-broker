AC_PREREQ([2.59])
AC_INIT([naemon_vimvault_neb], [0.1], [sven@consol.de])
AC_CONFIG_SRCDIR([module.c])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

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

PKG_CHECK_MODULES([naemon], [naemon >= 1.0])
PKG_CHECK_MODULES([openssl], [openssl >= 1.0])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIR([m4])
AC_OUTPUT
