AM_CFLAGS += $(CFLAGS) $(naemon_CFLAGS)
AM_CPPFLAGS += $(CPPFLAGS)
ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = naemon_vimcrypt.la

EXTRA_DIST = README.md
bin_PROGRAMS =
naemon_vimcrypt_la_LDFLAGS = -module -avoid-version -shared $(NAEMON_LIBS) -lssl
naemon_vimcrypt_la_CFLAGS = $(AM_CFLAGS)
naemon_vimcrypt_la_CPPFLAGS = $(AM_CPPFLAGS)

naemon_vimcrypt_sources = module.c

naemon_vimcrypt_la_SOURCES = $(naemon_vimcrypt_sources)

CLEANFILES = $(BUILT_SOURCES)
