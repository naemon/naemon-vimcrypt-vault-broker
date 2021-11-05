AM_CFLAGS += $(CFLAGS) $(naemon_CFLAGS)
AM_CPPFLAGS += $(CPPFLAGS)
ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = naemon_vimcrypt.la

EXTRA_DIST = README.md \
             naemon-vimvault.spec \
             debian \
             version.sh \
             vimvault.cfg.in

bin_PROGRAMS =
naemon_vimcrypt_la_LDFLAGS = -module -avoid-version -shared $(NAEMON_LIBS) -lssl -lcrypto
naemon_vimcrypt_la_CFLAGS = $(AM_CFLAGS) $(NAEMON_CFLAGS)
naemon_vimcrypt_la_CPPFLAGS = $(AM_CPPFLAGS)

naemon_vimcrypt_sources = module.c
naemonconf_DATA = vimvault.cfg

naemon_vimcrypt_la_SOURCES = $(naemon_vimcrypt_sources)

CLEANFILES = $(BUILT_SOURCES)

vimvault.cfg : % : %.in
	$(AM_V_GEN) sed \
		-e 's,@pkglibdir[@],$(pkglibdir),g' \
		-e 's,@brokeroptions[@],@brokeroptions@,g' \
		$< > $@

rpm: dist
	rpmbuild -tb naemon-vimvault-${VERSION}.tar.gz

deb:
	debuild -i -us -uc -b

version:
	[ -e .git ] || { echo "changing versions only works in git clones!"; exit 1; }
	[ `git status | grep -cP 'working (directory|tree) clean'` -eq 1 ] || { echo "git project is not clean, cannot tag version"; exit 1; }
	OLDVERSION=$(shell grep ^VERSION version.sh | awk -F = '{ print $$2}'); \
	NEWVERSION=$$(dialog --stdout --inputbox "New Version:" 0 0 "$$OLDVERSION"); \
		if [ -n "$$NEWVERSION" ] && [ "$$NEWVERSION" != "$$OLDVERSION" ]; then \
			sed -ri "s/$$OLDVERSION/$$NEWVERSION/" version.sh naemon-vimvault.spec; \
			sed -e 's/UNRELEASED/unstable/g' -i debian/changelog; \
			DEBFULLNAME="Naemon Development Team" DEBEMAIL="Naemon Development <naemon-dev@monitoring-lists.org>" dch --newversion "$$NEWVERSION" --package "naemon-vimvault" -D "UNRELEASED" --urgency "low" "new upstream release"; \
			sed -e 's/unstable/UNRELEASED/g' -i debian/changelog; \
		fi

