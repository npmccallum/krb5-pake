ACLOCAL_AMFLAGS = -Im4

AM_LDFLAGS = @OPENSSL_LIBS@ @KRB5_LIBS@ @KDB_LIBS@
AM_CFLAGS = @OPENSSL_CFLAGS@ @KRB5_CFLAGS@ @KDB_CFLAGS@ \
	-Wall \
	-Wextra \
	-Werror \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter

TESTS = src/pake/test
src_pake_test_LDADD = libpake.la 

noinst_PROGRAMS = $(TESTS) src/pake/spake_constants
BUILT_SOURCES = spake_constants.h
CLEANFILES = spake_constants.h
spake_constants.h: src/pake/spake_constants
	$(builddir)/$< $@

##
### The internal PAKE library (uses only OpenSSL types)
##
noinst_LTLIBRARIES = libpake.la
libpake_la_SOURCES = \
	src/pake/asn1.c	\
	src/pake/asn1.h	\
	src/pake/conv.c	\
	src/pake/conv.h	\
	src/pake/hash.c	\
	src/pake/hash.h	\
	src/pake/spake.c	\
	src/pake/spake.h	\
	src/pake/jpake.c	\
	src/pake/jpake.h	\
	src/pake/pake_ctx.h	\
	src/pake/pake.c	\
	src/pake/pake.h

##
### The kerberos plugin (uses krb5 types)
##
preauth_LTLIBRARIES = pake.la
pake_la_LIBADD = libpake.la
pake_la_LDFLAGS = -module -avoid-version -shared -export-symbols $(srcdir)/src/pake.sym
pake_la_SOURCES = \
	src/kconv.c	\
	src/kconv.h	\
	src/cookie.c	\
	src/cookie.h	\
	src/common.c	\
	src/common.h	\
	src/global.c	\
	src/global.h	\
	src/server.c	\
	src/client.c

install-data-hook:
	rm -f $(DESTDIR)$(preauthdir)/pake.la