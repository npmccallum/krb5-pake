AC_PREREQ(2.59)
AC_INIT(krb5-pake, 0.1)
AC_CANONICAL_SYSTEM
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC_C99
AC_PROG_LIBTOOL

AM_INIT_AUTOMAKE([subdir-objects])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O 

LT_INIT

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([OPENSSL], [openssl])
PKG_CHECK_MODULES([KDB], [kdb])
PKG_CHECK_MODULES([KRB5], [krb5],
                  [preauthdir=`$PKG_CONFIG --variable=libdir krb5`/krb5/plugins/preauth])
AC_SUBST([preauthdir])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
