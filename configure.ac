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

dnl Check for MIT support for KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED
AC_MSG_CHECKING([for KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED support])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([@%:@include <krb5/krb5.h>], [
#ifndef KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED
# error KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED not supported!
#endif
])], [AC_MSG_RESULT([yes])],
[AC_MSG_RESULT([no]); AC_MSG_ERROR([See: https://github.com/krb5/krb5/pull/245])])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
