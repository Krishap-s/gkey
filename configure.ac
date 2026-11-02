# Process this file with autoconf to produce a configure script.
#
# Copyright (C) 2024, 2026 Krishap <krishapbusiness@gmail.com>
#
# This file is part of gkey.
#
# gkey is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

AC_PREREQ([2.69])
AC_INIT([gkey],
        m4_esyscmd_s([sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1]),
        [https://github.com/Krishap-s/gkey/issues],
        [gkey],
        [https://github.com/Krishap-s/gkey])
AC_CONFIG_SRCDIR([src/lib.rs])

AC_PATH_PROG([CARGO], [cargo], [no])
AS_IF([test "x$CARGO" = xno], [AC_MSG_ERROR([cargo is required to build gkey])])
AC_PATH_PROG([RUSTC], [rustc], [no])
AS_IF([test "x$RUSTC" = xno], [AC_MSG_ERROR([rustc is required to build gkey])])

# The TPM Software Stack and PAM are linked into the programs.
AC_PATH_PROG([PKG_CONFIG], [pkg-config], [no])
AS_IF([test "x$PKG_CONFIG" = xno], [AC_MSG_ERROR([pkg-config is required])])
AC_MSG_CHECKING([for tss2-esys >= 2.4])
AS_IF([$PKG_CONFIG --atleast-version=2.4 tss2-esys tss2-tctildr tss2-mu],
      [AC_MSG_RESULT([yes])],
      [AC_MSG_RESULT([no])
       AC_MSG_ERROR([the TPM2 Software Stack (tpm2-tss) development files are required])])
AC_CHECK_LIB([pam], [pam_start], [:],
             [AC_MSG_ERROR([the PAM (Linux-PAM) development files are required])])

# Optional tools.
AC_PATH_PROG([MAKEINFO], [makeinfo], [makeinfo])
AC_PATH_PROG([TEXI2DVI], [texi2dvi], [texi2dvi])
AC_PATH_PROG([INSTALL_INFO], [install-info], [install-info])

AC_ARG_WITH([systemduserunitdir],
  [AS_HELP_STRING([--with-systemduserunitdir=DIR],
                  [install the systemd user unit in DIR @<:@PREFIX/lib/systemd/user@:>@])],
  [systemduserunitdir=$withval], [systemduserunitdir='${prefix}/lib/systemd/user'])
AC_ARG_WITH([udevrulesdir],
  [AS_HELP_STRING([--with-udevrulesdir=DIR],
                  [install udev rules in DIR @<:@PREFIX/lib/udev/rules.d@:>@])],
  [udevrulesdir=$withval], [udevrulesdir='${prefix}/lib/udev/rules.d'])
AC_ARG_WITH([modulesloaddir],
  [AS_HELP_STRING([--with-modulesloaddir=DIR],
                  [install the kernel module list in DIR @<:@PREFIX/lib/modules-load.d@:>@])],
  [modulesloaddir=$withval], [modulesloaddir='${prefix}/lib/modules-load.d'])
AC_ARG_WITH([pamdir],
  [AS_HELP_STRING([--with-pamdir=DIR],
                  [install the PAM configuration in DIR @<:@SYSCONFDIR/pam.d@:>@])],
  [pamdir=$withval], [pamdir='${sysconfdir}/pam.d'])
AC_SUBST([systemduserunitdir])
AC_SUBST([udevrulesdir])
AC_SUBST([modulesloaddir])
AC_SUBST([pamdir])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
