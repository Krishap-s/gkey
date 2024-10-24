
# Taken from https://ljones.dev/blog/gsoc-2/ and https://aravindavk.in/blog/autoconf-for-rust-projects/
AC_INIT([gkey], m4_esyscmd([grep version Cargo.toml | awk '{print $3}' | tr -d '"' | tr -d "\n"]), [krishapbusiness@gmail.com])

VERSION=$(grep version Cargo.toml | awk '{print $3}' | tr -d '"' | tr -d "\n")

m4_ifdef([AM_SILENT_RULES], [
    AM_SILENT_RULES([yes])
])

AC_CONFIG_MACRO_DIRS([m4])
AC_PATH_PROG([CARGO], [cargo], [notfound])
AS_IF([test "$CARGO" = "notfound"], [AC_MSG_ERROR([cargo is required])])

AC_PATH_PROG([RUSTC], [rustc], [notfound])
AS_IF([test "$RUSTC" = "notfound"], [AC_MSG_ERROR([rustc is required])])

# Default value for sbindir
prefix_temp=$prefix
exec_prefix_temp=$exec_prefix

test "${prefix}" = "NONE" && prefix="${ac_default_prefix}"
test "${exec_prefix}" = "NONE" && exec_prefix='${prefix}'

# Initial Value is $exec_prefix/sbin
sbintemp="${sbindir}"

# Expands to $prefix/sbin
eval sbintemp="${sbintemp}"
# Expands to /usr/local/sbin or /usr/sbin if --prefix is passed
eval sbintemp="${sbintemp}"
SBINDIR=${sbintemp}

AC_SUBST(SBINDIR)
AC_SUBST(VERSION)
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
