/* Check gkey against libfido2, the library OpenSSH uses for security keys.
 *
 * Copyright (C) 2026 Krishap <krishapbusiness@gmail.com>
 *
 * This file is part of gkey.
 *
 * gkey is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gkey is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gkey.  If not, see <https://www.gnu.org/licenses/>.
 *
 * The calls mirror OpenSSH's sk-usbhid.c, sk_enroll and sk_sign, which
 * is what "ssh-keygen -t ecdsa-sk" and ssh run.  Instead of a HID
 * device the program uses libfido2's pluggable I/O to talk CTAPHID over
 * the Unix socket of tests/helpers/socket-authenticator.rs.
 *
 * Usage: libfido2-check SOCKET
 */

#include <fido.h>
#include <fido/es256.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define REPORT 64
#define UP 0x01
#define UV 0x04

static int failures;

static void
check(int ok, const char *name, const char *detail)
{
	printf("%s: %s%s%s\n", ok ? "ok" : "FAIL", name,
	    ok || detail == NULL ? "" : ": ", ok || detail == NULL ? "" : detail);
	if (!ok)
		failures++;
}

static void
check_code(int r, int want, const char *name)
{
	char detail[80];

	snprintf(detail, sizeof(detail), "%s (wanted %s)", fido_strerr(r),
	    fido_strerr(want));
	check(r == want, name, detail);
}

/* libfido2 I/O over a stream socket: reports are 64 bytes, no report ID. */

static void *
io_open(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int *fd = malloc(sizeof(*fd));

	if (fd == NULL)
		return NULL;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	if ((*fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 ||
	    connect(*fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		free(fd);
		return NULL;
	}
	return fd;
}

static void
io_close(void *handle)
{
	close(*(int *)handle);
	free(handle);
}

static int
io_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	struct pollfd p = { .fd = *(int *)handle, .events = POLLIN };
	size_t got = 0;

	while (got < len) {
		ssize_t n;

		if (poll(&p, 1, ms) != 1)
			return -1;
		if ((n = read(p.fd, buf + got, len - got)) <= 0)
			return -1;
		got += (size_t)n;
	}
	return (int)len;
}

static int
io_write(void *handle, const unsigned char *buf, size_t len)
{
	/* libfido2 prefixes a report ID that the device does not use. */
	if (len == REPORT + 1) {
		buf++;
		len--;
	}
	return write(*(int *)handle, buf, len) == (ssize_t)len ?
	    (int)len + 1 : -1;
}

static const char *socket_path;

static fido_dev_t *
open_dev(void)
{
	fido_dev_io_t io = { io_open, io_close, io_read, io_write };
	fido_dev_t *dev = fido_dev_new();

	if (dev == NULL || fido_dev_set_io_functions(dev, &io) != FIDO_OK ||
	    fido_dev_open(dev, socket_path) != FIDO_OK) {
		fprintf(stderr, "cannot open %s\n", socket_path);
		exit(2);
	}
	return dev;
}

struct key {
	unsigned char id[256];
	size_t id_len;
	es256_pk_t *pk;
};

/* sk_enroll: prot is 0 for no credProtect, else the level. */
static int
enroll(struct key *key, int resident, int prot)
{
	unsigned char challenge[32], user_id[32];
	fido_dev_t *dev = open_dev();
	fido_cred_t *cred = fido_cred_new();
	int r;

	memset(challenge, 0x11, sizeof(challenge));
	memset(user_id, 0x22 + prot, sizeof(user_id));
	user_id[0] = (unsigned char)(resident * 16 + prot);
	if ((r = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK ||
	    (r = fido_cred_set_clientdata(cred, challenge,
	    sizeof(challenge))) != FIDO_OK ||
	    (r = fido_cred_set_rk(cred, resident ? FIDO_OPT_TRUE :
	    FIDO_OPT_OMIT)) != FIDO_OK ||
	    (r = fido_cred_set_user(cred, user_id, sizeof(user_id), "openssh",
	    "openssh", NULL)) != FIDO_OK ||
	    (r = fido_cred_set_rp(cred, "ssh:", NULL)) != FIDO_OK)
		goto out;
	if (prot != 0) {
		if (!fido_dev_supports_cred_prot(dev)) {
			r = FIDO_ERR_UNSUPPORTED_EXTENSION;
			goto out;
		}
		if ((r = fido_cred_set_prot(cred, prot)) != FIDO_OK)
			goto out;
	}
	if ((r = fido_dev_make_cred(dev, cred, NULL)) != FIDO_OK)
		goto out;
	if (fido_cred_x5c_ptr(cred) != NULL)
		r = fido_cred_verify(cred);
	else
		r = fido_cred_verify_self(cred);
	if (r != FIDO_OK)
		goto out;
	if (prot != 0 && fido_cred_prot(cred) != prot) {
		r = FIDO_ERR_INVALID_PARAM;
		goto out;
	}
	key->id_len = fido_cred_id_len(cred);
	memcpy(key->id, fido_cred_id_ptr(cred), key->id_len);
	key->pk = es256_pk_new();
	r = es256_pk_from_ptr(key->pk, fido_cred_pubkey_ptr(cred),
	    fido_cred_pubkey_len(cred));
 out:
	fido_cred_free(&cred);
	fido_dev_close(dev);
	fido_dev_free(&dev);
	return r;
}

/* sk_sign; on success *flags holds the authenticator data flags. */
static int
sign(const struct key *key, int up, int uv, int *flags)
{
	static const unsigned char message[] = "ssh signature data";
	fido_dev_t *dev = open_dev();
	fido_assert_t *assert = fido_assert_new();
	int r;

	*flags = -1;
	if ((r = fido_assert_set_clientdata(assert, message,
	    sizeof(message))) != FIDO_OK ||
	    (r = fido_assert_set_rp(assert, "ssh:")) != FIDO_OK ||
	    (r = fido_assert_allow_cred(assert, key->id,
	    key->id_len)) != FIDO_OK ||
	    (r = fido_assert_set_up(assert, up ? FIDO_OPT_TRUE :
	    FIDO_OPT_FALSE)) != FIDO_OK)
		goto out;
	if (uv && (r = fido_assert_set_uv(assert, FIDO_OPT_TRUE)) != FIDO_OK)
		goto out;
	if ((r = fido_dev_get_assert(dev, assert, NULL)) != FIDO_OK)
		goto out;
	if (fido_assert_count(assert) != 1) {
		r = FIDO_ERR_INTERNAL;
		goto out;
	}
	*flags = fido_assert_flags(assert, 0);
	/* libfido2 checks the flags and the signature against the key. */
	r = fido_assert_verify(assert, 0, COSE_ES256, key->pk);
 out:
	fido_assert_free(&assert);
	fido_dev_close(dev);
	fido_dev_free(&dev);
	return r;
}

/* key_lookup: a silent search for resident keys of the application. */
static int
lookup(void)
{
	static const unsigned char hash[32] = { 0 };
	fido_dev_t *dev = open_dev();
	fido_assert_t *assert = fido_assert_new();
	int r;

	if ((r = fido_assert_set_clientdata_hash(assert, hash,
	    sizeof(hash))) == FIDO_OK &&
	    (r = fido_assert_set_rp(assert, "ssh:")) == FIDO_OK &&
	    (r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) == FIDO_OK)
		r = fido_dev_get_assert(dev, assert, NULL);
	fido_assert_free(&assert);
	fido_dev_close(dev);
	fido_dev_free(&dev);
	return r;
}

int
main(int argc, char **argv)
{
	struct key plain = { 0 }, resident = { 0 }, required = { 0 };
	fido_dev_t *dev;
	fido_cbor_info_t *info;
	int flags, internal_uv = 0;
	size_t i;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s SOCKET\n", argv[0]);
		return 2;
	}
	socket_path = argv[1];
	fido_init(0);

	dev = open_dev();
	check(fido_dev_is_fido2(dev), "device is FIDO2", NULL);
	check(fido_dev_supports_cred_prot(dev), "credProtect is advertised",
	    NULL);
	info = fido_cbor_info_new();
	if (fido_dev_get_cbor_info(dev, info) == FIDO_OK) {
		char * const *name = fido_cbor_info_options_name_ptr(info);
		const bool *value = fido_cbor_info_options_value_ptr(info);

		for (i = 0; i < fido_cbor_info_options_len(info); i++)
			if (strcmp(name[i], "uv") == 0 && value[i])
				internal_uv = 1;
	}
	check(internal_uv, "built-in user verification is advertised", NULL);
	fido_cbor_info_free(&info);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	/* ssh-keygen -t ecdsa-sk */
	check_code(enroll(&plain, 0, 0), FIDO_OK,
	    "enroll a plain key (self attestation verifies)");
	/* ssh -i ... : touch required, the default */
	check_code(sign(&plain, 1, 0, &flags), FIDO_OK,
	    "sign with user presence (libfido2 verifies the signature)");
	check((flags & UP) != 0 && (flags & UV) == 0, "  presence flag only",
	    NULL);
	/* ssh with a key made with -O no-touch-required, and the probe */
	check_code(sign(&plain, 0, 0, &flags), FIDO_OK,
	    "sign without user presence");
	check(flags == 0, "  no flags", NULL);
	check_code(sign(&plain, 1, 1, &flags), FIDO_OK,
	    "sign with user verification");
	check((flags & (UP | UV)) == (UP | UV), "  presence and verification",
	    NULL);

	/* ssh-keygen -t ecdsa-sk -O resident */
	check_code(enroll(&resident, 1, 2), FIDO_OK,
	    "enroll a resident key (credProtect level 2)");
	check_code(sign(&resident, 1, 0, &flags), FIDO_OK,
	    "  sign with it by its key handle");

	/* ssh-keygen -t ecdsa-sk -O verify-required */
	check_code(enroll(&required, 0, 3), FIDO_OK,
	    "enroll a verify-required key (credProtect level 3)");
	check_code(sign(&required, 1, 1, &flags), FIDO_OK,
	    "  sign with user verification");
	check_code(sign(&required, 1, 0, &flags), FIDO_ERR_NO_CREDENTIALS,
	    "  refused without user verification");

	check_code(lookup(), FIDO_ERR_NO_CREDENTIALS,
	    "silent resident key lookup hides protected keys");

	printf("%s\n", failures ? "FAILED" : "all libfido2 checks passed");
	return failures != 0;
}
