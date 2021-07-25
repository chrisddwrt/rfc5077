/*
 * Copyright (c) 2011 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Simple client using OpenSSL as backend. */

#include "common.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <libubox/uloop.h>

extern int no_disconnect;

static void connect_timer_cb(struct uloop_timeout *t);

static struct uloop_timeout connect_timer = {
	.cb = connect_timer_cb
};

static struct config {
	struct addrinfo* addr;
	int n_connects;
	int n_connects_max;
	int use_sessionid;
	int use_ticket;
	int delay_ms;
	char *host;
	char *port;
	SSL_CTX *ssl_ctx;
	SSL_SESSION *ssl_session;
} cfg;

struct tls_conn {
	struct uloop_fd fd;
	SSL *ssl;
	int id;
};

static void tls_conn_free(struct tls_conn *tc)
{
	uloop_fd_delete(&tc->fd);
	SSL_shutdown(tc->ssl);
	close(tc->fd.fd);
	SSL_free(tc->ssl);
	free(tc);
}

static int get_last_socket_error(int fd)
{
        int err = 0;
        socklen_t len = sizeof(err);

        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        return err;
}

static const char * get_socket_source(int fd)
{
	static char strbuf[INET6_ADDRSTRLEN + 16];
	char addrbuf[INET6_ADDRSTRLEN];
	struct sockaddr_storage ss = {};
	socklen_t addrlen = sizeof(ss);
	unsigned short port;
	void *addr;

	getsockname(fd, (struct sockaddr *)&ss, &addrlen);

	if (ss.ss_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)&ss;

		addr = &in->sin_addr;
		port = ntohs(in->sin_port);
	} else {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;

		addr = &in6->sin6_addr;
		port = ntohs(in6->sin6_port);
	}

	inet_ntop(ss.ss_family, addr, addrbuf, sizeof(addrbuf));
	sprintf(strbuf, "%s:%hu", addrbuf, port);

	return strbuf;
}

static void tls_conn_cb(struct uloop_fd *fd, unsigned events)
{
	struct tls_conn *tc = container_of(fd, struct tls_conn, fd);

	if (fd->eof || fd->error) {
		int err = get_last_socket_error(fd->fd);

		start("connection closed id = %d, source = %s (%s)",
			tc->id, get_socket_source(fd->fd),
			err ? strerror(err) : "");
		tls_conn_free(tc);
		return;
	}
	
	if (events & ULOOP_READ) {
		char buffer[256];
		int n;

		start("Get HTTP answer");

		if ((n = SSL_read(tc->ssl, buffer, sizeof(buffer) - 1)) <= 0)
			fail("SSL read request failed:\n%s",
				ERR_error_string(ERR_get_error(), NULL));

		buffer[n] = '\0';
		if (strchr(buffer, '\r'))
			*strchr(buffer, '\r') = '\0';
		end("%s", buffer);
	}
}

static void tls_conn_connect(struct tls_conn *tc)
{
	char buffer[256];
	int n;
	int fd;

	tc->ssl = SSL_new(cfg.ssl_ctx);
	if (tc->ssl == NULL)
		fail("Unable to create new SSL struct:\n%s",
			ERR_error_string(ERR_get_error(), NULL));

	fd = connect_socket(cfg.addr, cfg.host, cfg.port);
	SSL_set_fd(tc->ssl, fd);

	/* reuse session when available */
	if (cfg.ssl_session) {
		if (!SSL_set_session(tc->ssl, cfg.ssl_session)) {
			fail("Unable to set session to previous one:\n%s",
				ERR_error_string(ERR_get_error(), NULL));
		}
	}

	if (SSL_connect(tc->ssl) != 1)
		fail("Unable to start TLS renegotiation:\n%s",
		ERR_error_string(ERR_get_error(), NULL));

	start("Check if session was reused id = %d", tc->id);

	if (!SSL_session_reused(tc->ssl) && cfg.ssl_session)
		warn("No session was reused.");
	else if (SSL_session_reused(tc->ssl) && !cfg.ssl_session)
		warn("Session was reused.");
	else if (SSL_session_reused(tc->ssl))
		end("SSL session correctly reused");
	else
		end("SSL session was not used");

	start("Get current session");
	if (cfg.ssl_session) {
		SSL_SESSION_free(cfg.ssl_session);
		cfg.ssl_session = NULL;
	}

	if (!(cfg.ssl_session = SSL_get1_session(tc->ssl)))
		warn("No session available");
	else {
		BIO *mem = BIO_new(BIO_s_mem());
		char *buf;
		if (SSL_SESSION_print(mem, cfg.ssl_session) != 1)
			fail("Unable to print session:\n%s",
			     ERR_error_string(ERR_get_error(), NULL));
		n = BIO_get_mem_data(mem, &buf);
		buf[n-1] = '\0';
		end("Session content:\n%s", buf);
		BIO_free(mem);
	}

	if ((!cfg.use_sessionid && !cfg.use_ticket) ||
		(!cfg.use_sessionid && !cfg.ssl_session->tlsext_tick)) {
			SSL_SESSION_free(cfg.ssl_session);
			cfg.ssl_session = NULL;
	}

	start("Send HTTP GET");
	n = snprintf(buffer, sizeof(buffer),
			"GET / HTTP/1.0\r\n"
			"Host: %s\r\n"
			"\r\n", cfg.host);

	if (n == -1 || n >= sizeof(buffer))
		fail("Unable to build request to send");

	if (SSL_write(tc->ssl, buffer, strlen(buffer)) != strlen(buffer))
		fail("SSL write request failed:\n%s",
			ERR_error_string(ERR_get_error(), NULL));

	tc->fd.fd = fd;
	tc->fd.cb = tls_conn_cb;
	uloop_fd_add(&tc->fd, ULOOP_READ);
}

static void connect_timer_cb(struct uloop_timeout *t)
{
	struct tls_conn *tc;

	cfg.n_connects += 1;

	if (cfg.n_connects > cfg.n_connects_max) {
		uloop_end();
		return;
	}

	tc = calloc(1, sizeof(*tc));
	if (tc) {
		tc->id = cfg.n_connects;
		tls_conn_connect(tc);
	}

	uloop_timeout_set(t, cfg.delay_ms);
}

static int connect_ssl_no_disconnect(char *host, char *port,
                          int reconnect,
                          int use_sessionid, int use_ticket,
                          int delay,
                          const char *client_cert, const char *client_key)
{
	SSL_CTX*         ctx;
	long opts = SSL_OP_ALL;

	start("Initialize OpenSSL library");
	SSL_load_error_strings();
	SSL_library_init();
	if ((ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL)
		fail("Unable to initialize SSL context:\n%s",
		     ERR_error_string(ERR_get_error(), NULL));

	if (client_cert || client_key) {
		if (SSL_CTX_use_certificate_chain_file(ctx,client_cert)==0) {
			fail("failed to read X509 certificate from file %s into PEM format",client_key);
		}
	}
	if (client_key) {
		if (SSL_CTX_use_PrivateKey_file(ctx,client_key,SSL_FILETYPE_PEM)==0) {
			fail("failed to read private key from file %s into PEM format",client_key);
		}
	}
	if (!use_ticket) {
		start("Disable use of session tickets (RFC 5077)");
		SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
	}
	// Allow only TLS 1.2
	opts |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1;
	opts |= TLS1_2_VERSION;
	SSL_CTX_set_options(ctx, opts);

	cfg.addr = solve(host, port);
	cfg.n_connects = 0;
	cfg.n_connects_max = reconnect;
	cfg.use_sessionid = use_sessionid;
	cfg.use_ticket = use_ticket;
	cfg.delay_ms = delay * 1000;
	cfg.ssl_ctx = ctx;
	cfg.host = host;
	cfg.port = port;

	uloop_init();
	uloop_timeout_set(&connect_timer, 1);
	uloop_run();
	uloop_done();

	SSL_CTX_free(ctx);
	return 0;
}

static int connect_ssl_normal(char *host, char *port,
	            int reconnect,
	            int use_sessionid, int use_ticket,
	            int delay,
	            const char *client_cert, const char *client_key)
{
	SSL_CTX*         ctx;
	SSL*             ssl;
	SSL_SESSION*     ssl_session = NULL;
	int              s, n;
	char             buffer[256];
	struct addrinfo* addr;
	long opts = SSL_OP_ALL;
	int rsave=reconnect;


	start("Initialize OpenSSL library");
	SSL_load_error_strings();
	SSL_library_init();
	if ((ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL)
		fail("Unable to initialize SSL context:\n%s",
		     ERR_error_string(ERR_get_error(), NULL));

	if (client_cert || client_key) {
		if (SSL_CTX_use_certificate_chain_file(ctx,client_cert)==0) {
			fail("failed to read X509 certificate from file %s into PEM format",client_key);
		}
	}
	if (client_key) {
		if (SSL_CTX_use_PrivateKey_file(ctx,client_key,SSL_FILETYPE_PEM)==0) {
			fail("failed to read private key from file %s into PEM format",client_key);
		}
	}
	if (!use_ticket) {
		start("Disable use of session tickets (RFC 5077)");
		SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
	}
	// Allow only TLS 1.2
	opts |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1;
	opts |= TLS1_2_VERSION;
	SSL_CTX_set_options(ctx, opts);

	// SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384");

	addr = solve(host, port);
	do {
		s = connect_socket(addr, host, port);
		start("Start TLS renegotiation");
		if ((ssl = SSL_new(ctx)) == NULL)
			fail("Unable to create new SSL struct:\n%s",
			     ERR_error_string(ERR_get_error(), NULL));
		SSL_set_fd(ssl, s);
		if (ssl_session) {
			if (!SSL_set_session(ssl, ssl_session)) {
				fail("Unable to set session to previous one:\n%s",
				     ERR_error_string(ERR_get_error(), NULL));
			}
		}
		if (SSL_connect(ssl) != 1)
			fail("Unable to start TLS renegotiation:\n%s",
			     ERR_error_string(ERR_get_error(), NULL));

		start("Check if session was reused");
		if (!SSL_session_reused(ssl) && ssl_session)
			warn("No session was reused.");
		else if (SSL_session_reused(ssl) && !ssl_session)
			warn("Session was reused.");
		else if (SSL_session_reused(ssl))
			end("SSL session correctly reused");
		else
			end("SSL session was not used");
		start("Get current session");
		if (ssl_session) SSL_SESSION_free(ssl_session);
		ssl_session = NULL;
		if (!(ssl_session = SSL_get1_session(ssl)))
			warn("No session available");
		else {
			BIO *mem = BIO_new(BIO_s_mem());
			char *buf;
			if (SSL_SESSION_print(mem, ssl_session) != 1)
				fail("Unable to print session:\n%s",
				     ERR_error_string(ERR_get_error(), NULL));
			n = BIO_get_mem_data(mem, &buf);
			buf[n-1] = '\0';
			end("Session content:\n%s", buf);
			BIO_free(mem);
		}
		if ((!use_sessionid && !use_ticket) ||
		    (!use_sessionid && !ssl_session->tlsext_tick)) {
			SSL_SESSION_free(ssl_session);
			ssl_session = NULL;
		}

		start("Send HTTP GET");
		n = snprintf(buffer, sizeof(buffer),
		             "GET / HTTP/1.0\r\n"
		             "Host: %s\r\n"
		             "\r\n", host);
		if (n == -1 || n >= sizeof(buffer))
			fail("Unable to build request to send");
		if (SSL_write(ssl, buffer, strlen(buffer)) != strlen(buffer))
			fail("SSL write request failed:\n%s",
			     ERR_error_string(ERR_get_error(), NULL));

		start("Get HTTP answer");
		if ((n = SSL_read(ssl, buffer, sizeof(buffer) - 1)) <= 0)
			fail("SSL read request failed:\n%s",
			     ERR_error_string(ERR_get_error(), NULL));
		buffer[n] = '\0';
		if (strchr(buffer, '\r'))
			*strchr(buffer, '\r') = '\0';
		end("%s", buffer);
		start("End TLS connection");
		SSL_shutdown(ssl);
		close(s);
		SSL_free(ssl);

		--reconnect;
		if (reconnect < 0) break;
		else {
			if ((rsave - reconnect) == 10) {
				start("waiting 30 seconds");
				sleep(30);
			} else {
				start("waiting %d seconds",delay);
				sleep(delay);
			}
		}
	} while (1);

	SSL_CTX_free(ctx);
	return 0;
}

static int connect_ssl(char *host, char *port,
	            int reconnect,
	            int use_sessionid, int use_ticket,
	            int delay,
	            const char *client_cert, const char *client_key)

{
	int rc;

	if (no_disconnect)
		rc = connect_ssl_no_disconnect(host, port, reconnect,
					use_sessionid, use_ticket,
					delay, client_cert, client_key);
	else
		rc = connect_ssl_normal(host, port, reconnect,
					use_sessionid, use_ticket,
					delay, client_cert, client_key);

	return rc;
}

int main(int argc, char * const argv[])
{
	return client(argc, argv, connect_ssl);
}
