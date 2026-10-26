
FILE *ssl_server_fopen(int fd)
{
	return ssl_server_fopen_ex(fd, NULL);
}

/* Decrypted or still-unprocessed TLS data buffered inside OpenSSL (read_ahead is on),
 * which select() on the socket cannot see. */
int ssl_server_has_pending(void *h)
{
	http_ssl_cookie_t *hsc = (http_ssl_cookie_t *)h;

	if (!hsc || !hsc->ssl)
		return 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	return SSL_has_pending(hsc->ssl);
#else
	return SSL_pending(hsc->ssl) > 0;
#endif
}
