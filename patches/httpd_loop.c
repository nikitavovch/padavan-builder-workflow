		/* Check and process pending or expired requests.
		 * TLS connections are handshaken on first readiness and then go back to
		 * select() until the HTTP request arrives: browsers (Safari) pre-connect
		 * and send ClientHello long before the request, and blocking on such a
		 * connection stalled every other client of this single-threaded server. */
		{
			long now = uptime();

			TAILQ_FOREACH_SAFE(item, &pool.head, entry, next) {
				FILE *conn_fp = NULL;

				if (!selected || !FD_ISSET(item->fd, &rfds)) {
					if ((now - item->ts) < MAX_CONN_TIMEOUT)
						continue;
				} else {
#if defined (SUPPORT_HTTPS)
					if (item->ssl && !item->ssl_fp) {
						item->ssl_fp = ssl_server_fopen_ex(item->fd, &item->ssl_h);
						if (item->ssl_fp) {
							item->ts = now;
							if (!ssl_server_has_pending(item->ssl_h))
								continue;
						}
					}
					if (item->ssl)
						conn_fp = item->ssl_fp;
					else
#endif
					conn_fp = fdopen(item->fd, "r+");
				}

				FD_CLR(item->fd, &active_rfds);
				TAILQ_REMOVE(&pool.head, item, entry);
				pool.count--;

				if (conn_fp) {
					handle_request(conn_fp, item);
					fflush(conn_fp);
#if defined (SUPPORT_HTTPS)
					http_is_ssl = 0;
					if (!item->ssl)
#endif
					shutdown(item->fd, SHUT_RDWR);
					fclose(conn_fp);
					item->fd = -1;
				}
#if defined (SUPPORT_HTTPS)
				else if (item->ssl_fp) {
					/* expired after handshake: fclose sends close_notify and closes fd */
					fclose(item->ssl_fp);
					item->fd = -1;
				}
#endif

				if (item->fd >= 0) {
					shutdown(item->fd, SHUT_RDWR);
					close(item->fd);
				}

				free(item);
			}
		}
	}
