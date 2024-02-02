/* SPDX-License-Identifier: MIT
 * Robert Balas <balasr@iis.ee.ethz.ch
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <byteswap.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aehneln.h"
#include "gdb.h"

/* currently we don't support multiple gdb/simulator concurrently so this is a
 * global */

static void *
get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in *)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void
gdb_spawn_server(struct gdb_ctx *gdb)
{
	struct sockaddr_storage remote_addr;
	socklen_t remote_addrlen;
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *rp;
	int sfd, rfd, e;

	hints = (struct addrinfo) { 0 };
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;

	e = getaddrinfo(NULL, GDB_PORT, &hints, &res);
	if (e != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(e));
		exit(EXIT_FAILURE);
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		struct sockaddr_in *host_sockaddr = (struct sockaddr_in *)res->ai_addr;
		struct in_addr *host_inaddr = &(host_sockaddr->sin_addr);

		char inaddr_str[INET_ADDRSTRLEN];
		const char *addr_str = inet_ntop(res->ai_family, host_inaddr, inaddr_str,
		    INET_ADDRSTRLEN);
		if (!addr_str) {
			perror("inet_ntop");
			exit(EXIT_FAILURE);
		}

		printf("gdb: starting server at %s:%s\n", addr_str, GDB_PORT);

		sfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sfd == -1)
			continue;
		if (bind(sfd, res->ai_addr, res->ai_addrlen) == 0)
			break; /* success */
		close(sfd);
	}
	freeaddrinfo(res);

	if (rp == NULL) { /* No address succeeded */
		perror("bind");
		exit(EXIT_FAILURE);
	}

	gdb->sfd = sfd;

	if (listen(sfd, GDB_BACKLOG) == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	/* TODO: make server restartable */
	remote_addrlen = sizeof(remote_addr);
	rfd = accept(sfd, (struct sockaddr *)&remote_addr, &remote_addrlen);
	if (rfd == -1) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	gdb->rfd = rfd;
	gdb->remote_addr = remote_addr;
	gdb->remote_addrlen = remote_addrlen;

	char s[INET6_ADDRSTRLEN];
	const char *inet_str = inet_ntop(remote_addr.ss_family,
	    get_in_addr((struct sockaddr *)&remote_addr), s, sizeof(s));
	if (!inet_str) {
		perror("inet_ntop");
		exit(EXIT_FAILURE);
	}

	printf("gdb: connection from %s\n", inet_str);

	e = getnameinfo((struct sockaddr *)&(gdb->remote_addr), gdb->remote_addrlen,
	    gdb->remote_host, NI_MAXHOST, gdb->remote_service, NI_MAXSERV, NI_NUMERICSERV);
	if (e) {
		fprintf(stderr, "getnameinfo: %s\n", gai_strerror(e));
		exit(EXIT_FAILURE);
	}

	e = gdb_expect_ack(gdb);
	if (e != 0) {
		fprintf(stderr, "gdb: error: gdb_expect_ack() failed\n");
		exit(EXIT_FAILURE);
	}
}

int
gdb_call(struct gdb_ctx *gdb)
{
	ssize_t nread;
	/* TODO: this is multiple KiB on the stack */
	struct gdb_packet gpacket = { 0 };

	nread = gdb_recv_packet(gdb, &gpacket);

	if (nread == 0)
		return -1; /* shutdown */
	if (nread == -1)
		return -1; /* ignore failed request */

	if (gdb->trace)
		printf("gdb: `%s' from %s:%s (%zd bytes)\n", gpacket.raw, gdb->remote_host,
		    gdb->remote_service, nread);

	nread = gdb_send_ack(gdb);
	if (nread == -1)
		return -1;

	/* TODO: error handling */
	gdb_handle_packet(gdb, &gpacket);

	return 0;
}

int
gdb_expect_ack(struct gdb_ctx *ctx)
{
	char rbuf[1] = { 0 };
	size_t rlen = 1;
	ssize_t nread;

	nread = recv(ctx->rfd, rbuf, rlen, 0);
	if (nread != 1) {
		fprintf(stderr, "gdb: error: gdb_recv_packet() failed\n");
		return -1;
	}

	switch (rbuf[0]) {
	case '+':
		return 0;
	case '-':
		return 1;
	default:
		fprintf(stderr, "gdb: error: bad response 0x%2x\n", rbuf[0]);
		return -1;
	}
}

int
gdb_send_ack(struct gdb_ctx *ctx)
{
	char rbuf[1] = { 0 };
	size_t rlen = 1;
	ssize_t nread;

	rbuf[0] = '+';
	nread = send(ctx->rfd, rbuf, rlen, 0);
	if (nread == -1) {
		fprintf(stderr, "gdb: error: gdb_send_packet() failed\n");
		perror("send");
		return -1;
	}
	return 0;
}

int
gdb_recv_packet(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	ssize_t nread;
	unsigned int checksum = 0;
	char *rbuf = gpacket->raw;

	memset(rbuf, 0, GDB_RBUF_SIZE);

	nread = recv(ctx->rfd, rbuf, GDB_RBUF_SIZE - 1, 0);
	if (nread == 0)
		return nread;
	if (nread == -1) {
		perror("recv");
		return nread;
	}
	/* at this point last byte of rbuf for sure is null */

	if (rbuf[0] != '$') {
		fprintf(stderr, "gdb: error: packet not starting with `$'\n");
		fprintf(stderr, "gdb: contents: `%s'\n", rbuf);
		return -1;
	}

	char *end = memrchr(rbuf, '#', nread);
	if (!end) {
		fprintf(stderr, "gdb: error: packet not ending with `#'\n");
		return -1;
	}

	/* check if the 2-byte checksum exists */
	if (end + 3 > rbuf + nread) {
		fprintf(stderr, "gdb: error: packet missing checksum or too small\n");
		return -1;
	}

	/* Verify checksum. Skip $ and stop at # */
	for (char *p = rbuf + 1; p < end; p++)
		checksum += ((unsigned int)*p) & 0xff;
	checksum &= 0xff;

	errno = 0;
	unsigned long packet_checksum = strtoul(end + 1, NULL, 16) & 0xff;
	if (errno) {
		perror("strtoul");
		return -1;
	}

	if (packet_checksum != checksum) {
		fprintf(stderr, "gdb: error: checksum mismatch\n");
		return -1;
	}

	/* fill in packet payload */
	memset(gpacket->payload, 0, GDB_RBUF_SIZE);
	memcpy(gpacket->payload, rbuf + 1, end - (rbuf + 1));
	gpacket->len = end - (rbuf + 1);
	gpacket->checksum = checksum;

	return nread;
}

int
gdb_send_packet(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	ssize_t nread;
	int checksum = 0;
	char *sbuf = gpacket->raw;
	size_t sbuflen = 0;

	if (gpacket->len > GDB_RBUF_SIZE - 4) {
		fprintf(stderr, "gdb: error: payload too large\n");
		return -1;
	}

	/* just to be sure we clear the send buffer */
	memset(sbuf, 0, GDB_RBUF_SIZE);
	sbuf[0] = '$';
	sbuflen += 1;
	memcpy(sbuf + 1, gpacket->payload, gpacket->len);
	sbuflen += gpacket->len;
	sbuf[sbuflen] = '#';
	sbuflen += 1;

	/* calculate checksum */
	for (char *p = gpacket->payload; p < gpacket->payload + gpacket->len; p++)
		checksum += ((unsigned int)*p) & 0xff;
	checksum &= 0xff;

	/* Convert to ascii. hexbuf is also null terminated. */
	char hexbuf[3] = { 0 };
	int nprnt = snprintf(hexbuf, sizeof(hexbuf), "%02x", checksum);
	if (nprnt < 0) {
		fprintf(stderr, "gdb: snprintf() failed\n");
		return -1;
	}

	memcpy(sbuf + sbuflen, hexbuf, sizeof(hexbuf) - 1);
	sbuflen += (sizeof(hexbuf) - 1);

	if (ctx->trace)
		printf("gdb: sending packet `%s'\n", sbuf);

	nread = send(ctx->rfd, sbuf, sbuflen, 0);
	if (nread == -1) {
		perror("send");
		return nread;
	}

	return nread;
}

static int
gdb_reply_str(struct gdb_ctx *ctx, struct gdb_packet *gpacket, char *reply)
{
	ssize_t nread = 0;

	memcpy(gpacket->payload, reply, strlen(reply));
	gpacket->len = strlen(reply);

	nread = gdb_send_packet(ctx, gpacket);

	int e = gdb_expect_ack(ctx);
	if (e != 0) {
		fprintf(stderr, "gdb: error: gdb_expect_ack() failed\n");
		exit(EXIT_FAILURE);
	}

	return nread;
}

int
gdb_report_halt_reason(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	return gdb_reply_str(ctx, gpacket, "S05");
}

int
gdb_report_supported(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	char key[] = "PacketSize=";
	char hexbuf[6] = { 0 };
	ssize_t nread = 0;

	memcpy(gpacket->payload, key, sizeof(key));

	int nprnt = snprintf(hexbuf, sizeof(hexbuf), "%05x", GDB_RBUF_SIZE);
	if (nprnt < 0) {
		fprintf(stderr, "gdb: snprintf() failed\n");
		return -1;
	}

	/* consider the null termination of key and hexbuf*/
	memcpy(gpacket->payload + (sizeof(key) - 1), hexbuf, sizeof(hexbuf) - 1);
	gpacket->len = sizeof(key) - 1 + sizeof(hexbuf) - 1;

	nread = gdb_send_packet(ctx, gpacket);

	int e = gdb_expect_ack(ctx);
	if (e != 0) {
		fprintf(stderr, "gdb: error: gdb_expect_ack() failed\n");
		exit(EXIT_FAILURE);
	}

	return nread;
}

int
gdb_reply_empty(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	ssize_t nread = 0;

	memset(gpacket->payload, 0, GDB_RBUF_SIZE);
	gpacket->len = 0;

	nread = gdb_send_packet(ctx, gpacket);

	int e = gdb_expect_ack(ctx);
	if (e != 0) {
		fprintf(stderr, "gdb: error: gdb_expect_ack() failed\n");
		exit(EXIT_FAILURE);
	}

	return nread;
}

int
gdb_reply_ok(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	return gdb_reply_str(ctx, gpacket, "OK");
}

#define GDB_NUM_GPR 32
#define GDB_NUM_OTHER 1

int
gdb_read_registers(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	/* Each register is 8 bytes wide which needs 16 bytes to represented as
	 * hex string */
	char hexregs[16 * (GDB_NUM_GPR + GDB_NUM_OTHER) + 1] = { 0 };
	int off = 0;

	struct sim_ctx *sim = ctx->sim;

	/* We use the following sequence: GPRs: 0..0x1f PC: 0x20. We need to do
	 * a byteswap since printf obviously prints numbers in big endian
	 * format */
	for (int k = 0; k < GDB_NUM_GPR; k++) {
		snprintf(hexregs + off, 16 + 1, "%016lx", bswap_64(sim->regs[k]));
		off += 16;
	}

	snprintf(hexregs + off, 16 + 1, "%016lx", bswap_64(sim->pc));

	return gdb_reply_str(ctx, gpacket, hexregs);
}

int
gdb_write_registers(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	/* skip 'G' */
	char *buf = gpacket->payload + 1;
	char hex[16 + 1] = { 0 };

	if (gpacket->len < 16 * (GDB_NUM_GPR + GDB_NUM_OTHER)) {
		fprintf(stderr, "gdb: `G' packet too small\n");
		return -1;
	}

	for (int k = 0; k < GDB_NUM_GPR + GDB_NUM_OTHER; k++) {
		memcpy(hex, buf + k * 16, 16);

		errno = 0;
		uint64_t val = bswap_64(strtoull(hex, NULL, 16));
		if (errno) {
			perror("strtoull");
			return -1;
		}

		if (k == 0)
			break; /* x0 is not writeable */
		else if (k < GDB_NUM_GPR)
			ctx->sim->regs[k] = val;
		else
			ctx->sim->pc = val;
	}

	return gdb_reply_ok(ctx, gpacket);
}

static void
numtohex(uint8_t num, char *out)
{
	const char *hex = "0123456789abcdef";
	*out++ = hex[(num >> 4) & 0xf];
	*out++ = hex[num & 0xf];
	*out = 0;
}

int
gdb_read_memory(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	/* format is: M'addr','len' */
	char *endptr, *next;
	uint64_t addr, len;
	int nread;

	errno = 0;
	addr = strtoull(gpacket->payload + 1, &endptr, 16);
	if (errno) {
		perror("strtoull");
		return -1;
	}

	next = memchr(gpacket->payload, ',', gpacket->len);
	errno = 0;
	len = strtoull(next + 1, &endptr, 16);
	if (errno) {
		perror("strtoull");
		return -1;
	}

	memset(gpacket->payload, 0, GDB_RBUF_SIZE);

	if (ctx->trace)
		printf("gdb: read memory at addr = %016lx, len = %016lx\n", addr, len);

	if (len * 2 > GDB_RBUF_SIZE) {
		fprintf(stderr, "gdb: `m' memory read too large\n");
		return -1;
	}

	char hexbuf[3] = { 0 };
	/* char debugbuf[3] = { 0 }; */
	for (uint64_t k = 0; k < len; k++) {
		uint8_t val = mem_vread8(ctx->sim, ctx->mem, addr + k);
		numtohex(val, hexbuf);
		/* int nprnt = snprintf(hexbuf, sizeof(hexbuf), "%02x", val); */
		/* if (nprnt < 0) { */
		/* 	fprintf(stderr, "gdb: snprintf() failed\n"); */
		/* 	return -1; */
		/* } */
		/* if (strcmp(hexbuf, debugbuf) != 0) { */
		/* 	fprintf(stderr, "fallback mismatch %s != %s\n", hexbuf, debugbuf); */
		/* 	exit(EXIT_FAILURE); */
		/* } */
		memcpy(gpacket->payload + 2 * k, hexbuf, 2);
	}
	gpacket->len = 2 * len;

	nread = gdb_send_packet(ctx, gpacket);

	int e = gdb_expect_ack(ctx);
	if (e != 0) {
		fprintf(stderr, "gdb: error: gdb_expect_ack() failed\n");
		exit(EXIT_FAILURE);
	}

	/* TODO: proper length handling */
	return nread;
}

int
gdb_write_memory(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	/* format is: M'addr','len':'hexadecimal-payload' */
	char *endptr, *next;
	uint64_t addr, len;

	errno = 0;
	addr = strtoull(gpacket->payload + 1, &endptr, 16);
	if (errno) {
		perror("strtoull");
		return -1;
	}

	next = memchr(gpacket->payload, ',', gpacket->len);
	errno = 0;
	len = strtoull(next + 1, &endptr, 16);
	if (errno) {
		perror("strtoull");
		return -1;
	}

	if (ctx->trace)
		printf("gdb: write memory at addr = %016lx, len = %016lx\n", addr, len);

	next = memchr(gpacket->payload, ':', gpacket->len);
	/* skip over ',' */
	next += 1;

	char hex[3] = { 0 };
	for (uint64_t k = 0; k < len; k++) {
		memcpy(hex, next + k * 2, 2);

		errno = 0;
		uint8_t val = strtoull(hex, NULL, 16);
		if (errno) {
			perror("strtoull");
			return -1;
		}
		/* printf("writing 0x%02x...\n", val); */
		/* we are forcing all accesses to go through address
		 * translation */
		mem_vwrite8(ctx->sim, ctx->mem, addr + k, val);
	}

	/* TODO: send error if we couldn't handle the full request */
	return gdb_reply_ok(ctx, gpacket);
}

int
gdb_continue(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	/* We simply stop the polling loop. This should resume execution of the
	 * simulator */
	ctx->sim->call_gdb = false;

	return gdb_reply_str(ctx, gpacket, "S05");
}

int
gdb_single_step(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	fprintf(stderr, "single stepping not implemented yet\n");
	exit(EXIT_FAILURE);
}

struct gdb_cmd {
	char *name;
	int (*func)(struct gdb_ctx *, struct gdb_packet *);
};

struct gdb_cmd gdb_cmds[] = {
	{ "?", &gdb_report_halt_reason },
	{ "g", &gdb_read_registers },
	{ "G", &gdb_write_registers },
	{ "c", &gdb_continue },
	{ "m", &gdb_read_memory },
	{ "M", &gdb_write_memory },
	{ "s", &gdb_single_step },
	{ "qSupported", &gdb_report_supported },
	{ "vMustReplyEmpty", &gdb_reply_empty },
	{ "!", &gdb_reply_empty },
	{ "Hg", &gdb_reply_empty },
	{ "unsupported", &gdb_reply_empty },
	{ 0 },
};

int
gdb_handle_packet(struct gdb_ctx *ctx, struct gdb_packet *gpacket)
{
	/* can be used as by called functions as scratchpad */
	/* struct gdb_packet *gpacket_buf = { 0 }; */
	char *buf = gpacket->payload;
	for (struct gdb_cmd *cmd = gdb_cmds; cmd->name; cmd++) {
		size_t cmd_len = strlen(cmd->name);
		/* printf("gdb: trying `%s', packet len %ld, cmd len %ld\n", cmd->name,
		 * gpacket->len, */
		/*     cmd_len); */
		if (cmd_len <= gpacket->len && strncmp(cmd->name, buf, cmd_len) == 0) {
			if (ctx->trace)
				printf("gdb: handling packet `%s'\n", cmd->name);
			cmd->func(ctx, gpacket);
			/* TODO: handle error code in func */
			break;
		} else if (strncmp(cmd->name, "unsupported", cmd_len) == 0) {
			if (ctx->trace)
				printf("gdb: unsupported command `%s'\n", buf);
			cmd->func(ctx, gpacket);
		}
	}
	return 0;
}
