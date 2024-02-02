/* SPDX-License-Identifier: MIT
 * Robert Balas <balasr@iis.ee.ethz.ch
 */

#ifndef GDB_H
#define GDB_H

#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#define GDB_PORT "1234"
#define GDB_BACKLOG 10
#define GDB_RBUF_SIZE (4096 * 8)

struct gdb_packet {
	char raw[GDB_RBUF_SIZE];
	char payload[GDB_RBUF_SIZE];
	size_t len;
	int checksum;
};
struct gdb_ctx {
	int sfd;			     /* server file descriptor */
	int rfd;			     /* remote file descriptor */
	struct sockaddr_storage remote_addr; /* remote adddress */
	socklen_t remote_addrlen;	     /* remote address length */

	char remote_host[NI_MAXHOST];
	char remote_service[NI_MAXSERV];

	struct sim_ctx *sim; /* simulator context */
	struct mem_ctx *mem; /* simulator memory context */

	int trace;
};

void gdb_spawn_server(struct gdb_ctx *gdb);
int gdb_expect_ack(struct gdb_ctx *ctx);
int gdb_send_ack(struct gdb_ctx *ctx);
int gdb_recv_packet(struct gdb_ctx *ctx, struct gdb_packet *gpacket);
int gdb_call(struct gdb_ctx *gdb);

int gdb_report_halt_reason(struct gdb_ctx *ctx, struct gdb_packet *gpacket);
int gdb_report_supported(struct gdb_ctx *ctx, struct gdb_packet *gpacket);
int gdb_handle_packet(struct gdb_ctx *ctx, struct gdb_packet *gpacket);

#endif /* GDB_H */
