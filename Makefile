SRCS = dhcpd.c options.c errwarn.c convert.c conflex.c confpars.c \
       tree.c memory.c bootp.c dhcp.c alloc.c print.c socket.c \
       hash.c tables.c inet.c db.c dispatch.c bpf.c packet.c raw.c \
       nit.c
PROG = dhcpd
MAN=dhcpd.8 dhcpd.conf.5

all:	dhcpd dhclient

.include <bsd.prog.mk>

DEBUG=-g

CFLAGS += $(DEBUG) -Wall -Wstrict-prototypes -Wno-unused \
	  -Wno-implicit -Wno-comment \
	  -Wno-uninitialized -Werror

dhclient:	dhclient.o $(COBJ)
	$(CC) -o dhclient dhclient.o $(COBJ)
