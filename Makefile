SRCS = dhcpd.c options.c errwarn.c convert.c conflex.c confpars.c \
       tree.c memory.c bootp.c dhcp.c alloc.c print.c socket.c \
       hash.c tables.c inet.c
PROG = dhcpd

all:	dhcpd dhclient

.include <bsd.prog.mk>

CFLAGS += -DDEBUG -g -Wall -Wstrict-prototypes -Wno-unused \
	  -Wno-uninitialized -Werror

dhclient:	dhclient.o confpars.o alloc.o memory.o options.o \
		hash.o tables.o inet.o convert.o conflex.o errwarn.o \
		tree.o print.o
	cc -o dhclient dhclient.o confpars.o alloc.o memory.o options.o \
		hash.o tables.o inet.o convert.o conflex.o errwarn.o \
		print.o tree.o