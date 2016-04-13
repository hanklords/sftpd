PROGRAM = sftpd
#CPPFLAGS = -Wall -Wextra -Wno-format -D_DEFAULT_SOURCE
#CFLAGS = -g
#LDFLAGS = -L.
#LDLIBS = -lxxx
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

$(PROGRAM): $(OBJS)

test: $(PROGRAM)
	sftp -D ./sftpd 

release:
	$(MAKE) clean
	$(MAKE) CFLAGS=-O3
	strip $(PROGRAM)

clean:
	$(RM) $(PROGRAM) $(OBJS)

.PHONY: release clean
