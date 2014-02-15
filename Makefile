PROGRAM = sftpd
CFLAGS = -Wall -std=c11 -D_DEFAULT_SOURCE -g
#LDFLAGS = -L.
#LDLIBS = -lxxx
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

$(PROGRAM): $(OBJS)

test: $(PROGRAM)
	sftp -D ./sftpd 

release:
	$(MAKE) clean
	$(MAKE) CFLAGS=-Os LDFLAGS="$(LDFLAGS) -s"

clean:
	$(RM) $(PROGRAM) $(OBJS)

.PHONY: release clean
