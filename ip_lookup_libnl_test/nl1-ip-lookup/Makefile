CC = gcc 

CFLAGS = -g
LDFLAGS	= -g
LIBS = -lnl

SRCS = nl1-ip-lookup.c utils.c
OBJS = nl1-ip-lookup.o utils.o

all: nl1-ip-lookup

nl1-ip-lookup: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

$(OBJS) : utils.h 

clean:
	rm -f *.o nl1-ip-lookup

distclean: clean

install:
	@true

