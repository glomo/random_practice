CC = gcc 

NL_HDR=/home/xuywang/git/libnl/libnl-3.2.23/include/
NL_LIB=/home/xuywang/usnic/local/lib

CFLAGS = -g
CFLAGS += -I $(NL_HDR)
LDFLAGS	= -g
LIBS = -L $(NL_LIB) -lnl-3 -lnl-cli-3 

SRCS = nl-ip-lookup.c 
OBJS = nl-ip-lookup.o 

all: nl-ip-lookup

nl-ip-lookup: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

#$(OBJS) : $(SRCS)
#	$(CC) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -f *.o nl-ip-lookup

distclean: clean

install:
	@true

