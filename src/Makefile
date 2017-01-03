#GCCVERSION := $(shell awk 'BEGIN {"g++ --version" | getline LINE; split(LINE, TK, "[. ]*"); print TK[3]TK[4]; exit}' )
#AUTO_LIBSTDCPP := $(shell awk 'BEGIN {"g++ --version" | getline LINE; split(LINE, TK, "[. ]*"); GV=TK[3]TK[4]; if (GV!="34" && GV!="41") print "/usr/lib64/libstdc++.a"; exit}')
AUTO_TIMESTAMP := $(shell awk 'BEGIN {"g++ --version" | getline LINE; split(LINE, TK, "[. ]*"); GV=TK[3]TK[4]; if (GV<"42") print "-D __TIMESTAMPSTR__=\"" strftime() "\""; exit}')

PROG := dns_send

DEPS := . 


COMPILE_OPTIONS := \
	$(AUTO_TIMESTAMP) \
	-I . \
	-I ../  \
	-Wno-deprecated \
	-g -Wall -O2 -DNDEBUG

LINK_OPTIONS := \
    -L /usr/lib64 \
    -lpthread \
    $(AUTO_LIBSTDCPP)

	
SOURCE  := $(shell find $(DEPS) -name "*.cpp") $(shell find $(DEPS) -name "*.c")
OBJS    := $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCE)))

CC		:= g++
CFLAGS		:= $(COMPILE_OPTIONS)
CPPFLAGS	:= $(CFLAGS)


$(PROG):	$(OBJS)
	$(CC) $(CPPFLAGS) $(LDFLAGS) $(OBJS) $(LINK_OPTIONS) -o $@

clean:
	rm -rf $(PROG) $(OBJS) *~

install:
	cp $(PROG) /usr/local/ip_base_server/bin/

release:
	scp -P 12321 $(PROG) root@202.85.220.101:/usr/local/xmon_merger/bin/$(PROG).latest

release2:
	scp -P 12321 $(PROG) root@118.26.224.142:/usr/local/xmon_merger/bin/$(PROG).latest 
