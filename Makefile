TARGET         = ringdown
CSRC           = ringdown.c log.c conf.c cbuf.c

#OPTIMIZE       = -Os -mcall-prologues

#LIBS           = -lncurses -lform

CC             = gcc
CFLAGS         = -Wall $(OPTIMIZE) $(DEFS)
#LDFLAGS        = -Wl,-u,vfprintf -lprintf_flt
OBJ            = $(CSRC:.c=.o)


all: $(TARGET)


$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)


%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@


clean:
	rm -rf *.o $(TARGET)
