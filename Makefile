BASEFLAGS := -Wall -Wextra -pedantic -pipe -std=c11 -pthread
DEBUGFLAGS := -g -O0
RELEASEFLAGS := -s -O3 -march=native -flto -DNDEBUG
LIBFLAGS := 

all debug release: dns.o
	$(CC) $(CUSTOM_CFLAGS) dns.o $(LIBFLAGS) -o dns.elf

# Prevent clean from trying to do anything with a file called clean
.PHONY: clean

clean:
	$(RM) $(wildcard *.gch) dns.elf dns.o $(wildcard *.out)

#Check if in debug mode and set the appropriate compile flags
ifeq (,$(filter debug, $(MAKECMDGOALS)))
$(eval CUSTOM_CFLAGS := $(BASEFLAGS) $(RELEASEFLAGS))
else
$(eval CUSTOM_CFLAGS := $(BASEFLAGS) $(DEBUGFLAGS))
endif

%.o: %.c
	$(CC) $(CUSTOM_CFLAGS) -c $<
