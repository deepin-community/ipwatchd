CC ?= cc
CFLAGS ?= -g -O2
override CFLAGS += -Wall -Wextra -Werror -std=gnu11
CPPFLAGS += $(shell pkg-config --cflags dbus-1 json-c)
LDLIBS += $(shell pkg-config --libs dbus-1 json-c)

TEST_BINARY = test_securityloader
TEST_TIMEOUT ?= 30

.PHONY: all check clean

all: $(TEST_BINARY)

$(TEST_BINARY): test_securityloader.c ../src/securityloader.c ../src/ipwatchd.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

check: $(TEST_BINARY)
	timeout $(TEST_TIMEOUT)s dbus-run-session -- ./$(TEST_BINARY)

clean:
	$(RM) $(TEST_BINARY)
