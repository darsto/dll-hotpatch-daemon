OBJECTS = main.o exe.o gdbproxy.o sock.o
CFLAGS := -m32 -Wall -Werror -O2 -ggdb -MMD -MP $(CFLAGS)
CFLAGS += -D_WIN32_WINNT=0x601

$(shell mkdir -p build &>/dev/null)

all: build/hookdaemon.exe

clean:
	rm -f $(OBJECTS:%.o=build/%.o) $(OBJECTS:%.o=build/%.d) build/hookdaemon.exe

build/hookdaemon.exe: $(OBJECTS:%.o=build/%.o)
	gcc $(CFLAGS) -o build/hookdaemon.exe $^ -lws2_32

build/%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

-include $(OBJECTS:%.o=build/%.d)