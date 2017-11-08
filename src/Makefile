CFLAGS+=-O2

all: webcore.so

webcore.so: webcore_codec.o webcore_stream.o webcore_uv.o webcore.o
	@echo "    LD\t$@"
	@$(CC) --shared -o $@ webcore_codec.o webcore_stream.o webcore_uv.o webcore.o -luv -lssl -lcrypto

%.o: %.c
	@echo "    CC\t$<"
	@$(CC) -c -Wall -o $@ $(CFLAGS) $< -fPIC \

install: webcore.so
	@install $< /usr/local/lib/lua/5.1

clean:
	rm -f *.o webcore.so
