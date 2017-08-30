all:
	@$(MAKE) -C src

install:
	@$(MAKE) -C src install
	@install lib/*.lua /usr/local/share/lua/5.1/

clean:
	@$(MAKE) -C src clean
