default:
	[ -f build/Makefile ] || (mkdir -p build ; cd build ; cmake ..)
	$(MAKE) -C build

test:
	$(MAKE) -C test

clean:
	rm -rf build/
