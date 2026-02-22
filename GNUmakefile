vendors:
	test ! -d $@
	mkdir vendors
	@./source.sh

elit.hvt.target: | vendors
	@rm -f ./unikernels/elit.exe
	@rm -f ./unikernels/manifest.o
	@rm -f ./unikernels/manifest.c
	@echo " DESCR elit.exe"
	@dune describe location \
		--context solo5 --no-print-directory --root . --display=quiet \
		./unikernels/elit.exe 1> $@ 2>&1
	@echo " BUILD elit.exe"
	@dune build --root . --profile=release ./unikernels/elit.exe

elit.hvt: elit.hvt.target
	@echo " COPY elit.hvt: $(cat elit.hvt.target)"
	@cp $(file < elit.hvt.target) $@
	@chmod +w $@
	@echo " STRIP elit.hvt"
	@strip $@

all: elit.hvt | vendors

.PHONY: clean
clean:
	if [ -d vendors ] ; then rm -fr vendors ; fi
	rm -f elit.hvt.target
	rm -f elit.hvt
