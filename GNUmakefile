vendors:
	test ! -d $@
	mkdir vendors
	@./source.sh

lipap.hvt.target: | vendors
	@rm -f ./unikernels/lipap.exe
	@rm -f ./unikernels/manifest.o
	@rm -f ./unikernels/manifest.c
	@echo " DESCR lipap.exe"
	@dune describe location \
		--context solo5 --no-print-directory --root . --display=quiet \
		./unikernels/lipap.exe 1> $@ 2>&1
	@echo " BUILD lipap.exe"
	@dune build --root . --profile=release ./unikernels/lipap.exe

lipap.hvt: lipap.hvt.target
	@echo " COPY lipap.hvt: $(cat lipap.hvt.target)"
	@cp $(file < lipap.hvt.target) $@
	@chmod +w $@
	@echo " STRIP lipap.hvt"
	@strip $@

nec.hvt.target: | vendors
	@rm -f ./unikernels/nec.exe
	@rm -f ./unikernels/manifest.o
	@rm -f ./unikernels/manifest.c
	@echo " DESCR nec.exe"
	@dune describe location \
		--context solo5 --no-print-directory --root . --display=quiet \
		./unikernels/nec.exe 1> $@ 2>&1
	@echo " BUILD nec.exe"
	@dune build --root . --profile=release ./unikernels/nec.exe

nec.hvt: nec.hvt.target
	@echo " COPY nec.hvt: $(cat nec.hvt.target)"
	@cp $(file < nec.hvt.target) $@
	@chmod +w $@
	@echo " STRIP nec.hvt"
	@strip $@

ptt.target: | vendors
	@rm -f ./bin/ptt.exe
	@echo " DESCR ptt.exe"
	@dune describe location \
		--context default --no-print-directory --root . --display=quiet \
		./bin/ptt.exe 1> $@ 2>&1
	@echo " BUILD ptt.exe"
	@dune build --root . --profile=release ./bin/ptt.exe

ptt: ptt.target
	@echo " COPY ptt.exe: $(cat ptt.target)"
	@cp $(file < ptt.target) $@

ptt.install: lipap.hvt nec.hvt ptt
	@echo " GEN ptt.install"
	@ocaml install.ml > $@

all: ptt.install | vendors

.PHONY: clean
clean:
	if [ -d vendors ] ; then rm -fr vendors ; fi
	rm -f lipap.hvt.target
	rm -f lipap.hvt
	rm -f nec.hvt.target
	rm -f nec.hvt
	rm -f ptt.target
	rm -f ptt
	rm -f ptt.install

install: ptt.install
	@echo " INSTALL ptt"
	opam-installer ptt.install
