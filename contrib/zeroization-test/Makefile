.PHONY: default

default:
	cargo build
	@-gdb -x test_zeroization.txt \
	 --batch-silent target/debug/vodozemac-zeroization-test >/dev/null 2>&1 \
	 && echo OK \
	 || echo FAIL

