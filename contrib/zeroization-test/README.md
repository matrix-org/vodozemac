This test demonstrates that our zeroization approach works correctly.

The test is implemented using a GDB script and requires that it is run from
a custom vodozemac branch, `contrib/test-zeroization`. The single change in the
custom branch is needed solely to make some modules, structs and methods
public.

To perform the test, run:

1. `git checkout contrib/test-zeroization`
2. `cd contrib/test-zeroization`.
3. `make`

If the test is successful and the sensitive information is zeroized, `OK` will
be printed. Otherwise, the run will output `FAIL`.
