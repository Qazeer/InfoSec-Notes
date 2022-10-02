# Miscellaneous - Coverage guided fuzzing

### American Fuzzy Lop (AFL)

###### AFL compiler wrappers (if source code is available)

Comes with a number of compiler wrappers to add instrumentation in compiled
code:
  - `afl-gcc`
  - `afl-g++`
  - `afl-clang`
  - `afl-clang++`
  - `afl-clang-fast`
  - `afl-clang-fast++`

`AFL` compilers will assign a unique random id and add `_afl_maybe_log`
callbacks to every basic code blocks to trace block hit counts and determine
code coverage.

```
# -ggdb -O0: generates a debug build used for crash analysis later on.

afl-gcc -fsanitize=address,undefined -ggdb -O0 <INPUT_CODE_FILE> -o <OUTPUT_BINARY>
```

###### Tests cases minimization with AFL

The `AFL`'s `afl-cmin` utility can be used to minimize the tests cases /
fuzzing corpus by finding the smallest subset of inputs files that will trigger
the full range of instrumentation points in the targeted program.

```
afl-cmin -i <INPUT_CORPUS_FOLDER> -o <MINIMIZED_CORPUS_FOLDER> -- <TARGETED_APP>
```

###### AFL fuzzing

Information on the status screen can be found in the official
[AFL documention on the status screen](https://github.com/google/AFL/blob/master/docs/status_screen.txt).

```
# Example to generate a very basic img input corpus.
mkdir in && echo "IMG TEST" > in/1.img

afl-fuzz -i <INPUT_CORPUS_FOLDER> -o <OUTPUT_CRASH_FOLDER> -m none -- <TARGETED_APP> @@
```

If source code was not available and `AFL` callbacks couldn't be added to the
targeted program, the `qemu` fuzzing mode should be used:

```
# Support to qemu mode should be enabled first.
sudo ./build_qemu_support.sh

# Blackbox fuzzing of the targeted program.
afl-fuzz -Q -i <INPUT_CORPUS_FOLDER> -o <OUTPUT_CRASH_FOLDER> -- <TARGETED_APP> @@
```

`AFL` can run in a multi-cores / distributed mode, with a master and one or
more slave instances. The instances will then synchronize on the execution
paths found.

```
screen -S <MASTER_ID>
afl-fuzz -M <MASTER_ID> -i <INPUT_CORPUS_FOLDER> -o <OUTPUT_CRASH_FOLDER> -m none -- <TARGETED_APP> @@

# Can be repeated to add more slave instances.
screen -S <SLAVE_ID>
afl-fuzz -S <SLAVE_ID> -i <INPUT_CORPUS_FOLDER> -o <OUTPUT_CRASH_FOLDER> -m none -- <TARGETED_APP> @@
```

###### AFL crashes analysis with GDB

Source:

https://trustfoundry.net/introduction-to-triaging-fuzzer-generated-crashes/

```
# The targeted program should be compiled with no code optimization (with -ggdb -O0 for example).
gdb <TARGETED_APP>

# Crach file name example: id:000000,sig:06,src:000000,op:havoc,rep:16
(gdb) r <AFL_CRASH_FILE>
```
