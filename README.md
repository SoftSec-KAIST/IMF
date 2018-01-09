IMF: Inferred Model-based Fuzzer
========================

IMF is a kernel API fuzzer that leverages an automated API model
inferrence techinque proposed in our
[paper](http://daramg.gift/paper/han-ccs2017.pdf) at CCS. IMF
currently only supports macOS. To see how to configure and run
IMF, see the followings.

# Setup

## Requirements
- python2.7
- pypy
- clang

## How to run
1. Generate hooking library for APIs
```
$ ./gen-hook [output(hooking code) path]
$ clang  -Wall -dynamiclib -framework IOKit -framework CoreFoundation -arch i386\
         -arch x86_64 hook.c -o hook
```

2. Collect logs
```
$ DYLD_INSERT_LIBRARIES=[hooking library path] [program path] [program args]
```

3. Filter logs
```
$ ./filter-log [log dir] [output dir] [# of output(filtered log)] [# of core]
```

4. Infer a model and generate a fuzzer.
```
$ ./gen-fuzz [filtered logs path] [output(fuzzer code) path] [# of core]
```

5. Compile the fuzzer
```
$ clang -framework IOKit -framework CoreFoundation -arch i386 fuzz.c -o fuzz
```

6. Run the fuzzer
```
$ ./fuzz -f [log path] -s [seed] -b [bitlen] -r [rate] -l [# of max loops]
```

7. You may want to run the generated fuzzer within a while loop.

# CVEs

- CVE-2017-7159

# Authors

This research project has been conducted by [SoftSec Lab](https://softsec.kaist.ac.kr) at KAIST.

* [HyungSeok Han](http://daramg.gift/)
* [Sang Kil Cha](https://softsec.kaist.ac.kr/~sangkilc/)

# Citing IMF

To cite our paper ([pdf](http://daramg.gift/paper/han-ccs2017.pdf)):
```
@INPROCEEDINGS{han:ccs2017,
    author = {HyungSeok Han and Sang Kil Cha},
    title = {Inferred Model-based Fuzzing},
    booktitle = {Proceedings of the ACM Conference on Computer and Communications Security},
    year = {2017},
    pages = {2345--2358}
}
```

# Acknowledgement

The work was supported by Institute for Information & communications Technology Promotion (IITP) grant funded by the Korea government (MSIT).
