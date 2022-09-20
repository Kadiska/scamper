# CAIDA Scamper
source: https://www.caida.org/catalog/software/scamper/#H2725

Scamper's developer is [Matthew Luckie](https://users.caida.org/~mjl/). He has written this following [publication](https://www.caida.org/catalog/software/scamper/scamper.pdf)

All releases of scamper are licensed under the GPL v2.


## Branches organization

Time to time, CAIDA provides a CVS snapshot of Scamper source's code.

Those source should fed "upstream" branch *(generated files should be ignored by root .gitignore)*

please use CVS snapshot name (such as "cvs-20211212a") as commit name in, to properly track code evolution.

"kadiska" branch, on the other hand will be reserved to kadiska changes made.

## Makefile/Autoconf Generation

**Prerequist** : make sure you have installed automake (`sudo apt install automake`)

```batch
touch NEWS
touch README
touch AUTHORS
touch ChangeLog

aclocal # create aclocal.m4 macros
autoheader # create config.h.in
autoconf # create configure script
automake --add-missing # create Makefile.in from am files

./configure # create Makefile
```

## Compilation
```bash
make
```

## Usage example

```bash
sudo scamper/scamper -c 'trace -P ICMP-paris  -w 1 -c 95 -q 2' -O json -i 8.8.8.8
```

Checkout [cli documentation](scamper.1.pdf)

