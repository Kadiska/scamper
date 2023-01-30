# CAIDA Scamper
source: https://www.caida.org/catalog/software/scamper/#H2725

Scamper's developer is [Matthew Luckie](https://users.caida.org/~mjl/). He has written this following [publication](https://www.caida.org/catalog/software/scamper/scamper.pdf)

All releases of scamper are licensed under the GPL v2.


## Branches organization

Time to time, CAIDA provides a CVS snapshot of Scamper source's code.

Those source should fed "upstream" branch *(generated files should be ignored by root .gitignore)*

please use CVS snapshot name (such as "cvs-20211212a") as commit name in, to properly track code evolution.

"kadiska" branch, on the other hand will be reserved to kadiska changes made.

## Linux 

1- Makefile/Autoconf Generation

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

LIBS=-lpcap ./configure --disable-privsep --enable-debug # create Makefile
```

2- Compilation
```bash
make
```

## Windows

Prerequisites:
- visual studio 2022 (https://visualstudio.microsoft.com/fr/vs/community/)
- npcap (https://npcap.com/#download)

open `windows\vs2022.sln` visual studio 2022 project

After compiling the project, move the DLLs `Packet.dll` and `wpcap.dll` from npcap (_located on C:\Windows\System32\Npcap with the default installation_) closed to compiled scamper.exe

## Usage example

```bash
sudo scamper/scamper -c 'trace -P ICMP-paris  -w 1 -c 95 -q 2' -O json -i 8.8.8.8
```

Checkout [cli documentation](scamper.1.pdf)

