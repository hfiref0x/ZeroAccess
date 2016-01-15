
#ZeroAccess
## Toolkit for ZeroAccess/Sirefef v3

ZeroAccess is an advanced malware family (probably most advanced from all of available), whose first appearance was in the middle of 2009. Initially Win32 kernel mode rootkit, transformed then into user 

mode toolkit. Uses self made p2p engine for communication (main purpose - download files). Based on modular structure. Survived multiple takedown attempts (they were mostly serving marketing purposes of 

various so-called security companies/corporations). Has multiple generations of various toolkit modules.

This project provide you insights into ZeroAccess v3 code and provide several instruments to work with ZeroAccess v3 files.

# Project contents

**Umikaze - peer list (@ file) decoder**

Processes input file as ZeroAccess peer file, type required for correct port assignation. 
Result is output file with Time and IP+Port pairs as text. Usage:

+ umikaze peerlist_filename [type 32 or 64, default 32], e.g. umikaze s32 32

**Shigure - payload decryptor**

Processes input as ZeroAccess payload container, attempting to decode it using RC4 and extract Microsoft Cabinet afterthat.

Usage: 
+ shigure inputfile [outputfile], e.g. shigure 80000000.@ out.bin

**Harusame - payload container verificator**

Verifies if given file is valid container for ZeroAccess. Requires EA to be set at input file. More information about verification algorithm can be found in source.

Usage: 
+ harusame inputfile [mode, default 32], e.g. harusame 80000000.@ 32

...

# Build 

Project comes with full source code.
In order to build from source you need:
Microsoft Visual Studio 2015 U1 and later versions.
 
# Authors

(c) 2016 ZeroAccess Project
