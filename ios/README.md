# iOS

## Unpacker

The `unpack.py` script extracts the application sourced code found in the IPA
passed as the `INFILE` parameter and writes it to `OUTDIR`.

```shell
$ ./unpacker/unpack.py
Usage: unpack.py [OPTIONS] INFILE PACKAGE_NAME OUTDIR

Error: Missing argument "infile".
```

The script takes three arguments:

1. `INFILE`: The IPA file to unpack.
2. `PACKAGE_NAME`: The package name of the IPA. For example, `com.example.app`.
3. `OUTDIR`: The directory to write the unpacked source code to.

```
$ ./unpacker/unpack.py Visualizer.ipa com.kony.visualizerpreviewmobile js
Available devices:
id                                        name          type
--  ----------------------------------------  ------------  ------
 0  local                                     Local System  local
 1  tcp                                       Local TCP     remote
 2  f84d76a13316d1b63cc60c36a5e322315b1a3ec7  iOS Device    usb

Select device (by index): 2
[+] Hooked CCCryptorCreate
Found iv: b'MjAxOTAzMDgxNTI5MDMwMw=='
Found key: b'6XNP5jMi6tmuUA4xlERavaY0Wr56RBsWCb9LLOrup6Q='
Unpacking IPA.

ayrx@d1visi0n:~/code/konyutils/ios$ ls js/
total 496K
drwxr-xr-x 2 ayrx ayrx 4.0K May 27 10:53 .
drwxr-xr-x 4 ayrx ayrx 4.0K May 27 10:53 ..
-rw-r--r-- 1 ayrx ayrx 488K May 27 10:53 K4C9S0V89DS9W

ayrx@d1visi0n:~/code/konyutils/ios$ file js/K4C9S0V89DS9W
js/K4C9S0V89DS9W: Zip archive data, at least v2.0 to extract
```
