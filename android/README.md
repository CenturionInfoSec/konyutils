# Android

## Unpacker

The `unpack.py` script extracts the application sourced code found in the APK
passed as the `INFILE` parameter and writes it to `OUTDIR`.

```shell
$ ./unpacker/unpack.py
Usage: unpack.py [OPTIONS] INFILE PACKAGE_NAME OUTDIR

Error: Missing argument "infile".
```

The script takes three arguments:

1. `INFILE`: The APK file to unpack.
2. `PACKAGE_NAME`: The package name of the APK. For example, `com.example.app`.
3. `OUTDIR`: The directory to write the unpacked source code to.

```shell
$ ./unpacker/unpack.py com.kony.FunctionPreviewApp_2017-09-21.apk com.kony.FunctionPreviewApp js
Available devices:
id            name          type
--  ------------  ------------  ------
 0  local         Local System  local
 1  tcp           Local TCP     remote
 2  FA69J0302683  Google Pixel  usb

Select device (by index): 2
[+] Hooked konyjsvm
[+] Hooked simpleSHA256!
Found key: b'mTzpKahGUBQBjym59PxRhB8UWzMAqhP5Ox7n/bNChis='
Unpacking APK.

$ ls js/
total 428K
drwxr-xr-x 2 ayrx ayrx 4.0K May 27 10:37 .
drwxr-xr-x 5 ayrx ayrx 4.0K May 27 10:38 ..
-rw-r--r-- 1 ayrx ayrx  57K May 27 10:37 common-jslibs.kfm.zip
-rw-r--r-- 1 ayrx ayrx 312K May 27 10:37 startup.js.zip
-rw-r--r-- 1 ayrx ayrx  48K May 27 10:37 workerthreads.kfm.zip

$ file js/startup.js.zip
js/startup.js.zip: Zip archive data, at least v1.0 to extract
```

## Debugger

The `patch_debug.py` script repacks an APK with a provided `libkonyjsvm.so`.
The repacked APK has to be manually signed before it can be loaded onto a
device.

```
$ ./debugger/patch_debug.py
Usage: patch_debug.py [OPTIONS] INFILE LIBKONYJSVM OUTFILE

Error: Missing argument "infile".
```

The script takes three arguments:
1. `INFILE`: The APK to repack.
2. `LIBKONYJSVM`: The debug build of `libkonyjsvm.so` to repack with.
3. `OUTFILE`: The location of the repacked APK.

The `debugger/vscode/` directory contains config files for Visual Studio Code
that can be used to connect to the debugger.
