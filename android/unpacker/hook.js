"use strict";


var didHookApis = false;

Java.perform(function() {
    // Credit to @enovella:
    // https://github.com/frida/frida/issues/434#issuecomment-423822024
    const System = Java.use("java.lang.System");
    const Runtime = Java.use('java.lang.Runtime');
    const SystemLoadLibrary = System.loadLibrary.overload('java.lang.String');
    const VMStack = Java.use('dalvik.system.VMStack');

    SystemLoadLibrary.implementation = function(library) {
        const loaded = Runtime.getRuntime().loadLibrary0(
            VMStack.getCallingClassLoader(), library
        );

        if (library.includes("konyjsvm")) {
            console.log("[+] Hooked konyjsvm");
            hookFunctions();
        }

        return loaded;
    }
});


function hookFunctions() {

    Interceptor.attach(Module.getExportByName("libkonyjsvm.so", "simpleSHA256"), {
        onEnter: function(args) {
            console.log("[+] Hooked simpleSHA256!");
            this.a = args[2]
        },
        onLeave: function(retval) {
            send("key", Memory.readByteArray(this.a, 32));
            Interceptor.detachAll();
        }
    })
};
