"use strict";


Interceptor.attach(Module.findExportByName(null, "CCCryptorCreate"), {
    onEnter: function(args) {
        console.log("[+] Hooked CCCryptorCreate");

        var iv = args[5];
        if (iv != 0x0) {
            send("iv", Memory.readByteArray(iv, 16));
        }

        send("key", Memory.readByteArray(args[3], 32));
    },
    onLeave: function(retval) {
        Interceptor.detachAll();
    }
})
