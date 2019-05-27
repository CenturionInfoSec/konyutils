"use strict";


Java.perform(function() {

    var konyMain = Java.use("com.konylabs.android.KonyMain");
    console.log(konyMain);
    var c = Java.use("com.konylabs.vmintf.c");

    // The method called by konyMain will change depending on the specific
    // APK. Use dex2jar and look for the method that returns a Handler.
    Java.choose("com.konylabs.vmintf.KonyJavaScriptVM", {
        onMatch: function (instance) {
            konyMain.N().post(c.$new(instance, 9222));
        },
        onComplete: function() {}
    })
})
