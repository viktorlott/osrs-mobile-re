"use strict";

console.log("Waiting for Java..");

function log(msg = "", tag = "myrsos-log") {
  Java.use("android.util.Log").v(tag, msg);
}

log("Initialized!");

//   Java.openClassFile(filePath)

Java.perform(function () {
  log(JSON.stringify(Java.enumerateMethods("*"), null, 2));

  // Create an instance of java.lang.String and initialize it with a string
  const JavaString = Java.use("java.lang.String");
  const exampleString1 = JavaString.$new(
    "Hello World, this is an example string in Java."
  );
  log("[+] exampleString1: " + exampleString1);
  log("[+] exampleString1.length(): " + exampleString1.length());

  // Create an instance of java.nio.charset.Charset, and initialize the default character set
  const Charset = Java.use("java.nio.charset.Charset");
  const charset = Charset.defaultCharset();
  // Create a byte array of a Javascript string
  const charArray = "This is a Javascript string converted to a byte array."
    .split("")
    .map(function (c) {
      return c.charCodeAt(0);
    });

  // Create an instance of java.lang.String and initialize it through an overloaded $new,
  // with a byte array and a instance of java.nio.charset.Charset
  const exampleString2 = JavaString.$new
    .overload("[B", "java.nio.charset.Charset")
    .call(JavaString, charArray, charset);
  log("[+] exampleString2: " + exampleString2);
  log("[+] exampleString2.length(): " + exampleString2.length());

  // Intercept the initialization of java.lang.Stringbuilder's overloaded constructor,
  // and write the partial argument to the console
  const StringBuilder = Java.use("java.lang.StringBuilder");
  // We need to replace .$init() instead of .$new(), since .$new() = .alloc() + .init()
  const ctor = StringBuilder.$init.overload("java.lang.String");
  ctor.implementation = function (arg) {
    let partial = "";
    const result = ctor.call(this, arg);
    if (arg !== null) {
      partial = arg.toString().replace("\n", "").slice(0, 10);
    }
    // log('new StringBuilder(java.lang.String); => ' + result);
    log('new StringBuilder("' + partial + '");');
    return result;
  };
  log("[+] new StringBuilder(java.lang.String) hooked");

  // Intercept the toString() method of java.lang.StringBuilder and write its partial contents to the
  const toString = StringBuilder.toString;
  toString.implementation = function () {
    const result = toString.call(this);
    let partial = "";
    if (result !== null) {
      partial = result.toString().replace("\n", "").slice(0, 10);
    }
    log("StringBuilder.toString(); => " + partial);
    return result;
  };
  log("[+] StringBuilder.toString() hooked");

  const Activity = Java.use("android.app.Activity");
  Activity.onResume.implementation = function () {
    log("onResume() got called! Let's call the original implementation");
    this.onResume();
  };
  log("new Initialized!");
});
