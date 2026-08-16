# Consuming apps must not strip the embedded shell entry points.
-keep class com.yqsh.protector.shell.ProxyApplication { *; }
-keep class com.yqsh.protector.shell.ProxyComponentFactory { *; }
-keep class com.yqsh.protector.shell.JniBridge {
    native <methods>;
    *;
}
-keep class com.yqsh.protector.shell.DexMerger { *; }
-keep class com.yqsh.protector.shell.ApplicationReplacer { *; }
