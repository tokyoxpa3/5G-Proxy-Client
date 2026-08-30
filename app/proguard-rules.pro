# Add project specific ProGuard rules here.

# JNI：NativeEngine 由原生 JNI_OnLoad / native_register_instance 以
# FindClass("com/tokyoxpa3/socksclient/NativeEngine") 字串查找，
# 其方法（createSocketFromNative 等）亦以 GetMethodID 快取後自原生呼叫。
# R8 不得更名類別或移除/更名這些方法，否則 JNI 無法解析。
-keep class com.tokyoxpa3.socksclient.NativeEngine { *; }

# 原生方法符號保留（目前用 RegisterNatives 綁定，保留以備未來動態查找）
-keepclasseswithmembernames class * {
    native <methods>;
}
