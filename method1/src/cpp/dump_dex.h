/**
 * Create by sp00f
 * dump dex , this implement was under android os version 5.0.2
 * @version 0.1
 */
#ifndef HELLO_DUMP_DEX_H
#define HELLO_DUMP_DEX_H

#include <jni.h>
#include <string>

#include <vector>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "alog.h"

#include "DexUtil.h"
#include "Debug.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline std::string get_main_classdef(const char* main_app_class) {
    std::string main_app_classdef = "L";
    main_app_classdef += main_app_class;
    main_app_classdef += ";";
    return main_app_classdef;
}

#define MAIN_APP_CLASS "com/example/hello/MainApplication" // You must modify here for the correct that you want.
#define MAIN_APP_CLASSDEF get_main_classdef(MAIN_APP_CLASS).c_str()

/**
 * dump dex
 * @param env JNIEnv
 * @param api_level  android api level
 * @return 0 success , < 0 failed
 */
int dump_dex(JNIEnv *env, jint api_level);


typedef enum  {
    under_android_4 = 3, android4x, android5, android6, android7,
    android8, android9
} Android_Version;

typedef struct {
    Android_Version maj_version; // Major version , such as 5
    std::string min_version; // minor version such 0.2 , not used in current
} Version_Info;

static Version_Info minfo;

static std::string get_android_os_version() {
    std::string version = std::to_string(minfo.maj_version);
    version.append(".").append(minfo.min_version);
    return version;
}

static Android_Version get_os_major_version() {
    return minfo.maj_version;
}

static void set_apilevel(jint apil) {
    if(apil < 14) {
        minfo.maj_version = under_android_4;
        minfo.min_version = "0";
    } else if (apil == 14) {
        minfo.maj_version = android4x;
        minfo.min_version = "0.2" ; // .0.1, .0.2
    } else if(apil == 15) {
        minfo.maj_version = android4x;
        minfo.min_version = "0.4" ; // .0.3, .0.4
    } else if(apil == 16) {
        minfo.maj_version = android4x;
        minfo.min_version = "1" ; // .1.x
    } else if(apil == 17) {
        minfo.maj_version = android4x;
        minfo.min_version = "2" ; // .2.x
    } else if(apil == 18) {
        minfo.maj_version = android4x;
        minfo.min_version = "3" ; // .3.x
    } else if(apil == 19) {
        minfo.maj_version = android4x;
        minfo.min_version = "4" ; // .4.x
    } else if(apil == 21) {
        minfo.maj_version = android5;
        minfo.min_version = "0" ; // .0
    } else if(apil == 22) {
        minfo.maj_version = android5;
        minfo.min_version = "1" ; // .1
    } else if(apil == 23) {
        minfo.maj_version = android6;
        minfo.min_version = "0" ; // .0
    } else if(apil == 24) {
        minfo.maj_version = android7;
        minfo.min_version = "0" ; // .0
    } else if(apil == 25) {
        minfo.maj_version = android7;
        minfo.min_version = "1" ; // .0
    } else if(apil == 26) {
        minfo.maj_version = android8;
        minfo.min_version = "0" ; // .0
    } else if(apil == 27) {
        minfo.maj_version = android8;
        minfo.min_version = "1" ; // .0
    } else if(apil == 28) {
        minfo.maj_version = android9;
        minfo.min_version = "0" ; // .0
    }
}

/**
 * different os version, different implement.
 * @param env JNIEnv
 * @param cookie1 DexFile->mCooke update 5
 * @param cookie2 DexFile->mCooke under 5
 * @return DexFile* list
 */
static void*  convert_java_array_to_dexfiles(JNIEnv* env, jlong cookie1, jint cookie2) ;

#ifdef __cplusplus
}
#endif
#endif //HELLO_DUMP_DEX_H
