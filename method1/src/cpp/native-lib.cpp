#include <jni.h>
#include <string>
#include <android/log.h>

#include <vector>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <cstring>

#include "dump_dex.h"

extern "C"
JNIEXPORT jint JNICALL dumpDex(JNIEnv *env, jobject instance, jint apilevel, jint generation, jstring jpath) {

    return dump_dex(env, apilevel/*21*/, generation, jpath);

}
