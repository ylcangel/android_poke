#include <vector>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string>

#include "dump_dex.h"

#include "ScopedLocalRef.h"
#include "ScopedUtfChars.h"

#include "DexUtil.h"
#include "Debug.h"

// android 5.0.2

static std::vector<const DexFile*>* toDexFiles(jlong dex_file_address, JNIEnv* env) {
    std::vector<const DexFile*>* dex_files = reinterpret_cast<std::vector<const DexFile*>*> (
            static_cast<uintptr_t> (dex_file_address));
    return dex_files;
}

//you need add you version implement

static void* convert_java_array_to_dexfiles(JNIEnv* env, jlong cookie1, jint cookie2) {
    void* dexfiles = NULL;
    if (/*get_android_os_version().compare("5.0.2")*/ get_os_major_version() == android5) {
        dexfiles = toDexFiles(cookie1, env);
    }

    return dexfiles;
}

int dump_dex(JNIEnv *env, jint api_level) {

    set_apilevel(api_level);

    ScopedLocalRef<jclass> javaClass(env, env->FindClass("java/lang/Class"));
    ALOGI("[*] javaClass: %p", javaClass.get());

    jmethodID getClassLoaderMeth = env->GetMethodID(javaClass.get(), "getClassLoader", "()Ljava/lang/ClassLoader;");
    ALOGI("[*] getClassLoaderMeth: %p", getClassLoaderMeth);

    ScopedLocalRef<jclass> appClass(env, env->FindClass(MAIN_APP_CLASS));
    ALOGI("[*] appClass: %p", appClass.get());

    ScopedLocalRef<jobject> classLoader(env, env->CallObjectMethod(appClass.get(), getClassLoaderMeth));
    ALOGI("[*] classLoader: %p", classLoader.get());

    ScopedLocalRef<jclass> baseLoader(env, env->FindClass("dalvik/system/BaseDexClassLoader"));
    ALOGI("[*] baseLoader: %p", baseLoader.get());

    jfieldID pathListField = env->GetFieldID(baseLoader.get(), "pathList", "Ldalvik/system/DexPathList;");
    ALOGI("[*] pathListField: %p", pathListField);

    ScopedLocalRef<jobject> pathList(env, env->GetObjectField(classLoader.get(), pathListField));
    ALOGI("[*] pathList: %p", pathList.get());

    ScopedLocalRef<jclass> pathListClass(env, env->GetObjectClass(pathList.get()));
    ALOGI("[*] pathListClass: %p", pathListClass.get());

    jfieldID dexElementsField = env->GetFieldID(pathListClass.get(), "dexElements", "[Ldalvik/system/DexPathList$Element;");
    ALOGI("[*] dexElementsField: %p", dexElementsField);

    ScopedLocalRef<jobjectArray> dexElements(env, (jobjectArray) env->GetObjectField(pathList.get(), dexElementsField));
    ALOGI("[*] dexElements: %p", dexElements.get());

    jsize dexElementsSize = env->GetArrayLength(dexElements.get());
    ALOGI("[*] dexElements size: %u", dexElementsSize);

    bool is_dumped = false;

    for (int i = 0; i < dexElementsSize; i++) {
        if (is_dumped)
            break;

        ScopedLocalRef<jobject> element(env, env->GetObjectArrayElement(dexElements.get(), i));
        ALOGI("[*] element: %p", element.get());

        ScopedLocalRef<jclass> elementClass(env, env->GetObjectClass(element.get()));
        ALOGI("[*] elementClass: %p", elementClass.get());

        jfieldID dexFileField = env->GetFieldID(elementClass.get(), "dexFile",
                                                "Ldalvik/system/DexFile;");
        ALOGI("[*] dexFileField: %p", dexFileField);

        ScopedLocalRef<jobject> dexFile(env, env->GetObjectField(element.get(), dexFileField));
        ALOGI("[*] dexFile: %p", dexFile.get());

        if (dexFile.get() != NULL) {
            ScopedLocalRef<jclass> dexFileClass(env, env->GetObjectClass(dexFile.get()));
            ALOGI("[*] dexFileClass: %p", dexFileClass.get());

            jfieldID fileNameField = env->GetFieldID(dexFileClass.get(), "mFileName",
                                                     "Ljava/lang/String;");
            jstring fileName = (jstring) env->GetObjectField(dexFile.get(), fileNameField);
            ALOGI("[*] dex file name: %s", env->GetStringUTFChars(fileName, NULL));

            jlong cookie1 = 0;
            jint cookie2 = 0;

            jfieldID cookieField = env->GetFieldID(dexFileClass.get(), "mCookie", "J");
            if (cookieField == NULL) {
                env->ExceptionClear();
                cookieField = env->GetFieldID(dexFileClass.get(), "mCookie", "I");
                cookie2 = env->GetIntField(dexFile.get(), cookieField);
                ALOGI("[*] under android 5 cookie: 0x%08x", cookie2);
            } else {
                cookie1 = env->GetLongField(dexFile.get(), cookieField);
                ALOGI("[*] cookie in android above 5: 0x%llx", cookie1);
            }

            ALOGI("[*] cookieField: %p", cookieField);

            std::vector<const DexFile*>* dex_files = (std::vector<const DexFile*>*) convert_java_array_to_dexfiles(env, cookie1, cookie2);
            if (dex_files == NULL) {
                return JNI_FALSE;
            }

            std::string path = "/sdcard/dump.dex";
            for (const DexFile* dex_file : *dex_files) {
                DexUtil* dexUtil = new DexUtil((u1*) dex_file->pHeader);
                ALOGI("[+] Dex dump dex dexutil: %p", dexUtil);
                int class_def_index = dexUtil->findClassIndex(MAIN_APP_CLASSDEF);

                if (class_def_index != -1) {
                    ALOGI("[+] Dex dump dex file size: %d, dump dex name: %s", dex_file->pHeader->fileSize, path.c_str());
                    int fd = open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY);
                    if (fd < 0) {
                        ALOGE("[-] create file /sdcard/test.dex failed, %s", strerror(errno));
                        is_dumped = true;
                    } else {
                        write(fd, dex_file->pHeader, dex_file->pHeader->fileSize);
                        close(fd);
                        is_dumped = true;
                    }
                }

                delete dexUtil;
                dexUtil = NULL;

                if (is_dumped)
                    break;
            }
        }
    }
    return JNI_OK;
}