#include <vector>
#include <unistd.h>
#include <time.h>

#include "dump_dex.h"

#include "ScopedLocalRef.h"
#include "ScopedUtfChars.h"

#include "descriptors_names.h"
#include "Leb128.h"

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


static int find_class(JNIEnv* env, const char* classdec) {

    if(!IsValidJniClassName(classdec)) {
        ALOGE("[*] Find class name : %s was wrong", classdec);
        return JNI_ERR;
    }
    ScopedLocalRef<jclass> javaClass(env, env->FindClass(classdec));
    if (!javaClass.get()) {
        env->ExceptionClear();
    }
    ALOGI("[*] Find javaClass: %p", javaClass.get());

    return JNI_OK;
}

static int invoke_method(JNIEnv* env, const char* mnane, const char* proto_type, jobjectArray args) {


    return JNI_OK;
}


int dump_dex(JNIEnv *env, jint api_level, jint generation, jstring jpath) {

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


    static int dex_index = 0;

    for (int i = 0; i < dexElementsSize; i++) {
        ScopedLocalRef<jobject> element(env, env->GetObjectArrayElement(dexElements.get(), i));
        ALOGI("[*] element: %p", element.get());

        ScopedLocalRef<jclass> elementClass(env, env->GetObjectClass(element.get()));
        ALOGI("[*] elementClass: %p", elementClass.get());

        jfieldID dexFileField = env->GetFieldID(elementClass.get(), "dexFile", "Ldalvik/system/DexFile;");
        ALOGI("[*] dexFileField: %p", dexFileField);

        ScopedLocalRef<jobject> dexFile(env, env->GetObjectField(element.get(), dexFileField));
        ALOGI("[*] dexFile: %p", dexFile.get());

        if (dexFile.get() != NULL) {
            ScopedLocalRef<jclass> dexFileClass(env, env->GetObjectClass(dexFile.get()));
            ALOGI("[*] dexFileClass: %p", dexFileClass.get());

            jfieldID fileNameField = env->GetFieldID(dexFileClass.get(), "mFileName", "Ljava/lang/String;");
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

            const char* save_dir = NULL;
            if (jpath == NULL) {
                save_dir = "/sdcard/";
            } else {
                ScopedUtfChars path_str(env, jpath);
                save_dir = path_str.c_str();
            }

            ALOGI("[*] save dir of dex: %s", save_dir);

            static char save_path[256];
            for(int j = 0 ; j < dex_files->size(); j++) {
                memset(save_path, 0, 256);
                snprintf(save_path, 255, "%s%d%s", save_dir, dex_index++, ".dex");
                ALOGI("[*] save path of dex: %s", save_path);
                DexFile* dexFile = const_cast<DexFile*> (dex_files->at(j));

                switch(generation) {
                    case 1: // 完整
                        if (dump_complete_dex(dexFile, save_path) == JNI_ERR) {
                            ALOGI("[-] Dump dex of path: %s failed!", save_path);
                        }
                        break;
                    case 21: // 抽取，第一次加载后偏移被修复
                        if(dump_complete_extract_dex(env, dexFile, save_path) == JNI_ERR) {
                            ALOGI("[-] Dump dex of path: %s failed!", save_path);
                        }
                        break;
                    case 22:
                        break;
                    case 24: // 抽取，执行时修复
                        break;

                    default:
                        ALOGI("[*] Dump dex was not support!");
                        break;
                }
            }
        }
    }

    return JNI_OK;
}

static bool is_sys_dex(DexFile* dex) {
    DexUtil* dexUtil = new DexUtil((u1*) dex);
    bool is_found = false;

    for(int i = 0 ; i < dexUtil->classCount(); i++) {
        const DexClassDef* classDef =  dexUtil->dexGetClassDef(i);
        const char* declaring_class = dexUtil->dexStringByTypeIdx(classDef->classIdx);
        if(strstr(declaring_class, SYS_DEX_PREFIX) != NULL) {
            is_found = true;
            break;
        }
    }

    CLS(dexUtil) ;
    return is_found;
}

static int dump_complete_dex(DexFile* dexFile, char* save_path) {

    if(is_sys_dex(dexFile)) {
        return JNI_OK;
    }

    int fd = open(save_path, O_CREAT | O_EXCL | O_WRONLY);
    if (fd < 0) {
        ALOGE("[-] create file %s failed, %s", save_path, strerror(errno));
        return JNI_ERR;
    }

    DexUtil* dexUtil = new DexUtil((u1*)dexFile);

    write(fd, dexUtil->base(), dexUtil->fileSize());
    close(fd);

    CLS(dexUtil);
    return JNI_OK;
}

static int dump_complete_extract_dex(JNIEnv* env, DexFile* dexFile, char* save_path) {

    if(is_sys_dex(dexFile)) {
        return JNI_OK;
    }

    DexUtil* dexUtil = new DexUtil((u1*) dexFile);

    u1* dexbuf = (u1*) malloc(dexUtil->fileSize());
    if(!dexbuf) {
        ALOGE("[-] malloc dexbuf failed %s!",  strerror(errno));
        return JNI_ERR;
    }

    memset(dexbuf, 0, dexUtil->fileSize());
    memcpy(dexbuf, dexUtil->base(), dexUtil->fileSize());

    srand((unsigned)time(NULL));
    int random_class_def_n = (rand() % dexUtil->classCount() + 1);
    const DexClassDef* classDefr =  dexUtil->dexGetClassDef(random_class_def_n);
    const char* declaring_class = dexUtil->dexStringByTypeIdx(classDefr->classIdx);
    ALOGI("[*] Find class %s!",  declaring_class);
    // 主动调用一次，虽然可能没有意义, 一般这个时候加固dex主activity已经启动
    find_class(env, declaring_class);

    IS_OUT is_out;

    // 之前用随机方式选择method->codeitem，但是只随机一次可能导致codeitem为空
    // 这样会让is_code_item_out = true ，而产生bug
    for(int i = 0 ; i < dexUtil->classCount(); i++) {
        const DexClassDef* classDef =  dexUtil->dexGetClassDef(i);
        // 在这里我们假设classdef没有被抽取，也确实很多加固并没有对其抽取
        // 我们假设抽取部分仅为class_data、code_item
        const u1* pEncodedData = dexUtil->dexGetClassData(*classDef);
        DexClassData* pClassData = dexUtil->dexReadAndVerifyClassData(&pEncodedData, NULL);

        assert(pClassData != NULL);

        ALOGV("[*] Class data item[%d] = %x\n", i, (u4)pEncodedData);

        if(i == 0 && is_outof_dex((u4)dexUtil->base(), dexUtil->fileSize(), (u4)pEncodedData)) {
            is_out.is_class_data_item_out = true;
        }

        bool is_set_out = false;
        DexMethod* pDexMethod;
        int methodsSize = (int)pClassData->header.directMethodsSize;
        for(int j = 0; j < methodsSize; j++) {
            pDexMethod = &pClassData->directMethods[j];
            if(!(dexUtil->dexGetCode(pDexMethod)) && is_outof_dex((u4)dexUtil->base(), dexUtil->fileSize(), (u4)(dexUtil->base() + pDexMethod->codeOff)) ) {
                is_out.is_code_item_out = true;
                is_set_out = true;
                break;
            }
        }

        if(!is_set_out) {
            methodsSize = (int)pClassData->header.virtualMethodsSize;
            for(int j = 0; j < methodsSize; j++) {
                pDexMethod = &pClassData->virtualMethods[j];
                if(!(dexUtil->dexGetCode(pDexMethod)) && is_outof_dex((u4)dexUtil->base(), dexUtil->fileSize(), (u4)(dexUtil->base() + pDexMethod->codeOff)) ) {
                    is_out.is_code_item_out = true;
                    is_set_out = true;
                    break;
                }
            }
        } else {
            break;
        }

        if(!is_set_out)
            continue;
        else
            break;

        C_CLS(pClassData);
    }

    // append data
    // class_data_item
    List* classdataList = make_class_data(dexUtil, is_out);
    assert(!classdataList);
    u4 begin = (0 + dexUtil->fileSize() + classdataList->all_size);

    // code_item
    List* codelist = make_code_item(dexUtil, is_out, begin);
    assert(!codelist);

    // repair classoff
    DexHeader* header = (DexHeader*) dexbuf;
    DexClassDef* classDef = (DexClassDef* )((u1*) dexbuf + header->classDefsOff);
    repair_class_data_off(classDef, header->classDefsSize, classdataList);
    // reapair codeoff
    u1* class_data_buf = repair_codeoff(dexUtil, classdataList, codelist);
    assert(!class_data_buf);

    int fd = open(save_path, O_CREAT | O_EXCL | O_WRONLY);
    if (fd < 0) {
        ALOGE("[-] create file %s failed, %s", save_path, strerror(errno));
        return JNI_ERR;
    }

    // reapair header filesize
    header->fileSize += (classdataList->all_size + codelist->all_size);
    // write origin dexfile
    write(fd, dexbuf, dexUtil->fileSize());
    fsync(fd);
    // append class_data
    write(fd, class_data_buf, classdataList->all_size);
    fsync(fd);
    //append code_item

    u1* code_item_buf = make_code_item_buf(codelist, (dexUtil->fileSize() + classdataList->all_size));
    write(fd, code_item_buf, codelist->all_size);
    fsync(fd);

    close(fd);

    list_free(classdataList);
    list_free(codelist);

    C_CLS(class_data_buf);
    C_CLS(code_item_buf);
    CLS(dexUtil);
    return JNI_OK;
}

static List* make_class_data(DexUtil* dexUtil, IS_OUT is_out) {
    u4 classCount = dexUtil->classCount();
    u4 begin = (0 + dexUtil->fileSize()); // 文件偏移 base = 0

    List* classdataList = create_list(classCount);
    u4 off = begin;

    if(is_out.is_class_data_item_out) {
        const DexClassDef* classDef = dexUtil->dexGetClassDef(0);

        for(int i = 0; i < dexUtil->classCount(); i++) {
            const u1* pEncodedData = dexUtil->dexGetClassData(*classDef);
            DexClassData* pClassData = dexUtil->dexReadAndVerifyClassData(&pEncodedData, NULL);
            DexClassDataHeader header = pClassData->header;
            size_t classDataSize = sizeof(DexClassDataHeader) +
                                (header.staticFieldsSize * sizeof(DexField)) +
                                (header.instanceFieldsSize * sizeof(DexField)) +
                                (header.directMethodsSize * sizeof(DexMethod)) +
                                (header.virtualMethodsSize * sizeof(DexMethod));

            const DexClassDef* classDef = dexUtil->dexGetClassDef(i);
            // todo; class_data应该不用对齐
            // 我观察class_data的偏移有奇数地址
            // 如果需要对齐，你需要处理align_size
            // 我觉得不用对齐，所以这里直接传入classDataSize
            // 这里buf指向pEncodedData，其实它存在意义不大，后续会重新写入
            list_add(classdataList, classDataSize, (u1*)pEncodedData, classDataSize, off);
            off += classDataSize;

            CLS(pClassData);
        }
    }

    return classdataList;
}

// 直接追加到文件尾
// |dex file|class_data|
// classdef->classDataOff = base + dexfile_len + i* class_data
// 即使codeoff为空也创建一个Item，但是其偏移为0
static List* make_code_item(DexUtil* dexUtil, IS_OUT is_out, u4 begin) {
    u4 methodSize = dexUtil->methodCount(); // 足够容纳code了，因为还有code_off为0的方法
    List* codeList = create_list(methodSize);
    u4 off = begin;

    if(is_out.is_code_item_out) {
        for( int i = 0 ; i < dexUtil->classCount(); i++) {
            const DexClassDef *classDef = dexUtil->dexGetClassDef(i);
            const u1* pEncodedData = dexUtil->dexGetClassData(*classDef);
            DexClassData* pClassData = dexUtil->dexReadAndVerifyClassData(&pEncodedData, NULL);

            const DexMethod* pDexMethod;
            u4 code_size = 0;

            int methodsSize = (int)pClassData->header.directMethodsSize;
            if(methodsSize > 0) {
                for(int j = 0; j < methodsSize; j++) {
                    pDexMethod = &pClassData->directMethods[j];
                    u4 old_off = off;
                    // 按四字节对齐
                    off = alignTo(off);
                    const DexCode* dexCode = dexUtil->dexGetCode(pDexMethod);
                    code_size = dexUtil->getDexCodeSize(dexCode);
                    u4 align_size = code_size;
                    align_size += (off - old_off);
                    // 如果code_off 为0， 则传入dexCode = NULL
                    // 后面需要依据这个判断
                    list_add(codeList, code_size, (u1*) dexCode, align_size, off);
                    off += align_size;
                }
            }

            methodsSize = (int)pClassData->header.virtualMethodsSize;
            if(methodsSize > 0) {
                for(int j = 0; j < methodsSize; j++) {
                    pDexMethod = &pClassData->virtualMethods[j];
                    u4 old_off = off;
                    // 按四字节对齐
                    off = alignTo(off);
                    const DexCode* dexCode = dexUtil->dexGetCode(pDexMethod);
                    code_size = dexUtil->getDexCodeSize(dexCode);
                    u4 align_size = code_size;
                    align_size += (off - old_off);
                    list_add(codeList, code_size, (u1*) dexCode, align_size, off);
                    off += align_size;
                }
            }

            C_CLS(pClassData);
        }
    }
    return codeList;
}


static void repair_class_data_off(DexClassDef* classDef, u4 classCount, List* class_data_list) {
    for(int i = 0; i < classCount; i++) {
        DexClassDef* _classDef = &classDef[i];
        _classDef->classDataOff = class_data_list->next[i]->off;
    }
}




// 直接追加到class_data尾
// |dex file|class_data|code_item|
// dexmethod->codeOff = writeUnsignedLeb128(pData);
// classdef->classDataOff = base + dexfile_len + i* class_data
static u1* repair_codeoff(DexUtil* dexUtil, List* class_data_list, List* codelist) {
    u4 codeIndex = 0;

    u1* class_data_buf = (u1*) malloc(class_data_list->all_size);
    assert(!class_data_buf);

    memset(class_data_buf, 0, class_data_list->all_size);

    u1* pData = class_data_buf;

    for( int i = 0 ; i < dexUtil->classCount(); i++) {
        const DexClassDef *classDef = dexUtil->dexGetClassDef(i);
        const u1* pEncodedData = dexUtil->dexGetClassData(*classDef);
        DexClassData* pClassData = dexUtil->dexReadAndVerifyClassData(&pEncodedData, NULL);

        DexMethod* pDexMethod;
        u4 code_size = 0;
        DexClassData* dexClassDatar = (DexClassData*) class_data_list->next[i]->buf;

        int methodsSize = (int)pClassData->header.directMethodsSize;
        if(methodsSize > 0) {
            for(int j = 0; j < methodsSize; j++) {
                pDexMethod = &pClassData->directMethods[j];
                const DexCode* dexCode = dexUtil->dexGetCode(pDexMethod);


                if(!dexCode) {
                    pDexMethod->codeOff = codelist->next[codeIndex++]->off;
                } else { // codeOff = 0, 不需要修正，但是codeIndex需要加1
                    codeIndex++;
                }
            }
        }

        methodsSize = (int)pClassData->header.virtualMethodsSize;
        if(methodsSize > 0) {
            for(int j = 0; j < methodsSize; j++) {
                pDexMethod = &pClassData->virtualMethods[j];
                const DexCode* dexCode = dexUtil->dexGetCode(pDexMethod);
                if(!dexCode) {
                    pDexMethod->codeOff = codelist->next[codeIndex++]->off;
                } else { // codeOff = 0, 不需要修正，但是codeIndex需要加1
                    codeIndex++;
                }
            }
        }

        // 写入class_data_buf
        write_class_data(pData, pClassData);

        C_CLS(pClassData);
    }
}

static void write_class_data(u1* pData, const DexClassData* dexClassData) {
    const DexClassDataHeader* pHeader = &dexClassData->header;
    pData = writeUnsignedLeb128(pData, pHeader->staticFieldsSize);
    pData = writeUnsignedLeb128(pData, pHeader->instanceFieldsSize);
    pData = writeUnsignedLeb128(pData, pHeader->directMethodsSize);
    pData = writeUnsignedLeb128(pData, pHeader->virtualMethodsSize);

    for(int i = 0; i < pHeader->staticFieldsSize; i++) {
        DexField* pItem = &dexClassData->staticFields[i];
        pData = writeUnsignedLeb128(pData, pItem->fieldIdx);
        pData = writeUnsignedLeb128(pData, pItem->accessFlags);
    }

    for(int i = 0; i < pHeader->instanceFieldsSize; i++) {
        DexField* pItem = &dexClassData->instanceFields[i];
        pData = writeUnsignedLeb128(pData, pItem->fieldIdx);
        pData = writeUnsignedLeb128(pData, pItem->accessFlags);
    }

    for (int i = 0; i < pHeader->directMethodsSize; i++) {
        DexMethod* pItem = &dexClassData->directMethods[i];
        pData = writeUnsignedLeb128(pData, pItem->methodIdx);
        pData = writeUnsignedLeb128(pData, pItem->accessFlags);
        pData = writeUnsignedLeb128(pData, pItem->codeOff);
    }

    for (int i = 0; i < pHeader->virtualMethodsSize; i++) {
        DexMethod* pItem = &dexClassData->virtualMethods[i];
        pData = writeUnsignedLeb128(pData, pItem->methodIdx);
        pData = writeUnsignedLeb128(pData, pItem->accessFlags);
        pData = writeUnsignedLeb128(pData, pItem->codeOff);
    }
}

static u1* make_code_item_buf(List* codeList, u4 begin) {
    u1* code_item_buf = (u1*) malloc(codeList->all_size);
    assert(!code_item_buf);
    memset(code_item_buf, 0, codeList->all_size);

    for(int ci = 0; ci < codeList->count; ci++) {
        if(!codeList->next[ci]->buf) {
            memcpy((code_item_buf + (codeList->next[ci]->off - begin)), codeList->next[ci]->buf, codeList->next[ci]->size);
        }
    }

    return code_item_buf;
}
