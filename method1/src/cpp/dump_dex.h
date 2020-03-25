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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <cstdlib>

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

#define SYS_DEX_PREFIX "Landroid/"

/**
 * dump dex
 * @param env JNIEnv
 * @param api_level  android api level
 * @param generation 1 completely 2 extracted
 * @param jpath save path of dex
 * @return 0 success , < 0 failed
 */
int dump_dex(JNIEnv *env, jint api_level, jint generation, jstring jpath);


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
    char buf[10];
    memset(buf, 0, 10);
    snprintf(buf, 10, "%d%s%s", minfo.maj_version, ".", minfo.min_version.c_str());
    std::string version(buf);
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

typedef struct {
    bool is_class_def_out;
    bool is_class_data_item_out;
    bool is_code_item_out;
} IS_OUT;


#define CLS(a) {            \
                if(!a)  {   \
                delete a;   \
                        }    \
                a = NULL;    \
            }   \

#define C_CLS(a) {            \
                if(!a)  {     \
                    free(a);   \
                        }      \
                a = NULL;      \
            }   \

/**
 * different os version, different implement.
 * @param env JNIEnv
 * @param cookie1 DexFile->mCooke update 5
 * @param cookie2 DexFile->mCooke under 5
 * @return DexFile* list
 */
static void*  convert_java_array_to_dexfiles(JNIEnv* env, jlong cookie1, jint cookie2) ;

static bool is_sys_dex(DexFile* dex);

static int find_class(JNIEnv* env, const char* classdec);
static int invoke_method(JNIEnv* env, const char* mnane, const char* proto_type, jobjectArray args);

/**
 * dump 完整dex
 * @param dex
 * @param save_path
 * @return 0 成功
 */
static int dump_complete_dex(DexFile* dex, char* save_path);

/**
 * dump 完整抽取的，不是执行时才修复的
 * @param env
 * @param dex
 * @param save_path
 * @return
 */
static int dump_complete_extract_dex(JNIEnv* env, DexFile* dex, char* save_path);

static bool is_outof_dex(u4 begin, u4 len, u4 wh) {
    u4 end = begin + len;
    if (begin < wh  <  end) {
        return false;
    }
    return true;
}

u4 align_to(u4 offset, u4 unitSize) {
    u4	alignmentMask	= unitSize - 1;
    offset = (offset + alignmentMask) & ~alignmentMask;
    return offset;
}

u4 alignTo(u4 off) {
    int mask = off - 1;
    return (off + mask) & ~mask;
}

typedef struct {
    u4 off; // 修复后的偏移|dex file|class_data|code_item|，如果codeoff是0对应dexcode为NULL
    // ClassData为sizeof(DexClassData) +
    //    (header.staticFieldsSize * sizeof(DexField)) +
    //    (header.instanceFieldsSize * sizeof(DexField)) +
    //    (header.directMethodsSize * sizeof(DexMethod)) +
    //    (header.virtualMethodsSize * sizeof(DexMethod));
    // DexCode为sizeof(DexCode + code_inst_size,忽略padding，源码中并没有显示的操作padding
    u4 size; // buf大小
    u1* buf; // 指向内存中真正的classdata或者dexcode
} _DataItem;

typedef struct Node {
    u4 max_count; // method 或者 class最大数
    u4 count; // 当前classdata或者dexcode个数
    u4 all_size; // 仅用于dexcode
    _DataItem** next;
} List;


static List* create_list(u4 list_size) {
    List* list = (List*) malloc(sizeof(List));
    assert(!list);
    list->max_count = list_size;
    list->count = 0;
    list->all_size = 0;
    list->next = (_DataItem**) malloc(list_size * sizeof(_DataItem));
    assert(!list->next);
    memset(list->next, 0, (list_size * sizeof(_DataItem)));
    return list;
}

static void list_add(List* list, u4 buf_size, u1* buf, u4 align_size, u4 off) {
    _DataItem* _dataItem = (_DataItem*)malloc(sizeof(_DataItem));
    assert(!_dataItem);

    _dataItem->off = off;
    _dataItem->size = buf_size;
    _dataItem->buf = buf;

    list->all_size += align_size;
    list->next[list->count] = _dataItem;
    list->count += 1;
}

static void list_free(List* list) {
    for(int i = 0; i < list->max_count; i++) {
        _DataItem* _dataItem = list->next[i];
        if(!_dataItem)
            C_CLS(_dataItem);
    }

    free(list->next);

    C_CLS(list);
}

static List* make_class_data(DexUtil* dexUtil, IS_OUT is_out);
static void repair_class_data_off(DexClassDef* classDef, u4 classCount, List* class_data_list);
static List* make_code_item(DexUtil* dexUtil, IS_OUT is_out, u4 begin);
static u1* repair_codeoff(DexUtil* dexUtil, List* class_data_list, List* codelist);
static void write_class_data(u1* pData, const DexClassData* dexClassData);
static u1* make_code_item_buf(List* codeList, u4 begin);

#ifdef __cplusplus
}
#endif
#endif //HELLO_DUMP_DEX_H
