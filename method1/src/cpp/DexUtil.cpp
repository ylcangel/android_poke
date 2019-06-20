#include "DexUtil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <zlib.h>
#include <sys/mman.h>
#include <sys/system_properties.h>


#include "GlobalMarco.h"
#include "Leb128.h"
extern int __system_property_get(const char* prop, char* value);

DexUtil::DexUtil(const u1* addr) {
    mAddr = addr;

    if (isDex(addr)) {
        mHeader = reinterpret_cast<const DexHeader*>(mAddr);
        mOptHeader = NULL;
    } else if (isOptDex(addr)) {
        mOptHeader = (const DexOptHeader*)mAddr;
        mAddr = addr + mOptHeader->dexOffset;
        mHeader = reinterpret_cast<const DexHeader*>(mAddr);
    } else {
        ALOGI("[*] DexUtil::DexUtil(), is not dex or Opt header");
        mHeader = NULL;
    }
}

bool DexUtil::isDex(const u1* addr) {
    return (memcmp(addr, DEX_MAGIC, 4) == 0);
}

bool DexUtil::isOptDex(const u1* addr) {
    return (memcmp(addr, DEX_OPT_MAGIC, 4) == 0);
}

u4 DexUtil::getNativeCountInDexClassData(DexClassData* classDataItem) {
    u4 nativeCount = 0;
    if (classDataItem) {
        for(int i=0; i < classDataItem->header.directMethodsSize ; i++ ) {
            const DexMethod* pDexMethod = &classDataItem->directMethods[i];
            if (pDexMethod->accessFlags & ACC_NATIVE) {
                nativeCount++;
            }
        }

        for(int i=0; i < classDataItem->header.virtualMethodsSize ; i++ ) {
            const DexMethod* pDexMethod = &classDataItem->virtualMethods[i];
            if (pDexMethod->accessFlags & ACC_NATIVE) {
                nativeCount++;
            }
        }
    } else {
        ALOGI("[*] classDataItem is null");
    }

    return nativeCount;
}

/*
 * Round up to the next highest power of 2.
 *
 * Found on http://graphics.stanford.edu/~seander/bithacks.html.
 */
static u4 dexRoundUpPower2(u4 val) {
    val--;
    val |= val >> 1;
    val |= val >> 2;
    val |= val >> 4;
    val |= val >> 8;
    val |= val >> 16;
    val++;

    return val;
}

u4 DexUtil::classDescriptorHash(const char* str) {
    u4 hash = 1;

    while (*str != '\0')
        hash = hash * 31 + *str++;

    return hash;
}

void DexUtil::classLookupAdd(DexClassLookup* pLookup,
                             int stringOff, int classDefOff, int* pNumProbes)
{
    const char* classDescriptor =
            (const char*) (mAddr + stringOff);
    const DexClassDef* pClassDef =
            (const DexClassDef*) (mAddr + classDefOff);
    u4 hash = classDescriptorHash(classDescriptor);
    int mask = pLookup->numEntries-1;
    int idx = hash & mask;

    /*
     * Find the first empty slot.  We oversized the table, so this is
     * guaranteed to finish.
     */
    int probes = 0;
    while (pLookup->table[idx].classDescriptorOffset != 0) {
        idx = (idx + 1) & mask;
        probes++;
    }
    //if (probes > 1)
    //    ALOGW("classLookupAdd: probes=%d", probes);

    pLookup->table[idx].classDescriptorHash = hash;
    pLookup->table[idx].classDescriptorOffset = stringOff;
    pLookup->table[idx].classDefOffset = classDefOff;
    *pNumProbes = probes;
}

bool DexUtil::hasNative() {
    bool isHasNative = false;
    for (int i = 0; i < (int)mHeader->classDefsSize; i++ ) {
        const DexClassDef* pClassDef;
        pClassDef = dexGetClassDef(i);
        const u1* pEncodedData = dexGetClassData(*pClassDef);
        DexClassData* pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);
        if (!pClassData)
            continue;

        int virtualMethodsSize = (int)pClassData->header.virtualMethodsSize;
        int directMethodsSize = (int)pClassData->header.directMethodsSize;

        int vCount = 0;
        for(; vCount < directMethodsSize ;  vCount++ ) {
            const DexMethod* pDexMethod = &pClassData->directMethods[vCount];
            isHasNative = ((pDexMethod->accessFlags & ACC_NATIVE) != 0);
            if(isHasNative) {
                free(pClassData);
                goto Exit;
            }
        }

        for(vCount = 0;  vCount < virtualMethodsSize; vCount++) {
            const DexMethod* pDexMethod = &pClassData->virtualMethods[vCount];
            isHasNative = ((pDexMethod->accessFlags & ACC_NATIVE) != 0);
            if(isHasNative) {
                free(pClassData);
                goto Exit;
            }
        }
        free(pClassData);
    }

    Exit:
    return isHasNative;
}

int DexUtil::findClassIndex(const char* name) {
    for (int i = 0; i < (int)mHeader->classDefsSize; i++ ) {
        const DexClassDef* pClassDef = dexGetClassDef(i);
        const char* className = dexStringByTypeIdx(pClassDef->classIdx);
        // ALOGD("[*] className=%s", className);

        if (strcmp(name, className) == 0)
            return i;
    }

    return -1;
}

u4 DexUtil::getMethodCount(u4 classIdx) {
    const DexClassDef* pClassDef ;
    pClassDef = dexGetClassDef(classIdx);
    const u1* pEncodedData = dexGetClassData(*pClassDef);
    DexClassData* pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);
    if (!pClassData)
        return 0;

    int directMethodsSize = (int)pClassData->header.directMethodsSize;
    int virtualMethodsSize = (int)pClassData->header.virtualMethodsSize;

    free(pClassData);
    return directMethodsSize + virtualMethodsSize;
}

const char* DexUtil::getMethodName(u4 classIdx, u4 methodIndex) {
    const DexClassDef* pClassDef;
    pClassDef = dexGetClassDef(classIdx);
    const u1* pEncodedData = dexGetClassData(*pClassDef);
    DexClassData* pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);
    if (!pClassData)
        return NULL;

    int directMethodsSize = (int)pClassData->header.directMethodsSize;
    int virtualMethodsSize = (int)pClassData->header.virtualMethodsSize;

    const char* name = NULL;
    int currMethodIndex = 0;
    for(int i=0; i < directMethodsSize; i++) {
        const DexMethod* pDexMethod = &pClassData->directMethods[i];
        const DexMethodId* pMethodId = dexGetMethodId(pDexMethod->methodIdx);
        const char* methName = dexStringById(pMethodId->nameIdx);

        if (methodIndex == currMethodIndex) {
            name = methName;
            break;
        }

        currMethodIndex++;
    }

    for(int i=0; i<virtualMethodsSize && !name; i++) {
        const DexMethod* pDexMethod = &pClassData->virtualMethods[i];
        const DexMethodId* pMethodId = dexGetMethodId(pDexMethod->methodIdx);
        const char* methName = dexStringById(pMethodId->nameIdx);

        if (methodIndex == currMethodIndex) {
            name = methName;
            break;
        }

        currMethodIndex++;
    }

    free(pClassData);

    return name;
}

static u4 calcHash(u4 hash, const char* str) {
    while (*str != '\0') {
        hash = hash * 31 + *str++;
    }

    return hash;
}

static const char* type2hash(const char* type) {
    if (!type) {
        return "-N";
    }

    if (strlen(type) == 0) {
        return "-0";
    }

    switch (type[0]) {
        case 'V':
            return "0";
            break;
        case '[':
        case 'L':
            return "3";
            break;
        case 'J':
        case 'D':
            return "2";
            break;
        default:
            return "1";
            break;
    }
}

void DexUtil::calcMethodHash(u4 methodIdx, char* hashStr) {
    const DexMethodId* pMethodId = dexGetMethodId(methodIdx);
    const DexProtoId* protoId    = dexGetProtoId(pMethodId->protoIdx);
    const char* returnType = dexStringByTypeIdx(protoId->returnTypeIdx);
    const DexTypeList* typeList = dexGetProtoParameters(protoId);

    if (typeList) {
        for (int i = 0; i < (int)typeList->size; i++) {
            const DexTypeItem* item = dexGetTypeItem(typeList, i);
            const char* type = dexStringByTypeIdx(item->typeIdx);

            strcat(hashStr, type2hash(type));
        }
    }

    strcat(hashStr, type2hash(returnType));
}

/* Helper for verification which reads and verifies a given number
 * of uleb128 values. */
static bool verifyUlebs(const u1* pData, const u1* pLimit, u4 count) {
    bool okay = true;
    u4 i;

    while (okay && (count-- != 0)) {
        readAndVerifyUnsignedLeb128(&pData, pLimit, &okay);
    }

    return okay;
}

static void dexReadClassDataHeader(const u1** pData,
                                   DexClassDataHeader *pHeader) {
    pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    pHeader->directMethodsSize = readUnsignedLeb128(pData);
    pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
}
/* Read and verify the header of a class_data_item. This updates the
 * given data pointer to point past the end of the read data and
 * returns an "okay" flag (that is, false == failure). */
static bool dexReadAndVerifyClassDataHeader(const u1** pData, const u1* pLimit,
                                            DexClassDataHeader *pHeader) {
    if (! verifyUlebs(*pData, pLimit, 4)) {
        return false;
    }

    dexReadClassDataHeader(pData, pHeader);
    return true;
}

static void dexReadClassDataField(const u1** pData, DexField* pField,
                                  u4* lastIndex) {
    u4 index = *lastIndex + readUnsignedLeb128(pData);

    pField->accessFlags = readUnsignedLeb128(pData);
    pField->fieldIdx = index;
    *lastIndex = index;
}

/* Read and verify an encoded_field. This updates the
 * given data pointer to point past the end of the read data and
 * returns an "okay" flag (that is, false == failure).
 *
 * The lastIndex value should be set to 0 before the first field in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags or indices
 * are valid. */
static bool dexReadAndVerifyClassDataField(const u1** pData, const u1* pLimit,
                                           DexField* pField, u4* lastIndex) {
    if (! verifyUlebs(*pData, pLimit, 2)) {
        return false;
    }

    dexReadClassDataField(pData, pField, lastIndex);
    return true;
}

/* Read an encoded_method without verification. This updates the
 * given data pointer to point past the end of the read data.
 *
 * The lastIndex value should be set to 0 before the first method in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 */
void dexReadClassDataMethod(const u1** pData, DexMethod* pMethod,
                            u4* lastIndex) {
    u4 index = *lastIndex + readUnsignedLeb128(pData);

    pMethod->accessFlags = readUnsignedLeb128(pData);
    pMethod->codeOff = readUnsignedLeb128(pData);
    pMethod->methodIdx = index;
    *lastIndex = index;
}

/* Read and verify an encoded_method. This updates the
 * given data pointer to point past the end of the read data and
 * returns an "okay" flag (that is, false == failure).
 *
 * The lastIndex value should be set to 0 before the first method in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags, indices, or offsets
 * are valid. */
bool dexReadAndVerifyClassDataMethod(const u1** pData, const u1* pLimit,
                                     DexMethod* pMethod, u4* lastIndex) {
    if (! verifyUlebs(*pData, pLimit, 3)) {
        return false;
    }

    dexReadClassDataMethod(pData, pMethod, lastIndex);
    return true;
}

/* Read, verify, and return an entire class_data_item. This updates
 * the given data pointer to point past the end of the read data. This
 * function allocates a single chunk of memory for the result, which
 * must subsequently be free()d. This function returns NULL if there
 * was trouble parsing the data. If this function is passed NULL, it
 * returns an initialized empty DexClassData structure.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags, indices, or offsets
 * are valid. */
DexClassData* DexUtil::dexReadAndVerifyClassData(const u1** pData, const u1* pLimit) {
    DexClassDataHeader header;
    u4 lastIndex;

    if (*pData == NULL) {
        DexClassData* result = (DexClassData*) malloc(sizeof(DexClassData));
        memset(result, 0, sizeof(*result));
        return result;
    }

    if (! dexReadAndVerifyClassDataHeader(pData, pLimit, &header)) {
        return NULL;
    }

    size_t resultSize = sizeof(DexClassData) +
                        (header.staticFieldsSize * sizeof(DexField)) +
                        (header.instanceFieldsSize * sizeof(DexField)) +
                        (header.directMethodsSize * sizeof(DexMethod)) +
                        (header.virtualMethodsSize * sizeof(DexMethod));

    DexClassData* result = (DexClassData*) malloc(resultSize);
    u1* ptr = ((u1*) result) + sizeof(DexClassData);
    bool okay = true;
    u4 i;

    if (result == NULL) {
        return NULL;
    }

    result->header = header;

    if (header.staticFieldsSize != 0) {
        result->staticFields = (DexField*) ptr;
        ptr += header.staticFieldsSize * sizeof(DexField);
    } else {
        result->staticFields = NULL;
    }

    if (header.instanceFieldsSize != 0) {
        result->instanceFields = (DexField*) ptr;
        ptr += header.instanceFieldsSize * sizeof(DexField);
    } else {
        result->instanceFields = NULL;
    }

    if (header.directMethodsSize != 0) {
        result->directMethods = (DexMethod*) ptr;
        ptr += header.directMethodsSize * sizeof(DexMethod);
    } else {
        result->directMethods = NULL;
    }

    if (header.virtualMethodsSize != 0) {
        result->virtualMethods = (DexMethod*) ptr;
    } else {
        result->virtualMethods = NULL;
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.staticFieldsSize); i++) {
        okay = dexReadAndVerifyClassDataField(pData, pLimit,
                                              &result->staticFields[i], &lastIndex);
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.instanceFieldsSize); i++) {
        okay = dexReadAndVerifyClassDataField(pData, pLimit,
                                              &result->instanceFields[i], &lastIndex);
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.directMethodsSize); i++) {
        okay = dexReadAndVerifyClassDataMethod(pData, pLimit,
                                               &result->directMethods[i], &lastIndex);
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.virtualMethodsSize); i++) {
        okay = dexReadAndVerifyClassDataMethod(pData, pLimit,
                                               &result->virtualMethods[i], &lastIndex);
    }

    if (! okay) {
        free(result);
        return NULL;
    }

    return result;
}

DexClassLookup* DexUtil::dexCreateClassLookup() {
    ALOGI("[*] DexUtil::dexCreateClassLookup()");
    if(mHeader == NULL) {
        ALOGI("[-] Error, mHeader is null");
    }
    DexClassLookup* pLookup;
    int allocSize;
    int i, numEntries;
    int numProbes, totalProbes, maxProbes;

    numProbes = totalProbes = maxProbes = 0;

    /*
    * Using a factor of 3 results in far less probing than a factor of 2,
    * but almost doubles the flash storage requirements for the bootstrap
    * DEX files.  The overall impact on class loading performance seems
    * to be minor.  We could probably get some performance improvement by
    * using a secondary hash.
    */
    numEntries = dexRoundUpPower2(mHeader->classDefsSize * 2);
    allocSize = offsetof(DexClassLookup, table)
                + numEntries * sizeof(pLookup->table[0]);

    pLookup = (DexClassLookup*) calloc(1, allocSize);
    if (pLookup == NULL)
        return NULL;
    pLookup->size = allocSize;
    pLookup->numEntries = numEntries;

    for (i = 0; i < (int)mHeader->classDefsSize; i++) {
        const DexClassDef* pClassDef;
        const char* pString;

        pClassDef = dexGetClassDef(i);
        pString = dexStringByTypeIdx(pClassDef->classIdx);

        classLookupAdd(pLookup,
                       (u1*)pString - mAddr,
                       (u1*)pClassDef - mAddr, &numProbes);

        if (numProbes > maxProbes)
            maxProbes = numProbes;
        totalProbes += numProbes;
    }

    ALOGI("[*] Class lookup: classes=%d slots=%d (%d%% occ) alloc=%d"
             " total=%d max=%d",
             mHeader->classDefsSize, numEntries,
             (100 * mHeader->classDefsSize) / numEntries,
             allocSize, totalProbes, maxProbes);

    return pLookup;
}

typedef DexClassLookup* (*DVM_DexCreateClassLookup)(void* dexfile);
static DexClassLookup* dvmDexCreateClassLookup(void* dexfile) {
    void* dl;
    DVM_DexCreateClassLookup func;

    dl = dlopen("libdvm.so", RTLD_NOW);
    if (dl) {
        func = (DVM_DexCreateClassLookup)dlsym(dl, "dexCreateClassLookup");
        if (func) {
            ALOGI("[*] dvmDexCreateClassLookup");
            return (*func)(dexfile);
        }
    }

    ALOGI("[*] dvmDexCreateClassLookup");
    return NULL;
}

void* DexUtil::dexFileSetupBasicPointers(u1* data, bool is2x) {


    DexHeader *pHeader = (DexHeader*) data;
    //ALOGI("dexFileSetupBasicPointers %c %c %c %c", data[0], data[1], data[2], data[3]);
    DexUtil* paddingDex = new DexUtil(data);
    ALOGI("[*] dexFileSetupBasicPointers paddingDex: %p", paddingDex);
    char brand[128];
    memset(brand, 0, PROP_VALUE_MAX);
    bool isAmazon = false;
    if(__system_property_get("ro.product.brand", brand) > 0 && strstr(brand, "Amazon") != NULL) {
        isAmazon = true;
        ALOGI("[*] This is Amazon");
    }
    void* ret = NULL;
    if (is2x) {
        DexFile2X* pDexFile = (DexFile2X*) malloc(sizeof(DexFile2X));
        memset(pDexFile, 0, sizeof(DexFile2X));
        pDexFile->baseAddr = data;

        pDexFile->pHeader = pHeader;
        pDexFile->pStringIds = (const DexStringId*) (data + pHeader->stringIdsOff);
        pDexFile->pTypeIds = (const DexTypeId*) (data + pHeader->typeIdsOff);
        pDexFile->pFieldIds = (const DexFieldId*) (data + pHeader->fieldIdsOff);
        pDexFile->pMethodIds = (const DexMethodId*) (data + pHeader->methodIdsOff);
        pDexFile->pProtoIds = (const DexProtoId*) (data + pHeader->protoIdsOff);
        pDexFile->pClassDefs = (const DexClassDef*) (data + pHeader->classDefsOff);
        pDexFile->pLinkData = (const DexLink*) (data + pHeader->linkOff);

        pDexFile->pClassLookup = paddingDex->dexCreateClassLookup();
        pDexFile->pRegisterMapPool = NULL; // paddingDex->dexCreateRegisterMapPool();

        ALOGI("[*] 2x dexFileSetupBasicPointers pClassLookup: %p", pDexFile->pClassLookup);
        ret = pDexFile;
    } else if (isAmazon) {
        DexFile_Amazon* pDexFile = (DexFile_Amazon*) malloc(sizeof(DexFile_Amazon));
        memset(pDexFile, 0, sizeof(DexFile_Amazon));
        pDexFile->baseAddr = data;

        pDexFile->pHeader = pHeader;
        pDexFile->pStringIds = (const DexStringId*) (data + pHeader->stringIdsOff);
        pDexFile->pStringIds2 = (const DexStringId*) (data + pHeader->stringIdsOff);
        pDexFile->pTypeIds = (const DexTypeId*) (data + pHeader->typeIdsOff);
        pDexFile->pFieldIds = (const DexFieldId*) (data + pHeader->fieldIdsOff);
        pDexFile->pFieldIds2 = (const DexFieldId*) (data + pHeader->fieldIdsOff);
        pDexFile->pMethodIds = (const DexMethodId*) (data + pHeader->methodIdsOff);
        pDexFile->pMethodIds2 = (const DexMethodId*) (data + pHeader->methodIdsOff);
        pDexFile->pProtoIds = (const DexProtoId*) (data + pHeader->protoIdsOff);
        pDexFile->pClassDefs = (const DexClassDef*) (data + pHeader->classDefsOff);
        pDexFile->pLinkData = (const DexLink*) (data + pHeader->linkOff);

        pDexFile->fieldSize = pHeader->fieldIdsSize;
        pDexFile->methodsSize = pHeader->methodIdsSize;
        pDexFile->stringSize = pHeader->stringIdsSize;
        pDexFile->pClassLookup = paddingDex->dexCreateClassLookup();
        pDexFile->pRegisterMapPool = NULL; // paddingDex->dexCreateRegisterMapPool();

        ALOGI("[*] dexFileSetupBasicPointers pClassLookup: %p", pDexFile->pClassLookup);
        ret = pDexFile;
    } else {
        DexFile* pDexFile = (DexFile*) malloc(sizeof(DexFile));
        memset(pDexFile, 0, sizeof(DexFile));
        pDexFile->baseAddr = data;

        pDexFile->pHeader = pHeader;
        pDexFile->pStringIds = (const DexStringId*) (data + pHeader->stringIdsOff);
        pDexFile->pTypeIds = (const DexTypeId*) (data + pHeader->typeIdsOff);
        pDexFile->pFieldIds = (const DexFieldId*) (data + pHeader->fieldIdsOff);
        pDexFile->pMethodIds = (const DexMethodId*) (data + pHeader->methodIdsOff);
        pDexFile->pProtoIds = (const DexProtoId*) (data + pHeader->protoIdsOff);
        pDexFile->pClassDefs = (const DexClassDef*) (data + pHeader->classDefsOff);
        pDexFile->pLinkData = (const DexLink*) (data + pHeader->linkOff);

        pDexFile->pClassLookup = paddingDex->dexCreateClassLookup();
        pDexFile->pRegisterMapPool = NULL; // paddingDex->dexCreateRegisterMapPool();

        ALOGI("[*] dexFileSetupBasicPointers pClassLookup: %p", pDexFile->pClassLookup);
        ret = pDexFile;
    }

    delete paddingDex;

    return ret;
}

// end of file
