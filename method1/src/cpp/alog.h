#ifndef ALOG_H_
#define ALOG_H_

#include <android/log.h>

//#ifdef LOG_DEBUG
#define ALOGV(...) ((void)__android_log_print(ANDROID_LOG_VERBOSE, "ALOG", __VA_ARGS__))
#define ALOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "ALOG", __VA_ARGS__))
#define ALOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "ALOG", __VA_ARGS__))
#define ALOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, "ALOG", __VA_ARGS__))
#define ALOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "ALOG", __VA_ARGS__))
//#else
//#define ALOGV(...)
//#define ALOGE(...)
//#define ALOGD(...)
//#define ALOGW(...)
//#define ALOGI(...)
//#endif

#endif /* ALOG_H_ */
