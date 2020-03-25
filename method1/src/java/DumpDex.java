package com.example.dump_dex;

import android.app.Activity;
import android.util.ArrayMap;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * @author sp00f
 * @version 0.1
 * <pre>
 *  <b>
 * 本人才疏学浅，仅仅了解这么多，如有纰漏，还请见谅
 * 1、完整dex比较容易脱，反射cookie即对应的native层dexfile指针
 * 2、抽取的（这个抽取方式有多种）
 * 2.1、完整抽取class_data_item, method_data,code_item执行时不会填，修复偏移
 * 2.2、有些抽取连classdef也抽取了，有的回填有的修复偏移
 * 2.3、有些仅抽取code_item，执行时回填或者修复偏移
 * 2.4、很多执行code时仅仅当执行那一刻才修复，执行完恢复原状态
 * 有可能存在抹掉头部的
 *
 * 3、dex2c、Java2c 最后大多基于反射调用；
 * 4、dexvmp脱壳后vmp部分仍需要单独分析
 *
 *
 * 关于二代脱壳网上有很多很好的开源项目，如DexHunter、FUPK3等
 * 我造轮子的目的仅仅是自己YY，这个时候在写这些其实可以忽略它的意义了， 哈哈
 * 当然我也会借鉴上面提到的开源项目的一些思想，
 * 俗话说站在巨人的肩膀上;
 * 对抽取加固，我不确认任何一种情况都可以完全脱掉，我也是随意发挥一下，有好的想法，
 * 你可以基于此二次开发。
 *
 * 代码和思想由于个人水平限制可能会存在问题，不过也不用刻意喷我
 * 小菜鸟只是玩乐，大佬不用太动肝火，源代码我也是曾经研究过很多次的
 *
 * 对于第二代脱壳脱壳思想：
 * 2.1-2.3 为简单起见把这些结构放到dex尾部，修复偏移，修复头部偏移即可，中间部分忽略
 * 2.4 可以遍历所有class - method - invoke method 实现dump
 *
 *
 * 另一种方法：
 * 曾经出现了zjdroid脱壳神器， 它的思想是把smalli编译成dex，我们可以借助于android源码DexDump.cpp
 * 位于<link> ANDROID_SOURCE/art/dexdump/</link>目录下，仿照其去dump每一个class在编译
 *
 * 源码中很多通用工具，dx 可以把java转化为dex
 * 还有很多其他工具
 * 安卓源码提供了很多丰富的工具，包括任意方式解析dex，包括细粒化到解析code，这并不需要调用invoke
 *
 * java-class - vm class
 * 反射 class 等同于 jni-findclass
 * java-class 主动调用方法 | jni-jclass-CallXXXMethod 最终都走向 vm runtime - method
 * vm试图
 * ClassObject|Class - Method|ArtMethod（vm试图）中直接或者间接带有文件试图的结构（如Code）
 *
 * 那实际上可以通过反射找到对应vm的class结构 ，通过findMethodId找到对应的VM method结构
 * 来还原，这样是否可以不用invoke，需要验证？？
 *
 * 如果调用则可以如下：
 * 单解释模式（5.02）：
 * java invoke(method）
 * |/
 * art::interpreter::EnterInterpreterFromInvoke(Thread* self, ArtMethod* method, Object* receiver, uint32_t* args, JValue* result)
 * JValue Execute(Thread* self, MethodHelper& mh, const DexFile::CodeItem* code_item, ShadowFrame& shadow_frame, JValue result_register)
 * 里面包含methodData 和 codeitem 信息
 *
 *
 * 三代思想：
 * （先研究研究 dex2c 、java2c后code变成什么样子）
 * 通过hook native层的 findclass invoke method 是否能还原，我没研究过不确定想法是否可行
 * 因为即使知道反射那些类，它的code可能已经变成native代码，想脱壳仍十分困难
 *
 * 四代：
 * 只能分析vmp，或许别无它法；但为求稳定运行，应该不会把全部的dex指令都vm化，应该只是少部分指令；
 * 但是vm哪些指令是可变的
 *
 * 还是我是一个不负责任的人，我没有测试过代码，因为本身就是写着玩， 如果想让这个项目跑起来，估计需要你
 * 在次基础上进行开发和调试 哈哈
 *
 * 其他的后续在补充吧，太累，另外再次强调代码可能存在问题哦
 *
 * </b>
 * </pre>
 */

public class DumpDex {


    public static String getDexClass() {
        return dexClass;
    }

    public static void setDexClass(String _dexClass) {
        dexClass = _dexClass;
    }

    private static String dexClass;


    static {
        System.loadLibrary("native-lib");
    }

    /**
     *
     * @param apilevel api level
     * @param g 加固第几代; 1, 21,24
     * @param path 保存dex路径
     * @return 0 成功 非0失败
     */
    public native int  dumpDex(int apilevel, int g, String path);


    public static ClassLoader getClassLoader() {
        Object objclass = null;
        try {
            Class threadClazz = Class.forName("android.app.ActivityThread");
            Method meth = threadClazz.getMethod("currentActivityThread");
            Object currentActivityThread = meth.invoke(null);
            Field f = threadClazz.getDeclaredField("mActivities");
            f.setAccessible(true);
            ArrayMap obj = (ArrayMap) f.get(currentActivityThread);
            for (Object key : obj.keySet()) {
                Object activityRecord = obj.get(key);
                Field actField = activityRecord.getClass().getDeclaredField("activity");
                actField.setAccessible(true);
                Object activity = actField.get(activityRecord);
                Activity _activity = (Activity) activity;

                objclass = _activity;

                String activeName = _activity.getClass().toString();// class
                setDexClass(activeName);

            }

            Class clazz = Class.forName("java.lang.Class");
            assert (clazz != null);
            Method m = clazz.getDeclaredMethod("getClassLoader", ClassLoader.class);
            assert (m != null);
            if(dexClass == null)
                return DumpDex.class.getClassLoader();

            return (ClassLoader) m.invoke(objclass, new Object[]{});
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static  Class<?> findClass(String name) {
        ClassLoader loader = getClassLoader();
        assert (loader != null);

        try {
            return loader.loadClass(name);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Method[] findMethods( String className) {
        Class clazz = findClass(className);
        if(clazz != null)
            return findMethods(clazz);

        return null;
    }

    public static  Method[] findMethods(Class<?> clazz) {
        try {
            return clazz.getDeclaredMethods();
        } catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public static Method getMethod(Class<?> clazz, String name, Class[] paramType) {
        try {
            return  clazz.getDeclaredMethod(name, paramType);
        } catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public static Object invokeMethod(Class clazz, String methodName, Object classobj ,Class[] paramType, Object[] params){
        Object ret = null;
        try {
            Method method = getMethod(clazz, methodName, paramType);
            if(method != null)
                ret = method.invoke(classobj, params);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

}
