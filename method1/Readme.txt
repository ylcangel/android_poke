author：sp00f
#完整dex脱壳
核心思路：反射 + mCookie（其实脱壳的点太多了，这是其中一个）
步骤：
1、找到加固apk的任一class，一般选择主Application或Activity
2、通过该类找到对应的Classloader
3、通过该Classloader找到BaseDexClassLoader
4、通过BaseDexClassLoader找到其字段DexPathList
5、通过DexPathList找到其变量Element数组dexElements
6、迭代该数组，该数组内部包含DexFile结构
7、通过DexFile获取其变量mCookie和mFileName（这个名字没什么鸟用）

至此我们已经获取了mCookie

对该mCookie的解释（有些现在记不太清楚了）：
#1、4.4以下好像，mCookie对应的是一个int值，该值是指向native层内存中的dexfile的指针
#2、5.0是一个long值，该值指向native层std::vector<const DexFile*>* 指针，注意这里有多个dex，你需要找到你要的
#3、我还测试了8.0手机，该值也是一个long型的值，指向底层vector，但是vector下标0是oat文件，从1开始是dex文件
// 至于你手机是那个版本，如果没有落入我上面描述的，你需要自己看看代码

8、根据mCookie对应的值做转换，最终你能找到dexfile内存指针
9、把该指针转换为dexfile结构，通过findClassDef来匹配你所寻找的dex是你要的dex
10、dump写文件


代码说明（代码包括java层和native层，但java层只需定义一个native函数即可）：
1、代码核心部分为dump_dex.h 和 dump_dex.cpp，里面涉及你需要自行实现的部分（我测试用的5.0.2 moto手机，
如果你的手机版本或者手机型号不同，你可能需要修改我表明的地方）
2、代码相对简单，你可以自行阅读

坑：
此方法思路相对简单，但是操作相对繁琐
1、你需要重打包apk
2、如果遇到签名校验，你同时需要在重打包中加入hook签名代码

#抽取dex脱壳
把抽取部分添加到尾部，并修复相关偏移

注意：
不要用于违法目的，本人声明只用于学习，其他责任本人概不承担。