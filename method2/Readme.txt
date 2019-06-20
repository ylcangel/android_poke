author: sp00f
核心思路(方法数不胜数，这是其中一个毕竟简单的）：
hook系统libart.so的ClassLinker->DefineClass函数

hook工具：
frida

这里提供了两种测试方式：
1、基于命令行的（dexcl.js)
2、基于python程序的(dumpdex.js + main.py)


注意：
你可能需要修改的地方（代码已经对可能需要修改的地方进行了标明）
1、我测试手机是moto 5.02版本，不同版本不同手机该导出函数的原型可能不同，你需要修改
2、有函数原型不同的原因，传入参数可能需要修改，相应的Interceptor.attach的args相关需要进行修改
3、你的class descriptor需要修改为你要找的dex的里面任一类（如Lcom/example/hello/MainApplication;）
4、python中的相应的class descriptor，js文件路径，保存dump的dex路径


测试机型 moto 5.02，frida版本12.6.8


声明：
不要用于违法目的，本人声明只用于学习，其他责任本人概不承担。