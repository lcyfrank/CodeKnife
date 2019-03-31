## CodeKnife

*针对已砸壳的 iOS 应用程序的静态分析工具。*

### 环境要求

* [Capstone](https://github.com/aquynh/capstone): 轻量跨平台的多架构的反汇编框架。
* [Python 3](https://www.python.org/): 一种知名编程语言。
* [Flask](http://flask.pocoo.org/) (可选): 用 Python 写的轻量 Web 框架，仅在需要访问图形化界面时需要。

### 如何运行

当前，`CodeKnife` 仅支持在**终端**运行，图形化界面正在完善中。

首先，确保已经安装上述依赖，然后进入 `CodeKinfe` 的根目录，执行一下命令即可运行：

```sh
python3 basic_analysis.py [`.ipa` or `.app`]
```

若想访问图形化界面，在终端中输入以下命令即可：

```sh
python3 ./view/home.py
```

### 检测项目

* **剪切板的访问**：针对 iOS 应用程序的剪切板访问进行检测，并输出访问这些剪切板的具体方法（函数）。示例：`Demos/PasteDemo.app`
* **数据存储方式检测**：针对 iOS 应用程序当前所使用的数据存储方式，包括 `UserDefaults`、`KeyArchived`、`SQLite`、`CoreData` 这些常用数据存储方式的使用，输出使用这些方式存储数据的方法（函数）。示例：`Demos/DataStorageDemo.app`
* **潜在热补丁方式检测**：针对 iOS 应用程序，检测使用 JSContext 类并为 JSContext 赋值相应 Objective-C 行为的方法，以及使用 JSContext 类执行 JavaScript 代码的方法。（当前只能显示使用 JSContext 的相关方法，后续进行解析具体的 Objective-C 行为）示例：`Demos/HotPatchDemo.app`
* **钥匙串访问检测**：针对 iOS 应用程序，检测访问钥匙串的方法，输出向钥匙串中增加数据、查询钥匙串中数据、更新钥匙串中数据，从钥匙串中删除数据的方法（函数）。示例：`Demos/KeychainDemo.app`
* **进入后台行为检测**：针对 iOS 应用程序，检测其即将/已经进入后台时所调用的系统 API 行为。示例：`Demos/BackgroundDemo.app`
* **应用内 Notification 检测**：针对 iOS 应用程序，检测内部发送的 Notification 以及相应的 Notification 的处理方法。示例：`Demos/AccountBook.app`

### TODO List
* 针对每一种检测项目和Demo的app文件，绘制其对应的control flow graph，并加以解释
* 针对每一种检测项目，考虑是否可以加入一些数据流分析，对检测结果进行确认。如剪切板的访问，但是可能是正常的行为，通过判断是否APP获取到剪切板内容之后对其数据进行滥用而造成实质的危害
* 设置一种打分机制，能够根据检测结果对APP存在的安全风险进行量化。
