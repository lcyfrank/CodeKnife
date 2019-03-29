## 基本介绍

本系统针对 iOS 应用程序进行动态分析，查看目标 iOS 应用程序的系统 API 调用情况从而对目标 iOS 应用程序的基本行为，敏感操作以及存在安全隐患的行为进行定位。

本系统使用已砸壳的 iOS 应用程序的 `.ipa` 文件或 `.app` 文件进行分析。对于 `.ipa` 文件，由于其本质相当于一个压缩文件，则首先将其解压至临时目录，提取目录中的 `.app` 文件之后进行进一步分析。之后，根据 iOS 应用程序 `.app` 包结构，解析其内部 `Info.plist` 文件定位二进制可执行文件，以进行应用程序的静态分析。

## 静态分析

首先，需要知道的是 iOS 应用程序的二进制文件格式为 Mach-O 格式，因此，在静态分析的开始，对 Mach-O 格式二进制文件进行分析。

### Fat 二进制格式分析

在 Mach-O 格式的文件中，存在着一种 Fat 二进制文件，即在该二进制文件中，存在着多个架构的可执行 Mach-O 文件。因此，在解析的开始，首先解析二进制文件开头的 `magic` 字段，对该字段的值进行判断其是否为 Fat 二进制格式。若其是 Fat 二进制格式，则选取其中的 64-bit  架构 Mach-O 文件进行后续分析，否则则针对当前 Mach-O 文件进行分析。

### Mach-O 各部分分析

首先，通过 Mach-O 文件的头部 `magic` 字段判断其是否为 64-bit 架构的 Mach-O 文件。其次，参考 `xnu` 内核源码中对 Mach-O 头部字段数据的定义，从二进制文件中解析出当前 Mach-O 文件的头部各字段的值，主要包括当前架构 CPU 类型、当前 Mach-O 文件中 Load Commands 的数量以及所有 Load Commands 的整体大小等关键信息。

之后，同样参考 `xnu` 内核源码中对于各个 Load Commands 类型的定义，解析 Mach-O 文件中头部字段以下的各个 Load Commands 字段，这些字段中包含着二进制文件中相应部分的偏移地址以及大小等关键信息。同时，需要注意的是 `LC_SEGMENT`/`LC_SEGMENT_64` 类型的 Load Commands 中包含着多个 Section，Section 中包含相应节在 Mach-O 文件中的偏移地址、大小以及其他相关信息，同样参考 `xnu` 内核源码的定义进行解析。

将以上 Mach-O 的头部信息，Load Commands 信息以及内部的 Section 等基本信息解析出来之后，开始进行进一步的解析。

#### 字符串及对应地址提取

在 Mach-O 文件中，存在着大量的字符串，其中有程序中使用的字符串常量，程序中调用的方法名，程序中出现的类名，每个类内部的属性、内部变量名等等。由于这些字符串在 Mach-O 文件中会分布在各个部分里，因此本系统在实现时将各个部分中的字符串以及其地址提取出来，并交由一个变量进行管理，以便在后续静态代码分析中进行使用。

* **objc_classname**: 该 Section 中包含着当前 iOS 应用程序中使用到的类名的字符串
* **objc_methname**: 该 Section 中包含着当前 iOS 应用程序中使用的方法名的字符串
* **cstring**: 该 Section 中包含着当前 iOS 应用程序中出现的一些常量字符串，以及一些属性类型签名字符串
* **objc_methtype**: 该 Section 中包含着当前 iOS 应用程序中出现的一些方法类型字符串
* **symtab**: 该 Load Command 中包含着 Nlist 结构的列表信息，每一个 Nlist 表项都存放着字符串偏移与对应的引用地址

#### 内置类数据解析

由于 Objective-C 的动态性，使得在 iOS 应用程序的运行过程中可以通过类名获取到相应的类，因此在 Mach-O 文件中，存在着类名与其对应地址的信息

#### 分类解析

#### 属性及内部变量解析

#### 静态变量解析

在 Mach-O 文件中同时存放有大量的静态变量，这些变量的引用地址存在于 `.bss` 的 Section 中，其与变量名的关联信息存在 `symtab` 的 Load Command 中，因此，通过遍历 `symtab` 的 Load Command 中的 Nlist 表项来将静态变量的引用地址与变量名关联起来。

#### 动态库中的类及其关联动态库解析

在程序加载过程中，除了加载二进制文件中本身的类之外，还会用到一些动态库中的类，例如 `UIView`、`UILabel` 等系统内置类以及其他第三方引用的动态库中的类。因此，需要了解 Mach-O 动态库绑定机制，并将其引用地址与其名字关联起来。

关于 Mach-O 动态库绑定机制，可参考 <https://stackoverflow.com/questions/8825537/mach-o-symbol-stubs-ios/8836580#8836580> 中的解释。由该解释并结合 MachOView 源码可知，Mach-O 对于动态库中类的信息基于状态进行绑定，基于此，实现一个针对动态库中类绑定的简单状态机，对动态库中类的引用地址以及对应名字解析。除此之外，考虑到在进行方法分析的时候，会对动态引用的第三方库中的方法进行递归解析，因此解析其对应动态库的地址。

#### 函数解析

Mach-O 文件中的函数分为内置函数以及动态函数，动态函数使用函数桩的形式进行动态加载，因此对于动态函数，可以分析 `stubs` Section 中的函数信息，将函数名以及函数的引用地址相关联。对于内置函数，则需要解析 `symtab` Section 中关于函数的信息，将其中函数名以及函数引用地址相关联。

#### Block 的解析（闭包）

在 Objective-C 语言中，使用 Block 数据类型作为代码块进行传递以及调用，与其他语言中的闭包类似。因此，在解析过程中，对 Block 数据类型进行额外分析，以在后续方法分析中判断传递的 Block 内容。

在 Objective-C 中，Block 的类型分为 `NSConcreteGlobalBlock`、`NSConcreteStackBlock` 和 `NSConcreteMallocBlock`，其中，`NSConcreteGlobalBlock` 的内容可在 Mach-O 文件中直接获得，具体方法是查询解析出来的动态类，获得类名为 `NSConcreteGlobalBlock` 的动态类引用地址，之后在 Mach-O 文件中定位到该地址，并根据 Objective-C Runtime 对 Block 数据结构的定义来解析相应字段，即可获得该 Block 的调用内容。对于其他两种类型的 Block，则需要在分析方法过程中，遇到对 Block 类型参数的传递时进行具体分析。

### 反编译

在解析出 Mach-O 文件中的关键信息之后，对当前 Mach-O 中的代码段部分进行反编译，反编译过程借助 Capstone 开源工具。首先，根据当前 Mach-O 架构类型，设置反编译引擎的架构信息以及指令集。在反编译时，由于要针对单个方法/函数进行分析，因此首先确定方法/函数边界。通过上一步解析出来的方法地址以及函数地址确定每个方法/函数的开始地址。之后，再由 Capstone 反编译出来的每一条指令的地址，确定每个方法/函数的边界，最终将反编译出来的指令，放置在单独的对应的每个函数中。

### 模拟执行

在得到以函数为分隔的指令集之后，开始针对每一个函数进行模拟执行，从而得到每一步调用方法/函数时的具体方法名称和函数名称。因此，实现一个基于 ARM 指令集的简单解释器，对每一步指令以及寄存器的值进行模拟执行。

在模拟执行过程中，首先根据分析 Mach-O 得到的方法签名来决定方法的参数（目前对于函数的参数暂时没有办法设置），并依照参数类型和参数长度在执行时设置方法的参数，以此来初始化寄存器和堆栈的值。

之后，由于后续要分析 `if-else` 条件跳转以及 `for` 等循环语句跳转，因此将单个函数分隔成一个个基本块，并且在分隔成基本块之后，判断每个基本块的可达性，及是否有一条路径，可以从入口块到达当前基本块。若不存在这条路径，则该基本块不可达，无需放入后续分析队列中。

在分析完基本块的可达性后，将每个块进行模拟执行。在执行的过程中，由于基本块之间的跳转，需要记录每个块的是否已被执行，防止重复执行某个块。同时，需要记录当前块执行完毕时的上下文，以供后续块执行时恢复当前的寄存器状态。每个块在执行完毕时，将后续块放入待执行队列中，以待执行。

在模拟执行每个基本块的过程中，得到块中调用方法/函数的指令，并通过当前寄存器的状态值，以及解析出来的 Mach-O 信息，进行类名/方法名/函数名的提取，从而实现对跳转方法/函数信息的分析。

此外，在分析跳转方法/函数的过程中，会调用一些当前 Mach-O 文件中自定义的方法（即开发者自己写的方法），则对其进行递归分析，并获得其返回值。同时，对调用的一些第三方动态库中的方法，递归解析 iOS 应用程序包中相应动态库文件中的对应方法，进行递归分析，从而提高返回值确定的准确性。

## 解决的一些问题

1. 反编译过程中遇到的问题：

发现在反编译过程中，会遇到某些指令（可能是当前框架不支持），导致反编译过程中断，从而使得后续代码无法反编译的情况。解决方法是在反编译停止时，判断其当前指令地址是否已经到达代码段最后一个地址，若不是，则继续反编译下一个地址。

2. 在解析 32-bit 架构时遇到的问题：

32-bit 架构下，地址长度为 4 字节，不同于 64-bit 架构下的 8 字节，因此在解析时若不考虑清楚会出现问题。此外，64-bit 可执行文件的地址通常以 `0x100000000` 开头，而 32-bit 可执行文件没有这个特性。

3. Block 数据的处理

在处理 Block 数据的时候，发现 3 种类型的 Block 数据在 Mach-O 文件中的存在形式不同，因此需要针对 3 中类型的 Block 进行针对性分析

4. 静态变量的类型确定

在 Mach-O 中提取到的静态变量为静态变量的值，而当前所需要的信息是静态变量的类型，因此在模拟执行过程中，获得静态变量的类型，并与相应的静态变量相关联，进行分析

5. 类的内部变量访问

执行过程中，发现对类的内部变量的访问通常采用偏移的方式，因此在对类的变量的处理时，额外采用一个偏移值的数据结构进行存储，从而完成对内部变量访问的分析

6. 反编译速度慢性能优化

将原本的针对 list 的查找变成有序 list 下的元素的单个匹配

7. 