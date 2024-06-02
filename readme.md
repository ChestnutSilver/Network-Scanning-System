## 网络扫描软件设计与实现

**简介：**

同济大学系统安全评估与应用安全实验课程设计（网络扫描系统，2022）

**总评为“良”。**

**文件结构：**

1. Network Scanning System（数据包捕获的cpp文件）

2. 过程性文件（主机扫描、端口扫描的初始方法，在后续改进过程中被淘汰；加入Qt前主机扫描、端口扫描的cpp文件）

3. 可执行文件（Qt在release模式下编译出的exe文件）

4. 源代码（主机扫描、端口扫描的最终方法）

   ```
   SOURCES += \
       icmp.cpp \
       main.cpp \
       mainwindow.cpp \
       port_multhr.cpp
   
   HEADERS += \
       mainwindow.h
   
   FORMS += \
       mainwindow.ui
   ```

5. 软件开发报告

**实现功能：**

1. 主机扫描
2. 端口扫描
3. 数据包捕获
4. ui设计

**帮助：**

如果你有更好的建议或想法，或者在操作过程中遇到问题，欢迎在本仓库 Issues 与我联系。
