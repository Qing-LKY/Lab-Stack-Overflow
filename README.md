# 栈溢出漏洞实践

## 人工调整模块基地址

gen.c 中的 new_base 数组需要与 windbg 下使用 lm 显示的基地址一致。

模块名体现在注释中。注释中没有标明的不需要动。

## 生成恶意输入文件

gen.c 调整正确后，编译运行，产生的 gen.bin 就是恶意文件。

正确执行时，效果是生成一个名为 2020302181032.txt 的文件。

## 项目使用方式

在 VS 或 make tools 提供的 Developer Command Prompt 下运行 project.bat。

输入 2 编译并生成 gen.bin。

注意模块基地址是会变的，需要手动调整。
