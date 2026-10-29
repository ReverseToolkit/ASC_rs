# ASC

按需查询的 Android / HarmonyOS 反编译前端。它不预先把整个包做成交叉引用数据库：ZIP 里的 DEX 和 ABC 保持只读，用到哪一段再解压、再查询。

本仓库是 [MG1937/ASC](https://github.com/MG1937/ASC) 的 Rust 重写。

## 能读什么

| 输入 | 内容 |
| --- | --- |
| APK / AAB | DEX、二进制或 protobuf 清单、`resources.arsc` |
| 裸 `.dex` | 单文件 DEX；资源要用 `--resources` |
| HAP / HSP | `ets/*.abc`、`module.json` / `config.json`、`pack.info`、`resources/` |
| 裸 `.abc` | 文件头 `PANDA\0\0\0`；资源要用 `--resources` |

容器按魔数分流：先认 8 字节 `PANDA\0\0\0`，再认 HAP 标记（`.abc`、`module.json`、`pack.info`），其余当 APK / AAB。`assets/.../config.json` 不会把包判成 HAP。

ZIP 支持 store、deflate、数据描述符和 ZIP64。中央目录里任何一条记录读不通都按错误上报。单个条目解压上限 1 GiB，并且不超过中央目录声明的解压大小。CRC 非 0 时会核对解压结果，不一致时在标准错误告警并继续读取。

## 构建

需要 Rust 1.88 或更新版本，与当前锁定依赖的最低要求一致。

```sh
cargo test --workspace --locked
cargo build --release
./target/release/asc --help
```

## 命令

```text
asc getclass app.apk 'Lcom/poc/Main;' -o Main.java
asc getclass app.apk com.poc.Main --threads 16
asc getclass app.apk com.poc.Main --engine smali
asc listclass app.apk --prefix com.poc -o classes.txt
asc getmanifest app.apk -o AndroidManifest.xml
asc dump app.apk -o output
asc findrefs app.apk string token -o string_refs.txt
asc findrefs app.apk type 'Lcom/poc/Main;'
asc findrefs app.apk method onCreate --class com.poc.Main
asc findrefs app.apk method notify --class MainActivity --fuzzy-class
asc findrefs app.apk field apiKey
asc getclass app.hap com.poc.Main
asc getclass app.hap com.poc.Main --abc-output asm
asc listclass app.hap --prefix com.poc
asc getmanifest app.hap -o module.json
asc dump app.hap -o output
asc findrefs app.hap string token
asc getclass classes.dex 'Lcom/example/Main;' --resources resources.arsc
asc getclass modules.abc 'Ldemo/App;' --resources resources
asc getclass modules.abc 'Ldemo/App;' --abc-output source
asc dump modules.abc -o output --abc-output asm
asc diff old.apk new.apk
asc diff --prefix assets/ old.apk new.apk -o diff-out
asc skills install
```

`-o FILE` 只写文件，不再同时打印到标准输出。`--threads` 默认等于可用 CPU 数。`--debug` 把耗时和诊断打到标准错误。

| 退出码 | 含义 |
| --- | --- |
| 0 | 完成；`listclass` / `findrefs` 无命中时标准输出为空 |
| 1 | 失败 |
| 2 | `findrefs` 有 DEX 条目读失败；其余命中仍然打印 |

## 反编译：`getclass` 和 `dump`

`getclass` 反编译一个类。类名可以是 `com.poc.Main` 或 `Lcom/poc/Main;`。

`dump` 导出整个包，`-o` 是输出目录。APK / AAB 会带上 `AndroidManifest.xml`；HAP 导出 Ark 类树；裸 DEX / ABC 只有类文件。某个类失败会计入 `errors`，其余类照常写出。标准错误摘要形如：

```text
dumped 120 classes (2 errors) -> output
```

`--engine` 只作用于 APK、AAB 和裸 DEX 的 `getclass` / `dump`：

| 引擎 | 输出 |
| --- | --- |
| `ddc`（默认） | [ddc](https://github.com/ejfkdev/ddc) / `jdc-core` 重构控制流后的 Java，并改写资源引用 |
| `smali` | baksmali 文本，保留指令名和寄存器，不改写资源引用 |

HAP 和 ABC 用 `--abc-output` 选择输出：`source`（默认）通过 Rust 的 `asc-abc-dec` 恢复 JavaScript；`asm` 打印 Ark 指令、操作数、跳转标签和异常表。`dump` 分别导出 `.js` 和 `.pa` 文件。`--engine` 仍只作用于 DEX。`listclass`、`findrefs`、`getmanifest` 不走反编译器。

ABC 反编译移植了 [xpanda-core](https://github.com/asmjmp0/xpanda) 必要的字节码解析、指令语义、模块与字面量、函数与类、控制流生成路径。指令表来自上游 24.0.0.0 ISA（332 条定义），兼容其 13.0.1.0 样本。Rust 原生的 Oxc AST 优化流程会折叠寄存器复制、恢复闭包变量、类字段与访问器、对象字面量和直接方法调用，并生成 `if` / `while` / `try` / `catch` / `finally`。复杂控制流仍可保留显式分派器。运行时只需 Rust 编译出的程序，不调用 Node、TypeScript 或 Babel。未实现语义的指令会返回明确错误，仍可选择汇编查看原始指令。

可读性与行为回归覆盖上游 class、MD5、AES 以及真实 24.0.0.0 ABC 中的 AppLog、GamePage；后两者恢复为直接的类与方法，去掉函数工厂和控制流分派器。测试还检查 getter 与参数求值顺序、循环、异常边界和闭包捕获。Node 仅用作可选测试解释器。

同名类按运行时顺序保留：`classes.dex`、`classes2.dex`、`classes10.dex`，其余根目录 DEX 按中央目录顺序排在后面。AAB 的代码在 `<module>/dex/*.dex`，清单在 `base/manifest/AndroidManifest.xml`；同名类先保留 `base` 模块。

`getclass` 先只解出头、id 表和字符串区来判断类在不在，命中后再整份解压。

## 列类：`listclass`

按 DEX 条目和 `class_def` 的顺序打印 Dalvik 描述符，一行一个。`--prefix com.poc` 会规范成 `Lcom/poc`。ABC / HAP 上 `com.poc`、`Lcom.poc`、`com/poc`、`Lcom/poc` 等价，点号和斜杠都当包分隔符。

## 清单：`getmanifest`

- APK / AAB：解码后的 `AndroidManifest.xml`。`@string/`、`@mipmap/`、`@0x7f......` 会换成 `resources.arsc` 或 `res/` 里的值。
- HAP：`module.json`（没有则读 `config.json`），再加上 `pack.info`。`$string:`、`$media:`、`$profile:` 换成 `resources/` 里的值。
- 裸 DEX / ABC：没有清单，命令失败。

资源取值按真正的默认配置（mcc/mnc、locale、密度、uiMode、sdkVersion 等限定符都为空）优先，与它在文件里的先后无关。字符串资源一律按字符串引用写回，即使内容看起来像数字或颜色。

## 引用搜索：`findrefs`

```text
asc findrefs <input> string  VALUE
asc findrefs <input> type    VALUE
asc findrefs <input> method  [NAME] [--class CLASS] [--fuzzy-class]
asc findrefs <input> field   [NAME] [--class CLASS] [--fuzzy-class]
```

多 DEX 时先搜压缩体积最大的条目，结果按压缩后体积排序。

APK / AAB：

- `string` 和 `type` 是对每条字符串内容的正则。`.` 匹配任意字节，可以命中字符串中间。
- `type` 搜的是类型描述符（`Lcom/poc/Main;` 或 `com/poc/Main`），不会把点号 Java 名改写成斜杠。
- 资源改写后的文本也能命中 `string`，打印的是解析后的值。
- 不带 `--class` 时，method / field 的 `NAME` 必须匹配整个简单名（锚定正则），且 `NAME` 必填。
- 带精确 `--class` 时，类名是完整类型，`NAME` 按字面量完全相等；省略 `NAME` 会列出该类被引用的全部成员。
- `--fuzzy-class` 把 `--class` 当字面量子串。内部类的 `$` 不是正则元字符；只有类名里没有斜杠时，点号才当成包分隔符。此时 `NAME` 仍是锚定正则。
- 结果行形如 `<dex> | <caller> | matched=(<target>; <target>)`。一行一个调用方。

HAP / ABC 使用同一套子命令，但拒绝 `--fuzzy-class`：`--class` 选一个类，成员名仍是锚定正则。

## 资源、缓存、裸文件

APK、AAB、HAP 自带资源表。裸 DEX 和裸 ABC 默认不解析资源；`--resources` 打开解析：

- DEX 指向 `resources.arsc`
- ABC 指向 `resources` 目录，或带这份资源的 HAP

同一张表也会写回 DEX：`getclass` / `dump` 里的常量、`R$type;->name`、字符串中的 `@string/`，以及 `findrefs` 命中的字符串和字段。HAP 里 ABC 的类文本和字面量同样替换 `$string:`、`$media:`、`$profile:`。

解压过的 DEX 缓存在 `~/.cache/asc`（也可用 `$ASC_CACHE_DIR` 或 `$XDG_CACHE_HOME/asc`）。`--cache-dir DIR` 改路径，`--no-cache` 关闭。

## 包对比：`diff`

`asc diff` 按中央目录里的路径和 CRC 比较两个 ZIP，不解压 DEX、不看类。相同文件只计数。`META-INF` 原始文件不参与比较。

分组：APK 按 `assets/`、`res/`、`lib/`、DEX、清单、`resources.arsc`；HAP / HSP 再认 `module.json`、`pack.info`、`ets/*.abc`、`libs/`、`resources/`。`--prefix` 只比路径前缀，例如 `assets/`。

- APK 证书来自 `META-INF/*.RSA`、`*.DSA`、`*.EC`；HAP / HSP 来自 `<hap sign block>`。都只比 SHA-256、主体、颁发者、序列号和有效期。
- `r/` 里被缩短的资源路径会先按 `resources.arsc` 还原成 `res/类型-限定符/条目名`，再按还原后的路径比较。
- `res` 下的 XML 解成文本后再比；二进制编码不同但文本相同的不算改动。
- `lib/` 或 `libs/` 下 CRC 变了的 `.so` 会再比 ELF 头、`DT_NEEDED`、导入和导出符号。节表和程序头都读，两边不一致时用程序头。虚拟地址相同的可执行段里的字节差，以及新增或删除的导出，会各反汇编一小段（x86、x86_64 的 NASM，以及 AArch64）。链接基址整段挪动时，不把相对跳转当成代码改动。

`-o DIR` 把变化、新增和删除的文件写到 `DIR/<versionCode>`，左右包各用自己的 versionCode。XML 用还原后的路径和可读文本。

AAB 从 `base/manifest/AndroidManifest.xml` 的 protobuf 清单读取 versionCode，导出的清单同样转为可读 XML。

## Agent skill

```sh
asc skills install
```

把 ASC 的 agent 说明装到：

- `~/.grok/skills/asc`
- `~/.agents/skills/asc`
- `~/.claude/skills/asc`
- `~/.cursor/skills/asc`

## Crate

| Crate | 职责 |
| --- | --- |
| `asc` | clap CLI |
| `asc-apk` | APK / AAB、ZIP、多 DEX、`resources.arsc`、ddc 适配 |
| `asc-dex` | DEX 解析、smali、findrefs |
| `asc-axml` | 二进制 XML 和 AAB protobuf 清单 |
| `asc-hap` | HarmonyOS HAP |
| `asc-abc` | 方舟 ABC，按文件头现查，不建全量索引 |
| `asc-abc-dec` | xpanda 必要核心的 Rust 移植，ABC 汇编和 JavaScript 反编译 |
| `asc-diff` | 按路径和 CRC 对比两个 ZIP |
| `asc-so` | ELF 比较和反汇编 |

## 和上游 Python 版的差别

- 引用搜索、类列表、DEX 041 容器和 ZIP 中央目录扫描沿用同一套规则：16 字节指令桶、指令边界校验、按需 inflate。
- `getclass` 和 `dump` 默认调用 ddc 重构控制流。`--engine smali` 打印标准 smali。
- `findrefs` 同时命中多个 DEX 时，结果按压缩后体积排序，避免多线程完成顺序抖动。
- 增加 HAP / ABC、裸 DEX / ABC、`diff` 和 `skills install`。
- ABC / HAP 的 `getclass` 和 `dump` 支持 JavaScript 反编译与 Ark 汇编选择。

## 许可

Apache License 2.0。本仓库是 [MG1937/ASC](https://github.com/MG1937/ASC) 的衍生作品，见 `NOTICE`。默认 DEX 反编译使用 MIT 许可的 [ddc](https://github.com/ejfkdev/ddc) 和 [jdc-core](https://github.com/ejfkdev/jdc-core)。

ABC 反编译的 `asc-abc-dec` 改写自 jmp0 的 [xpanda-core](https://github.com/asmjmp0/xpanda)（Apache-2.0）；指令定义沿用 OpenHarmony ISA（Huawei Device Co., Ltd., Apache-2.0）。来源修订和测试样本归属见 `NOTICE` 与 crate 内说明。
