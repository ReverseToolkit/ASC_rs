The class.abc, md5.abc, aes.abc, and hx360e.abc fixtures are from asmjmp0/xpanda,
revision 3ffb7b476b17066dc8bed0914caeea1f529b1e51, under Apache-2.0:
https://github.com/asmjmp0/xpanda/tree/3ffb7b476b17066dc8bed0914caeea1f529b1e51/packages/xpanda-core/test/resources

hx360e.abc is the upstream hx360e1.0.2.abc fixture, containing Ark 24.0.0.0
AppLog and GamePage records. Its tests mock the imported HarmonyOS APIs.

They exercise real Ark bytecode, nested functions, classes, property access,
numeric literals, and control flow. Node is an optional test oracle; the Rust
library and ASC CLI do not invoke or require Node.
