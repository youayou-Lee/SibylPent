"""知识库 → 运行时格式编译器（INTEGRATION.md §0：单一事实源，多运行时编译）。

三个编译器均返回 {相对 --out 的路径: 文件内容}，由 ``sibylctl compile``
统一落盘并打印；同一知识库输入必须得到字节相同的输出。
"""

from sibylpent.compilers.cai import compile_cai
from sibylpent.compilers.cc_skill import compile_cc_skill
from sibylpent.compilers.hbg import compile_hbg

__all__ = ["compile_cai", "compile_cc_skill", "compile_hbg"]
