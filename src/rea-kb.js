/* REA 知识库：内容整理自 morluto/rea（MIT 协议），详见 rea.tools */
(function(){
'use strict';

var KB_HTML = ''
+'<section class="card"><h3>REA 是什么</h3>'
+'<p><b>REA：逆向一切。</b>通过一个 MCP 服务，把 AI 智能体连接到逆向分析工具，调查二进制文件、应用程序和运行时行为。</p>'
+'<p>核心理念：<b>看到喜欢的功能，弄清它的工作原理，深入到二进制层面。</b>即使没有源代码，也可以检查应用、解释功能的工作方式、展示证据，并为你自己的项目实现类似功能。</p>'
+'<p class="hint">来源：github.com/morluto/rea（MIT 协议）· rea.tools</p></section>'

+'<section class="card"><h3>调查工作流（5 步）</h3>'
+'<ol class="kb-list">'
+'<li><b>明确目标</b>：说清楚想弄清的是哪个 App 的哪个功能（例：「弄清 Notes 应用的搜索功能如何工作」）。</li>'
+'<li><b>检查目标</b>：智能体通过 REA 调用分析工具，追踪相关代码和调用链。</li>'
+'<li><b>拿到证据</b>：REA 返回发现及对应证据——伪代码、汇编、字符串、符号、调用和引用。</li>'
+'<li><b>解释与限制</b>：据此解释行为，展示证据，并如实说明哪些结论不确定、受什么限制。</li>'
+'<li><b>实现验证</b>：利用这些发现，为你的项目编写类似功能的实现并测试。</li>'
+'</ol>'
+'<p class="hint">本 App 的「分析」页就是第 2–3 步的手机端做法：本地解析出证据，一键发给 AI 按这套流程解读。</p></section>'

+'<section class="card"><h3>能分析什么（目标 → 工具）</h3>'
+'<table class="kb-table">'
+'<tr><th>目标</th><th>能得到什么</th><th>用什么</th></tr>'
+'<tr><td>原生二进制</td><td>伪代码、汇编、字符串、符号、调用和引用</td><td>Hopper / Ghidra / IDA</td></tr>'
+'<tr><td>Android APK</td><td>清单声明、类、反编译的方法和引用</td><td>jadx（无界面）+ 完整 JDK</td></tr>'
+'<tr><td>Android 资源</td><td>解码后的清单、字符串表、语言区域</td><td>apktool</td></tr>'
+'<tr><td>Android 设备</td><td>软件包、进程、日志、截图、文件传输</td><td>adb</td></tr>'
+'<tr><td>JS / Electron</td><td>模块、导入、路由、IPC、原生扩展关系</td><td>Node.js + npm（无需分析引擎）</td></tr>'
+'<tr><td>.NET 程序集</td><td>元数据、CIL 指令、原生依赖</td><td>静态检查（无需引擎）</td></tr>'
+'<tr><td>固件</td><td>区域划分、提取结果</td><td>Binwalk / Unblob</td></tr>'
+'<tr><td>网站</td><td>页面结构、脚本、网络请求、截图</td><td>Chrome 系浏览器</td></tr>'
+'<tr><td>网络捕获</td><td>请求、响应、载荷</td><td>HAR 文件 / mitmdump</td></tr>'
+'<tr><td>进程行为</td><td>终端输出、文件系统变化、运行对比</td><td>进程捕获</td></tr>'
+'</table>'
+'<p class="hint">静态 JS 和 .NET 检查只读文件不运行；运行时捕获以你的用户权限执行目标，各有影响，先看对应指南。</p></section>'

+'<section class="card"><h3>案例：这套方法长什么样</h3>'
+'<p><b>DX-Ball：重建声像计算。</b>沿声音调用追踪到按位置计算声像的辅助函数，检查指令，把不完整的伪代码转成 C。重建结果通过了 3,205 个原始 x86 测试用例，并复现了编译后函数的全部 63 个字节。</p>'
+'<p><b>Notion：追踪 Electron 剪贴板桥。</b>找到渲染进程的剪贴板 API，沿 preload 和 IPC 追踪到主进程，检查富格式剪贴板数据。</p>'
+'<p><b>TH04：恢复 DOS 弹幕环计算。</b>检查原始 PC-98 游戏的 16 位指令，恢复固定角度和瞄准角度的计算，并与当年编译器输出对比。</p>'
+'<p class="hint">共同点：从可见行为出发 → 追踪调用链 → 拿到指令/代码证据 → 重建实现并验证。</p></section>'

+'<section class="card"><h3>常见问题</h3>'
+'<p><b>哪些智能体能用 REA？</b><br>任何支持本地 MCP 服务的智能体都行。跑 <span class="code">npx rea-agents setup</span> 注册并安装指引，重启智能体即可。</p>'
+'<p><b>需要 Hopper / Ghidra / IDA 吗？</b><br>深入的原生分析需要其中一个；静态 JS 和 .NET 检查不需要。setup 流程可在你批准后安装 Hopper。</p>'
+'<p><b>REA 会上传我的应用吗？</b><br>分析在本机运行，不上传。但智能体会把工具结果发给它的模型提供商，对方有自己的数据政策。</p>'
+'<p><b>遇到错误怎么办？</b><br>先更新（REA 迭代快，新版常修旧 bug），重试；还不行就带上版本、目标类型、复现步骤去提 issue。</p></section>'

+'<section class="card"><h3>在手机上怎么用这套东西</h3>'
+'<p>说实话：REA 的 MCP 工具链是桌面端的——jadx、Hopper、Ghidra 在 Android 手机上跑不了。所以：</p>'
+'<ol class="kb-list">'
+'<li>本 App 的<b>「分析」页</b>是手机端替代：纯本地解析 APK 的 Manifest、权限、dex 字符串、so 的 JNI 方法、证书、网络画像和风险评分，<b>不上传文件</b>。</li>'
+'<li>点<b>「发给 AI 分析」</b>，把完整报告交给「REA 逆向」助手，它会按上面的 5 步工作流帮你追踪和解读。</li>'
+'<li>需要深度反编译（看完整 Java 伪代码、跟进原生函数），还是得上桌面用 jadx / Hopper 走 REA 完整流程。</li>'
+'</ol></section>';

function renderKB(){
  var el = document.getElementById('kb-content');
  if(el) el.innerHTML = KB_HTML;
}

if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', renderKB);
else renderKB();
})();
