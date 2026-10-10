# rikkachat

REA 逆向助手 — AI 聊天 + 本地 APK 静态分析

## 下载

[Releases](../../releases) 页面下载最新 APK（包名 `cn.rikka.rea`）

```
https://github.com/SukiSU-rikka/rikkachat/releases/download/v1.5.0/rikkachat-v1.5.0.apk
```

## 功能

### 💬 AI 聊天
- 13 家服务商预设（DeepSeek / OpenAI / Claude / 国产等，照抄六花日语配置）
- 多助手：REA 逆向分析 / 通用聊天 / 自定义
- Markdown 代码高亮，消息复制 / 重新生成

### 🔍 本地 APK 分析（纯前端，无需联网）
- 二进制 Manifest 解析：包名 / 版本 / 权限（中文说明）/ 四大组件
- 敏感权限标红
- dex 字符串提取：URL / IP / API 路径 / 可疑字符串 / 包名分类
- so 原生库字符串：JNI 方法名 / URL / 可疑字符串
- assets 配置文件查看（JSON 自动格式化）
- APK 签名证书解析：签名者 / 有效期 / SHA-256 指纹
- APK 对比：两个版本看权限 / 组件 / dex 差异
- 网络行为画像：域名聚合，标记 IP 直连 / 内网 / HTTP 明文
- 风险评分：0-100 启发式打分（仅供参考）
- 分析历史：localStorage 存 20 条报告
- 一键生成完整 Markdown 报告，发给 AI 解读

## 版本历史

- v1.5.0：网络画像 + 风险评分 + 分析历史
- v1.4.0：so 字符串 + assets 查看器 + 完整报告
- v1.3.0：APK 对比 + 证书信息
- v1.2.0：dex 字符串深度分析
- v1.1.0：本地 APK 解析器
- v1.0.0：AI 聊天初版
