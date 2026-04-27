# AES File Encryptor Web

基于 React 的浏览器端 AES 文件加密/解密可视化工具。

## 快速开始

### 1. 安装依赖

```bash
npm install
```

### 2. 启动开发服务器

```bash
npm run dev
```

终端输出类似：

```
  VITE v5.3.0  ready in 312 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

在浏览器中打开 `http://localhost:5173/` 即可使用。

### 3. 构建生产版本

```bash
npm run build       # 输出到 dist/ 目录
npm run preview     # 本地预览生产构建
```

## 使用方式

### 界面操作

```
┌─────────────────────────────────────────────────────┐
│  AES File Encryptor                  [Light Auto Dark]
│  Encrypt and decrypt files in your browser           │
├─────────────────────────────────────────────────────┤
│  [🔒 Encrypt]  [🔓 Decrypt]                         │
├─────────────────────────────────────────────────────┤
│                                                     │
│   📁                                                │
│   Drop a file to encrypt, or click to browse        │
│                                                     │
├─────────────────────────────────────────────────────┤
│  Key / Passphrase                                   │
│  ┌───────────────────────────────────────────┐      │
│  │ Enter your secret passphrase              │      │
│  └───────────────────────────────────────────┘      │
├─────────────────────────────────────────────────────┤
│  [ AES-CBC ]  [ AES-CTR ]  [ AES-CFB ]              │
├─────────────────────────────────────────────────────┤
│  [ Encrypt (CBC) ]      [ Compare All 3 Modes ]     │
├─────────────────────────────────────────────────────┤
│  Encrypting...                          ██████░░ 75%│
├─────────────────────────────────────────────────────┤
```

1. **切换模式**：点击 `Encrypt` 或 `Decrypt` 按钮
2. **上传文件**：拖拽文件到上传区域，或点击选择文件
3. **输入密钥**：输入任意长度的密码短语
4. **选择算法**：点击 `AES-CBC`、`AES-CTR` 或 `AES-CFB`
5. **执行**：
   - `Encrypt/Decrypt (模式)` — 单次操作，带进度条
   - `Compare All 3 Modes` — 依次运行三种模式并对比性能（柱状图）
6. **下载**：操作完成后点击 `Download` 下载结果文件

### 支持的文件

**所有类型的文件都支持**，包括但不限于：

| 类型 | 扩展名示例 |
|------|-----------|
| 文本 | `.txt`, `.md`, `.json`, `.csv`, `.xml`, `.html` |
| 图片 | `.png`, `.jpg`, `.gif`, `.webp`, `.bmp`, `.svg` |
| 音视频 | `.mp3`, `.wav`, `.mp4`, `.avi`, `.mkv` |
| 文档 | `.pdf`, `.docx`, `.xlsx`, `.pptx` |
| 压缩包 | `.zip`, `.rar`, `.7z`, `.tar.gz`, `.tar` |
| 可执行文件 | `.exe`, `.dll`, `.so`, `.dmg`, `.app` |
| 其他 | 任意二进制文件 |

### 文件大小

- 小文件（< 10 MB）：瞬间完成
- 中等文件（10-100 MB）：数秒
- 大文件（100 MB+）：采用 1 MB 分块处理，进度条实时显示处理进度

## 技术栈

- **React 18** — UI 框架
- **Vite 5** — 构建工具
- **Tailwind CSS** — 样式（支持亮色/暗色主题，跟随系统）
- **TypeScript** — 类型安全
- **Web Crypto API** — 浏览器原生加密（零依赖）
