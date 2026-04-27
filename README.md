# AES File Encryptor

一个基于浏览器的 AES 文件加密/解密工具，提供独立的 npm 包和可视化 Web 界面。

## 项目结构

```
├── aes-file-encryptor/          # npm 加密库（可独立发布）
│   ├── src/index.ts             # 核心加解密逻辑
│   ├── test/test.html           # 浏览器端单元测试
│   └── package.json
├── aes-file-encryptor-web/      # React Web GUI
│   ├── src/App.tsx              # 主界面组件
│   └── package.json
└── README.md                    # 本文件
```

## 快速开始

### 1. 安装依赖

```bash
# 安装 npm 包依赖
cd aes-file-encryptor
npm install

cd ../aes-file-encryptor-web
npm install
```

### 2. 启动 Web 界面

```bash
cd aes-file-encryptor-web
npm run dev
```

终端会显示一个本地地址（通常是 `http://localhost:5173`），在浏览器中打开即可使用。

### 3. 构建（可选）

```bash
cd aes-file-encryptor
npm run build          # 编译 npm 包 → dist/

cd ../aes-file-encryptor-web
npm run build          # 编译前端生产版本 → dist/
npm run preview        # 预览生产构建
```

## 使用指南

### 支持的文件类型

**本工具支持任意类型的文件**，包括但不限于：

| 类别 | 示例 |
|------|------|
| 文本文件 | `.txt`, `.md`, `.json`, `.xml`, `.csv` |
| 图片 | `.png`, `.jpg`, `.gif`, `.svg`, `.webp` |
| 音频/视频 | `.mp3`, `.wav`, `.mp4`, `.avi` |
| 文档 | `.pdf`, `.docx`, `.xlsx`, `.pptx` |
| 压缩包 | `.zip`, `.rar`, `.7z`, `.tar.gz` |
| 程序文件 | `.exe`, `.dll`, `.so`, `.dmg` |
| 其他 | 任意二进制文件 |

文件通过浏览器原生 `Web Crypto API` 在本地处理，**不会上传到任何服务器**。

### 支持的文件大小

工具采用**分块处理**机制（每块 1 MB），理论上支持任意大小的文件。实际限制取决于浏览器内存：
- 小文件（< 10 MB）：瞬间完成
- 中等文件（10-100 MB）：数秒内完成
- 大文件（100 MB - 1 GB）：数十秒至数分钟
- 超大文件（> 1 GB）：取决于浏览器性能，可能会有延迟

### 加密模式对比

| 特性 | AES-CBC | AES-CTR | AES-CFB |
|------|---------|---------|---------|
| 填充 | 需要 PKCS#7 | 无需填充 | 无需填充 |
| 加密后文件大小 | 略大（填充开销） | 与原文件一致 | 与原文件一致 |
| 性能 | 稍慢（需派生子密钥） | 更快（Web Crypto 原生） | 较慢（JS 实现 AES 块加密） |
| 解密独立性 | 各块独立（可并行） | 顺序依赖 | 顺序依赖（标准 CFB 链接） |
| 适用场景 | 需要块独立解密 | 追求性能和零膨胀 | 需要标准流加密模式 |

### 操作步骤

1. **选择模式**：点击顶部 `Encrypt` / `Decrypt` 切换加密或解密
2. **选择文件**：拖拽文件到上传区域，或点击浏览选择
3. **输入密钥**：在密钥输入框中输入密码短语（任意长度）
4. **选择算法**：点击 `AES-CBC`、`AES-CTR` 或 `AES-CFB` 选择加密模式
5. **执行操作**：
   - 点击 `Encrypt (CBC/CTR/CFB)` 或 `Decrypt (CBC/CTR/CFB)` 执行单个操作
   - 点击 `Compare All 3 Modes` 同时运行三种模式并对比性能（显示进度条和柱状图）
6. **下载结果**：操作完成后点击 `Download` 按钮下载文件

### 使用界面功能

- **加密**：选择文件 → 输入密钥 → 选择模式 → 点击加密 → 下载加密文件
- **解密**：切换到 Decrypt → 选择加密文件 → 输入相同密钥 → 选择相同模式 → 点击下载
- **性能对比**：点击 `Compare All 3 Modes` 按钮，界面会显示三种模式的处理时间、速度柱状图和最快模式标识
- **进度条**：加密/解密过程中实时显示百分比进度

## npm 包独立使用

如果你只想在项目中使用加密库而不需要 GUI：

```bash
cd aes-file-encryptor
npm link                    # 全局注册

cd your-project
npm link aes-file-encryptor # 链接到项目
```

```typescript
import { encryptFile, decryptFile } from "aes-file-encryptor";

// 加密
const encrypted = await encryptFile(file, "my-password", "CBC");

// 解密
const decrypted = await decryptFile(encryptedFile, "my-password", "CBC");
```

### API

| 函数 | 参数 | 返回值 |
|------|------|--------|
| `encryptFile(file, key, mode, options?)` | `file: File`, `key: string`, `mode: "CBC"\|"CTR"\|"CFB"`, `options?: { onProgress?: (pct: number) => void }` | `Promise<Blob>` |
| `decryptFile(file, key, mode, options?)` | `file: File`, `key: string`, `mode: "CBC"\|"CTR"\|"CFB"`, `options?: { onProgress?: (pct: number) => void }` | `Promise<Blob>` |

## 安全性

- **密钥派生**：使用 PBKDF2-SHA256（10 万次迭代）从用户密码派生 256 位 AES 密钥
- **随机 IV**：CBC/CFB 模式自动生成随机 IV，存储在文件头中
- **完整性校验**：HMAC-SHA256 对文件头 + 密文进行签名，解密时验证。密钥错误或文件被篡改时会抛出异常
- **本地处理**：所有操作在浏览器本地完成，文件不会上传到任何服务器

## 注意事项

- **密钥必须一致**：加密和解密必须使用完全相同的密钥和模式
- **文件完整性**：解密后的文件与原文件逐字节一致
- **浏览器要求**：需要支持 Web Crypto API 的现代浏览器（Chrome 66+, Firefox 63+, Safari 15+）
- **本地处理**：所有操作在浏览器本地完成，文件不会离开你的设备

## License

MIT
