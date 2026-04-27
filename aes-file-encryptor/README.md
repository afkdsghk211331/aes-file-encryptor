# aes-file-encryptor

AES 文件加密/解密 npm 包，支持 **CBC**（密码分组链接）和 **CTR**（计数器）两种模式。基于 Web Crypto API，专为浏览器环境设计。

## 特性

- **两种 AES 模式**：CBC 和 CTR
- **大文件支持**：1 MB 分块处理，防止浏览器内存溢出
- **安全的密钥派生**：PBKDF2-SHA256，10 万次迭代
- **CBC 独立块解密**：每块使用 HKDF 派生的独立子密钥，无需链式依赖
- **零第三方依赖**：仅使用浏览器原生 Web Crypto API
- **TypeScript**：完整的类型定义

## 安装

```bash
npm install aes-file-encryptor
```

本地开发链接：

```bash
cd aes-file-encryptor
npm link
cd ../your-project
npm link aes-file-encryptor
```

## 使用

### ES Module

```typescript
import { encryptFile, decryptFile } from "aes-file-encryptor";

// 加密
const encryptedBlob = await encryptFile(file, "my-password", "CBC");

// 解密
const decryptedBlob = await decryptFile(encryptedFile, "my-password", "CBC");
```

### CommonJS

```javascript
const { encryptFile, decryptFile } = require("aes-file-encryptor");

const encryptedBlob = await encryptFile(file, "my-password", "CTR");
const decryptedBlob = await decryptFile(encryptedFile, "my-password", "CTR");
```

## API

### `encryptFile(file, key, mode) → Promise<Blob>`

| 参数 | 类型 | 说明 |
|------|------|------|
| `file` | `File` | 要加密的文件 |
| `key` | `string` | 密码短语（任意长度） |
| `mode` | `"CBC" \| "CTR"` | AES 加密模式 |

### `decryptFile(file, key, mode) → Promise<Blob>`

| 参数 | 类型 | 说明 |
|------|------|------|
| `file` | `File` | 已加密的文件 |
| `key` | `string` | 必须与加密时相同的密码 |
| `mode` | `"CBC" \| "CTR"` | 必须与加密时相同的模式 |

## CBC vs CTR

| 方面 | CBC | CTR |
|------|-----|-----|
| 填充 | PKCS#7 | 无 |
| 解密并行性 | 是（每块独立密钥） | 否（顺序计数器） |
| 性能 | 稍慢（填充 + 密钥派生） | 更快（无填充） |
| 文件大小膨胀 | +3% ~ +10% | 0% |

## 构建

```bash
npm install
npm run build
```

输出：`dist/index.mjs`（ESM）、`dist/index.cjs`（CJS）、`dist/index.d.ts`（类型）

## 测试

在浏览器中打开 `test/test.html`，自动运行以下测试用例：
- 空文件、单字节、15/16/17 字节等边界情况
- 100 字节、1 KB、10 KB、1 MB、2 MB 不同大小
- 全字节值覆盖（0x00–0xFF）
- 错误密钥拒绝
- 模式不匹配拒绝

## 运行环境

**仅限浏览器**。需要 `crypto.subtle`（Web Crypto API），所有现代浏览器均支持。不兼容 Node.js（除非使用 polyfill）。

## License

MIT
