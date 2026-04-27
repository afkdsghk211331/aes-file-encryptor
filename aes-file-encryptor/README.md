# aes-file-encryptor

AES 文件加密/解密 npm 包，支持 **CBC**（密码分组链接）、**CTR**（计数器）和 **CFB**（密码反馈）三种模式。基于 Web Crypto API，专为浏览器环境设计。

## 特性

- **三种 AES 模式**：CBC、CTR、CFB
- **大文件支持**：1 MB 分块处理，防止浏览器内存溢出
- **安全的密钥派生**：PBKDF2-SHA256，10 万次迭代
- **CBC 独立块解密**：每块使用 HKDF 派生的独立子密钥，无需链式依赖
- **CFB 标准实现**：手动 AES-128 块加密实现标准 CFB-128 流加密模式
- **完整性校验**：HMAC-SHA256 签名验证，检测密钥错误或文件篡改
- **进度回调**：`onProgress` 回调函数，实时显示处理进度
- **零第三方依赖**：仅使用浏览器原生 Web Crypto API（CFB 内置轻量 JS AES-128）
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

// 带进度回调
const blob = await encryptFile(file, "my-password", "CTR", {
  onProgress: (pct) => console.log(`${Math.round(pct * 100)}%`),
});
```

### CommonJS

```javascript
const { encryptFile, decryptFile } = require("aes-file-encryptor");

const encryptedBlob = await encryptFile(file, "my-password", "CFB");
const decryptedBlob = await decryptFile(encryptedFile, "my-password", "CFB");
```

## API

### `encryptFile(file, key, mode, options?) → Promise<Blob>`

| 参数 | 类型 | 说明 |
|------|------|------|
| `file` | `File` | 要加密的文件 |
| `key` | `string` | 密码短语（任意长度） |
| `mode` | `"CBC" \| "CTR" \| "CFB"` | AES 加密模式 |
| `options` | `{ onProgress?: (pct: number) => void }` | 可选，进度回调（0~1） |

### `decryptFile(file, key, mode, options?) → Promise<Blob>`

| 参数 | 类型 | 说明 |
|------|------|------|
| `file` | `File` | 已加密的文件 |
| `key` | `string` | 必须与加密时相同的密码 |
| `mode` | `"CBC" \| "CTR" \| "CFB"` | 必须与加密时相同的模式 |
| `options` | `{ onProgress?: (pct: number) => void }` | 可选，进度回调（0~1） |

## 加密模式对比

| 方面 | CBC | CTR | CFB |
|------|-----|-----|-----|
| 填充 | PKCS#7 | 无 | 无 |
| 解密并行性 | 是（每块独立密钥） | 否（顺序计数器） | 否（标准链接） |
| 性能 | 中等 | 最快 | 较慢 |
| 文件大小膨胀 | +3% ~ +10% | 0% | 0% |
| 实现方式 | Web Crypto 原生 | Web Crypto 原生 | JS AES-128 + Web Crypto |

## 文件格式

加密文件采用以下二进制结构：

```
┌──────┬──────────┬──────────┬─────────────┬──────────┬──────────────┐
│ Mode │ Salt(16) │ IV(16)   │ OrigSize(8) │ HMAC(32) │ 加密数据     │
│ (1B) │          │          │ LE uint64   │          │              │
└──────┴──────────┴──────────┴─────────────┴──────────┴──────────────┘
```

- **Mode**：`0x01` = CBC, `0x02` = CTR, `0x03` = CFB
- **Salt**：随机字节，用于 PBKDF2 密钥派生
- **IV**：随机初始化向量/计数器种子
- **OrigSize**：原始文件大小（字节），用于解密时截断填充
- **HMAC**：HMAC-SHA256 签名，覆盖文件头 + 密文，用于完整性验证
- **加密数据**：CBC/CFB 为 `[IV(16) + 密文块] * N`；CTR 为原始密文

## 安全性

- **密钥派生**：PBKDF2-SHA256，10 万次迭代，16 字节随机盐
- **随机 IV**：CBC/CFB 模式每次加密使用新的随机 IV
- **完整性校验**：HMAC-SHA256 签名验证，密钥错误或文件被篡改时会抛出异常
- **恒定时间比较**：HMAC 验证使用恒定时间字节比较，防止时序攻击

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
- 三种模式（CBC/CTR/CFB）的加密后解密一致性
- 错误密钥拒绝
- 模式不匹配拒绝

## 运行环境

**仅限浏览器**。需要 `crypto.subtle`（Web Crypto API），所有现代浏览器均支持。不兼容 Node.js（除非使用 polyfill）。

## License

MIT
