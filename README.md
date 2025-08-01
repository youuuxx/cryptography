# Cryptography Projects Collection

该仓库包含多个应用密码学相关的学习型项目。

---

## 📂 项目列表

### 🔐 [AES-Encryption-Demo](./AES-Encryption-Demo/README.md)

- 模块化实现对称加密（AES）、哈希（SHA、MD5）和非对称加密（RSA）
- 包括三个核心子模块：`symmetric`、`hash` 和 `asymmetric`
- 适合入门者理解加密流程的基本组成

### 🛡️ [SecureChat-DH](./SecureChat-DH/README.md)

- 使用 Diffie-Hellman 算法进行密钥协商
- 结合 RSA 签名实现身份认证
- 使用 AES + HMAC 实现机密通信与完整性校验
- 实现一个简单但安全的端到端通信系统（支持身份验证）

---

## 💡 使用说明

每个子项目目录下都包含独立的 `README.md` 文件，介绍对应功能、结构和运行方式。

建议结合顺序学习：

1. 先理解对称加密与非对称加密（项目一）
2. 再深入理解安全通信协议（项目二）

---

## ⚙️ 环境依赖

- Python 3.6+
- PyCryptodome 库：加密算法实现

```bash
pip install pycryptodome
```

---

## 📬 联系反馈

欢迎提交 issue 或 pull request，期待你的改进建议和交流！
