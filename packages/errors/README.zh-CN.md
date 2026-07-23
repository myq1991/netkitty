<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@netkitty/errors"><img src="https://img.shields.io/npm/v/@netkitty/errors?style=flat-square&labelColor=162032&color=2979ff&logo=npm&logoColor=white" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/@netkitty/errors"><img src="https://img.shields.io/npm/dm/@netkitty/errors?style=flat-square&labelColor=162032&color=22c55e&logo=npm&logoColor=white" alt="npm downloads"></a>
  <a href="https://github.com/myq1991/netkitty/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/@netkitty/errors?style=flat-square&labelColor=162032&color=2979ff" alt="license"></a>
</p>

# @netkitty/errors

netkitty 各子包共享的错误基元:每个子包的 error 都继承的 `NetKittyError` 基类,以及一份集中的 `ErrorCode`
错误码表。**纯 JS、零依赖、浏览器可跑。**

> English docs: [README.md](./README.md)

## 安装

```bash
npm i @netkitty/errors
```

## 为什么需要它

每个 netkitty 子包抛出的 error 都继承 `NetKittyError`,因此使用者可以**统一识别任何一个** netkitty 错误——
不管它是哪个子包抛的——并按它的 `code`/`errno` 分支处理:

```ts
import {NetKittyError} from '@netkitty/errors'

try {
  await codec.encode(input)
} catch (e) {
  if (e instanceof NetKittyError) {
    console.error(e.name, e.code, e.errno, e.message)
    // 例如 "CodecSchemaValidateError" "E_CODEC_SCHEMA_VALIDATE" 2001 "..."
  }
}
```

## API

`NetKittyError extends Error implements NodeJS.ErrnoException` —— 带一个 `errno: number` 和 `code: string`,
并把 `name` 设为具体子类名。定义一个子包 error 时继承它即可:

```ts
import {NetKittyError, ErrorCode} from '@netkitty/errors'

export class DeviceNotFoundError extends NetKittyError {
  public errno: number = ErrorCode.E_DEVICE_NOT_FOUND.errno
  public code: string = ErrorCode.E_DEVICE_NOT_FOUND.code
}
```

`ErrorCode` —— 集中的错误码表,把每个 `errno` 和一个稳定的 `code` 配对,按子包分段(1000 段 = capture,
2000 段 = codec,……),从而无论来自哪个包,一个 code 都是全局唯一的。
