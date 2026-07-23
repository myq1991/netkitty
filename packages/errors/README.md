<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@netkitty/errors"><img src="https://img.shields.io/npm/v/@netkitty/errors?style=flat-square&labelColor=162032&color=2979ff&logo=npm&logoColor=white" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/@netkitty/errors"><img src="https://img.shields.io/npm/dm/@netkitty/errors?style=flat-square&labelColor=162032&color=22c55e&logo=npm&logoColor=white" alt="npm downloads"></a>
  <a href="https://github.com/myq1991/netkitty/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/@netkitty/errors?style=flat-square&labelColor=162032&color=2979ff" alt="license"></a>
</p>

# @netkitty/errors

Shared error primitives for the netkitty packages: the `NetKittyError` base class that every package's
errors extend, and a central `ErrorCode` registry. **Pure JS, zero dependencies, browser-safe.**

> 中文文档见 [README.zh-CN.md](./README.zh-CN.md)。

## Install

```bash
npm i @netkitty/errors
```

## Why

Every netkitty package's error extends `NetKittyError`, so a consumer can identify **any** netkitty error
uniformly — regardless of which package threw it — and branch on its `code`/`errno`:

```ts
import {NetKittyError} from '@netkitty/errors'

try {
  await codec.encode(input)
} catch (e) {
  if (e instanceof NetKittyError) {
    console.error(e.name, e.code, e.errno, e.message)
    // e.g. "CodecSchemaValidateError" "E_CODEC_SCHEMA_VALIDATE" 2001 "..."
  }
}
```

## API

`NetKittyError extends Error implements NodeJS.ErrnoException` — carries `errno: number` and
`code: string`, and sets `name` to the concrete subclass. Define a package error by extending it:

```ts
import {NetKittyError, ErrorCode} from '@netkitty/errors'

export class DeviceNotFoundError extends NetKittyError {
  public errno: number = ErrorCode.E_DEVICE_NOT_FOUND.errno
  public code: string = ErrorCode.E_DEVICE_NOT_FOUND.code
}
```

`ErrorCode` — the central registry pairing each `errno` with a stable `code`, grouped by package
(1000s = capture, 2000s = codec, …), so a code is globally unique regardless of origin.
