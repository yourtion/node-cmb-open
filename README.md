[![NPM version][npm-image]][npm-url]
[![node version][node-image]][node-url]
[![npm download][download-image]][download-url]
[![npm license][license-image]][download-url]

[npm-image]: https://img.shields.io/npm/v/cmb-open.svg?style=flat-square
[npm-url]: https://npmjs.org/package/cmb-open
[node-image]: https://img.shields.io/badge/node.js-%3E=4.0-green.svg?style=flat-square
[node-url]: http://nodejs.org/download/
[download-image]: https://img.shields.io/npm/dm/cmb-open.svg?style=flat-square
[download-url]: https://npmjs.org/package/cmb-open
[license-image]: https://img.shields.io/npm/l/cmb-open.svg

# node-cmb-open

掌上生活开放平台（ https://open.cmbchina.com/Platform/ ） Node.js SDK

## 安装

```bash
npm install cmb-open --save
```

## 使用

```javascript
const CMB = require('cmb-open');
const cmb = new CMB({
  mid: 'xxx',
  aid: 'xxx',
  key: '/path/to/cmb.key',
  publicKey: '/path/to/pubkey.pem',
});

// 授权登录
cmb.getApproval();
// 获取 AccessToken
cmb.getAccessToken();
// 结果签名验证
cmb.verifyRespons();
```
