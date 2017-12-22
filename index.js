'use strict';

const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const querystring = require('querystring');

const PRIFIX = 'cmblife://';
const HOST = 'open.cmbchina.com';

function pad(n) { return n < 10 ? '0' + n : n; }

function dateStr(d = new Date()) {
  return d.getFullYear().toString() + pad(d.getMonth() + 1) + pad(d.getDate()) + pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds());
}

function randomString(num) {
  return crypto.randomBytes(num).toString('hex').substr(0, num);
}

/**
 * request
 *
 * @param {Object} params 参数
 * @param {String} data 数据
 * @returns {Promise}
 */
function request(params, data) {
  // eslint-disable-next-line
  return new Promise((resolve, reject) => {
    const req = https.request(params, function (response) {
      if(response.statusCode !== 200) {
        return reject({ 'httpcode': response.statusCode, 'code': response.statusCode });
      }
      const buffers = [];
      response.on('data', (chunk) => buffers.push(chunk));
      response.on('end', () => {
        return resolve(JSON.parse(Buffer.concat(buffers).toString('utf8')));
      });
      response.on('error', (e) => {
        return reject({ 'httpcode': response.statusCode, 'code': response.statusCode, 'message': '' + e });
      });
    });
    if(data) req.write(data);
    req.end();
  });
}

/**
 * POST
 *
 * @param {string} hostname 主机
 * @param {string} path 路径
 * @param {Object} data 数据
 * @returns {Promise}
 */
function post(hostname, path, data) {
  const dataString = querystring.stringify(data);
  return request({
    hostname, path,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(dataString, 'utf8'),
    },
  }, dataString);
}

/**
 * 招行掌上生活开放平台
 *
 * @class CMB
 */
class CMB {

  /**
   * Creates an instance of CMB.
   *
   * @param {Object} options - 配置参数
   * @param {String} options.mid - 商户号
   * @param {String} options.aid - 唯一应用号
   * @param {String} options.key - RSA私钥路径
   * @param {String} [options.publicKey] - RSA公钥路径
   * @param {String} [options.defaultType] - 默认跳转方式"app"、"h5"
   * @param {String} [options.host] - 服务器地址
   * @memberof CMB
   */
  constructor(options) {
    this.mid = options.mid;
    this.aid = options.aid;
    this.key = fs.readFileSync(options.key).toString();
    this.defaultType = options.defaultType || 'h5';
    this.host = options.host || HOST;
    this.publicKey = options.publicKey ? fs.readFileSync(options.publicKey) : '';
  }

  /**
   * 获取签名
   * {@link https://open.cmbchina.com/Platform/#/resource/document/signVerify signVerify}
   *
   * @param {String} prifix 前缀
   * @param {Object} data 签名数据
   * @returns {Object} 添加签名的数据
   * @memberof CMB
   */
  _signOrg(prifix, data) {
    if(!data.date) data.date = dateStr();
    if(!data.random) data.random = randomString(16);
    const keys = Object.keys(data).sort();
    const strArr = [];
    for(const key of keys) {
      strArr.push(`${ key }=${ data[key] }`);
    }
    const signStr = `${ prifix }?${ strArr.join('&') }`;
    const signFn = crypto.createSign('RSA-SHA256');
    signFn.update(signStr);
    const sign = signFn.sign(this.key, 'base64');
    data.sign = sign;
    return data;
  }

  /**
   * 获取JSON签名
   * @see _signOrg
   *
   * @param {String} funcName 调用方法
   * @param {Object} data 签名数据
   * @returns {Object} 添加签名的数据
   * @memberof CMB
   */
  _signJson(funcName, data) {
    return this._signOrg(funcName + '.json', data);
  }

  /**
   * 获取CMBLife签名链接
   * @see _signOrg
   *
   * @param {String} funcName 调用方法
   * @param {Object} data 签名数据
   * @returns {String} 包含签名的link
   * @memberof CMB
   */
  _signCmblife(funcName, data) {
    const signData = this._signOrg(PRIFIX + funcName, data);
    const keys = Object.keys(signData);
    const strArr = [];
    for(const key of keys) {
      strArr.push(`${ key }=${ encodeURIComponent(signData[key]) }`);
    }
    return `${ PRIFIX }${ funcName }?${ strArr.join('&') }`;
  }

  verifyRespons(res) {
    if(!this.publicKey || !res.sign) return false;
    const verify = crypto.createVerify('SHA256');
    const signature = new Buffer(res.sign, 'base64');
    delete res.sign;
    const keys = Object.keys(res).sort();
    const strArr = [];
    for(const key of keys) {
      strArr.push(`${ key }=${ res[key] }`);
    }
    const signStr = `${ strArr.join('&') }`;
    verify.update(signStr);
    return verify.verify(this.publicKey, signature);
  }

  /**
   * 授权登录
   * {@link https://open.cmbchina.com/Platform/#/resource/document/approvalAPI approvalAPI}
   *
   * @param {String} state client端的状态值
   * @param {String} [callback] 成功授权后的回调
   * @returns {String} 授权登录的url
   * @memberof CMB
   */
  getApproval(state, callback) {
    const data = {
      mid: this.mid,
      aid: this.aid,
      clientType: this.defaultType,
      state,
      scope: 'defaultScope',
      responseType: 'code',
    };
    if(callback) {
      data.callback = callback.indexOf('http') === 0 ? callback : 'javascript:' + callback;
    }
    return this._signCmblife('approval', data);
  }

  /**
   * 获取 AccessToken
   * @see {@link https://open.cmbchina.com/Platform/#/resource/document/approvalAPI accessToken}
   *
   * @param {String} code 临时授权码
   * @returns {Object} 授权结果
   * @memberof CMB
   */
  getAccessToken(code) {
    const data = {
      mid: this.mid,
      aid: this.aid,
      clientType: this.defaultType,
      grantType: 'authorizationCode',
      code,
    };
    const signData = this._signJson('accessToken', data);
    return post(this.host, '/AccessGateway/transIn/accessToken.json', signData);
  }

}

module.exports = CMB;
