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

class CMB {
  constructor(options) {
    this.mid = options.mid;
    this.aid = options.aid;
    this.key = fs.readFileSync(options.key);
    this.defaultType = options.defaultType || 'h5';
    this.host = options.host || HOST;
  }

  _signOrg(prifix, data) {
    // cmblife://funcName?key1=URLEncode(value1)&key2=URLEncode(value2)&...&sign=URLEncode(sign)
    if(!data.date) data.date = dateStr();
    if(!data.random) data.random = randomString(16);
    const keys = Object.keys(data).sort();
    const strArr = [];
    for(const key of keys) {
      strArr.push(`${ key }=${ data[key] }`);
    }
    const signStr = `${ prifix }?${ strArr.join('&') }`;
    // console.log(signStr);
    const signFn = crypto.createSign('RSA-SHA256');
    signFn.update(signStr);
    const sign = signFn.sign(this.key, 'base64');
    data.sign = encodeURI(sign);
    return data;
  }

  _signJson(funcName, data) {
    return this._signOrg(funcName + '.json', data);
  }

  _signCmblife(funcName, data) {
    const signData = this._signOrg(PRIFIX + funcName, data);
    const keys = Object.keys(signData);
    const strArr = [];
    for(const key of keys) {
      strArr.push(`${ key }=${ encodeURI(signData[key]) }`);
    }
    return `${ PRIFIX }${ funcName }?${ strArr.join('&') }`;
  }

  getApproval(state, callback) {
    const data = {
      mid: this.mid,
      aid: this.aid,
      clientType: this.defaultType,
      state,
      scope: 'defaultScope',
      responseType: 'code',
    };
    if(callback) data.callback = callback;
    return this._signCmblife('approval', data);
  }

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
