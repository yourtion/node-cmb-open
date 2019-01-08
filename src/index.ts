import { createSign, createVerify, randomBytes } from "crypto";
import { readFileSync } from "fs";
import * as https from "https";
import * as querystring from "querystring";

const PRIFIX = "cmblife://";
const HOST = "open.cmbchina.com";

function pad(n: number) {
  return n < 10 ? "0" + n : n;
}

function dateStr(d = new Date()) {
  return (
    d.getFullYear().toString() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  );
}

function randomString(num: number) {
  return randomBytes(num)
    .toString("hex")
    .substr(0, num);
}

/**
 * request
 *
 * @param {Object} params 参数
 * @param {String} data 数据
 * @returns {Promise}
 */
function request(params: Record<string, any>, data?: string | Buffer): Promise<Record<string, any>> {
  // eslint-disable-next-line
  return new Promise((resolve, reject) => {
    const req = https.request(params, (response) => {
      if (response.statusCode !== 200) {
        return reject({ httpcode: response.statusCode, code: response.statusCode });
      }
      const buffers: any[] = [];
      response.on("data", (chunk) => buffers.push(chunk));
      response.on("end", () => {
        return resolve(JSON.parse(Buffer.concat(buffers).toString("utf8")));
      });
      response.on("error", (e) => {
        return reject({ httpcode: response.statusCode, code: response.statusCode, message: "" + e });
      });
    });
    req.on("error", (err) => {
      return reject(err);
    });
    if (data) {
      req.write(data);
    }
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
function post(hostname: string, path: string, data: object) {
  const dataString = querystring.stringify(data);
  return request(
    {
      hostname,
      path,
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(dataString, "utf8"),
      },
    },
    dataString,
  );
}

export interface IOptions {
  mid: string;
  aid: string;
  key: string;
  defaultType?: string;
  host?: string;
  publicKey?: string;
}

export interface IAccessTokenRes extends Record<string, any> {
  respCode: string;
  respMsg: string;
  date: string;
  sign: string;
  accessToken?: string;
  openId?: string;
  expiresIn?: string;
}

/**
 * 招行掌上生活开放平台
 *
 * @class CMB
 */
export default class CMB {
  private mid: string;
  private aid: string;
  private key: string;
  private defaultType: string;
  private host: string;
  private publicKey: string | Buffer;

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
  constructor(options: IOptions) {
    this.mid = options.mid;
    this.aid = options.aid;
    this.key = readFileSync(options.key).toString();
    this.defaultType = options.defaultType || "h5";
    this.host = options.host || HOST;
    this.publicKey = options.publicKey ? readFileSync(options.publicKey) : "";
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
  public _signOrg(prifix: string, data: Record<string, any>) {
    if (!data.date) {
      data.date = dateStr();
    }
    if (!data.random) {
      data.random = randomString(16);
    }
    const keys = Object.keys(data).sort();
    const strArr = [];
    for (const key of keys) {
      strArr.push(`${key}=${data[key]}`);
    }
    const signStr = `${prifix}?${strArr.join("&")}`;
    const signFn = createSign("RSA-SHA256");
    signFn.update(signStr);
    const sign = signFn.sign(this.key, "base64");
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
  public _signJson(funcName: string, data: Record<string, any>) {
    return this._signOrg(funcName + ".json", data);
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
  public _signCmblife(funcName: string, data: Record<string, any>) {
    const signData = this._signOrg(PRIFIX + funcName, data);
    const keys = Object.keys(signData);
    const strArr = [];
    for (const key of keys) {
      strArr.push(`${key}=${encodeURIComponent(signData[key])}`);
    }
    return `${PRIFIX}${funcName}?${strArr.join("&")}`;
  }

  public verifyRespons(res: Record<string, any>) {
    if (!this.publicKey || !res.sign) {
      return false;
    }
    const verify = createVerify("SHA256");
    const signature = new Buffer(res.sign, "base64");
    delete res.sign;
    const keys = Object.keys(res).sort();
    const strArr = [];
    for (const key of keys) {
      strArr.push(`${key}=${res[key]}`);
    }
    const signStr = `${strArr.join("&")}`;
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
  public getApproval(state: string, callback: string) {
    const data = {
      mid: this.mid,
      aid: this.aid,
      clientType: this.defaultType,
      state,
      scope: "defaultScope",
      responseType: "code",
      callback: callback.indexOf("http") === 0 ? callback : "javascript:" + callback,
    };
    return this._signCmblife("approval", data);
  }

  /**
   * 获取 AccessToken
   * @see {@link https://open.cmbchina.com/Platform/#/resource/document/approvalAPI accessToken}
   *
   * @param {String} code 临时授权码
   * @returns {Object} 授权结果
   * @memberof CMB
   */
  public getAccessToken(code: string) {
    const data = {
      mid: this.mid,
      aid: this.aid,
      clientType: this.defaultType,
      grantType: "authorizationCode",
      code,
    };
    const signData = this._signJson("accessToken", data);
    return post(this.host, "/AccessGateway/transIn/accessToken.json", signData) as Promise<IAccessTokenRes>;
  }

  /**
   * 获取积分接口
   * @param {string} openid
   * @param {string} amount
   */
  public increaseTreasure(openid: string, amount: number) {
    const data = {
      openId: openid,
      mid: this.mid,
      aid: this.aid,
      random: Date.now(),
      treasureType: 0,
      treasureId: 0,
      treasureAmount: amount,
      refToken: Date.now(),
    };
    const signData = this._signJson("increaseTreasure", data);
    // console.log(signData)
    return post(this.host, "/AccessGateway/transIn/increaseTreasure.json", signData);
  }

  /**
   * 增加处理状态查询接口
   * @param {string} openid
   */
  public queryIncreaseTreasure(openid: string, refToken: string) {
    const data = {
      openId: openid,
      mid: this.mid,
      aid: this.aid,
      random: Date.now(),
      treasureType: 0,
      refToken,
    };
    const signData = this._signJson("queryIncreaseTreasure", data);
    return post(this.host, "/AccessGateway/transIn/queryIncreaseTreasure.json", signData);
  }
}
