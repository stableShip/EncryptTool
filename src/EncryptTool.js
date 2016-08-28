'use strict';

var _ = require("lodash");
var crypto = require('crypto');
var config = require("../configs");
var ursa = require("ursa");
var read = require("co-read");
var co = require("co");
var fs = require("fs");

/**
 * 加密工具类
 */
class EncryptTool {

    /**
     * base64加密
     * @param str   被加密的字符串
     * @param encoding  字符串编码
     * @returns {*}
     */
    static base64Encode(str, encoding) {
        if (_.isEmpty(str)) {
            return "";
        }
        encoding = encoding || "utf8"
        if (!_.isString(str)) str = str.toString();
        var encodeStr = new Buffer(str, encoding).toString("base64");
        return encodeStr;
    }

    /**
     * base64 解密
     * @param decodingStr  被加密的字符串
     * @param encoding     字符串编码
     * @returns {*}
     */
    static base64Decode(encodingStr, encoding) {
        encoding = encoding || "base64";
        if (_.isEmpty(encodingStr)) return "";
        var decodingStr = new Buffer(encodingStr, encoding).toString();
        return decodingStr;
    }


    /**
     * @fn static aes_encode(data): string
     * @brief  aes加密.
     * @param  data    要加密的字符串
     * @return 加密后字符串.
     */

    static aesEncode(data, encodekey) {
        //使用的加密算法
        var algorithm = 'AES-256-ECB';
        //使用的加密字符串
        var key = crypto.createHash("sha256").update(encodekey).digest();
        //输入的数据编码
        var inputEncoding = 'utf8';
        //初始化向量
        //输出数据编码
        var outputEncoding = 'base64';
        //创建加密器
        var cipher = crypto.createCipheriv(algorithm, key, "");
        cipher.setAutoPadding(true);
        //更新加密器：对数据进行加密
        var encodingStr = cipher.update(data, inputEncoding, outputEncoding);
        encodingStr += cipher.final(outputEncoding);
        //返回加密后字符串
        return encodingStr;

    }


    /**
     * @fn static aes_decode(encodingStr: string): string
     * @brief  aes 解密.
     * @param  encodingStr 要解密的字符串.
     * @return 解密后字符串.
     */

    static aesDecode(decodeKey, encodingStr) {
        //使用的算法
        var algorithm = 'AES-256-ECB';
        var key = crypto.createHash("sha256").update(decodeKey).digest();
        //输出的格式
        var outputEncoding = 'utf8';
        //输入数据编码
        var inputEncoding = 'base64';
        //创建解密器
        var decipher = crypto.createDecipheriv(algorithm, key, "");
        decipher.setAutoPadding(true);

        //解密数据
        var data = decipher.update(encodingStr, inputEncoding, outputEncoding);
        data += decipher.final(outputEncoding);
        return data;
    }


    /**
     * @fn static rsaPrivateDecode(encodingStr: string, privateKey: string): string
     * @brief  rsa 私钥解密.
     * @param  encodingStr 要解密的字符串.
     * @param  privateKey 私钥字符串.可选
     * @return 解密后字符串.
     */
    static rsaPrivateDecode(encodingStr, privateKey) {
        return co(function* () {
            if(!privateKey) {
                privateKey = yield config.getPrivateKey();
            }
            var key = ursa.createPrivateKey(privateKey);
            //输出的格式
            var outputEncoding = 'utf8';
            //输入数据编码
            var inputEncoding = 'base64';
            //解密数据
            var data = key.decrypt(encodingStr, inputEncoding, outputEncoding, ursa.RSA_PKCS1_OAEP_PADDING);

            return data
        })
    }

    /**
     * @fn static rsaPublicEncode(dataStr: string, privateKey: string): string
     * @brief  rsa 公钥加密.
     * @param  dataStr 要加密的字符串.
     * @param  privateKey 私钥字符串.可选
     * @return 解密后字符串.
     */
    static rsaPublicEncode(dataStr, publicKey) {
        return co(function* () {
            if(!publicKey) {
                publicKey = yield config.getPublicKey();
            }
            var key = ursa.createPublicKey(publicKey);
            //输出的格式
            var outputEncoding = 'base64';
            //输入数据编码
            var inputEncoding = 'utf8';
            //解密数据
            var data = key.encrypt(dataStr, inputEncoding, outputEncoding, ursa.RSA_PKCS1_OAEP_PADDING);

            return data
        })
    }

    /**
     * @fn static createFileSha1sum(filePath: string): string
     * @brief  产生文件sha1校验值
     * @param  filePath 文件地址
     * @return sha1校验值.
     */
    static createFileSha1sum(filePath) {
        return co(function* () {
            // the file you want to get the hash
            var fd = fs.createReadStream(filePath);
            var hash = crypto.createHash('sha1');
            var buf;
            while (buf = yield read(fd)) {
                hash.update(buf);
            }
            var sha1 = hash.digest("hex");
            return sha1;
        });
    }

    /**
     * md5加密
     * @param str   被加密的字符串
     * @param encoding  字符串编码
     * @returns {*}
     */
    static md5Encode(str, encoding){
        if (_.isEmpty(str)) {
            return "";
        }
        var hash = crypto.createHash('md5');
        hash.update(str)
        var encodeStr = hash.digest('hex');
        return encodeStr;
    }
}

module.exports = EncryptTool;