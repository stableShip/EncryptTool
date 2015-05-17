/**
 * Created with JetBrains WebStorm.
 * User: pankangyu
 * Date: 13-8-7
 * Time: 下午6:02
 */

///<reference path='../DefinitelyTyped/app.d.ts' />
var debug = require("debug")(__filename);
import _ = require("underscore");
var crypto = require('crypto');
var utf8 = require("utf8");

/**
 * 加密工具类
 * 作用: 1) base64加密  2) base64 解密
 */
 class EncryptTool{

    /**
     * base64加密
     * @param str   被加密的字符串
     * @param encoding  加密方式
     * @returns {*}
     */
    static base64_encode(str:any,encoding:string="utf8"):any{
        if(_.isEmpty(str)) return "";
        if(!_.isString(str)) str=str.toString();
        var encodeStr=new Buffer(str,encoding).toString("base64");
        return encodeStr;
      

    }

    /**
     * base64 解密
     * @param decodingStr  被加密的字符串
     * @param encoding     解密类型
     * @returns {*}
     */
    static base64_decode(encodingStr:string,encoding:string="base64"):any{
        if(_.isEmpty(encodingStr)) return "";
        var decodingStr=new Buffer(encodingStr,encoding).toString();
        return decodingStr;
    } 


     /**
      * @fn static aes_encode(data: any): string
      *
      * @brief  aes加密.
      *
      * @author 周捷
      * @date   2014/11/15
      *
      * @param  data    要加密的字符串
      *
      * @return 加密后字符串.
      */

     static aes_encode(data: string): string {
        //使用的加密算法
        var algorithm ='AES-128-ECB';
        //使用的加密字符串
        var key = 'jydasai38hao1616';
        //输入的数据编码
        var inputEncoding = 'utf8';
        //初始化向量
        //输出数据编码
        var outputEncoding = 'base64';
        //创建加密器
        var cipher = crypto.createCipheriv(algorithm, key,"");
        cipher.setAutoPadding(true);
        //更新加密器：对数据进行加密
        var encodingStr = cipher.update(data,inputEncoding,outputEncoding);
        encodingStr += cipher.final(outputEncoding);
        //返回加密后字符串
        return encodingStr;
       
     }


     /**
      * @fn static aes_decode(encodingStr: string): string
      *
      * @brief  aes 解密.
      *
      * @author 周捷
      * @date   2014/11/15
      *
      * @param  encodingStr 要解密的字符串.
      *
      * @return 解密后字符串.
      */

     static aes_decode(encodingStr: string): string {
        //使用的算法
        var algorithm = 'AES-128-ECB';
        //使用的密匙
        var key = 'jydasai38hao1616';
        //输出的格式
        var outputEncoding = 'utf8';
        //输入数据编码
        var inputEncoding = 'base64';
        //创建解密器
        var decipher = crypto.createDecipheriv(algorithm, key,"");
        decipher.setAutoPadding(true);

        //解密数据
        var data = decipher.update(encodingStr,inputEncoding,outputEncoding);
        data += decipher.final(outputEncoding);
        return data;
      

     } 

     /**
      * md5加密
      *
      * @author 周捷
      * @date   2015/2/6
      *
      * @param  {string}    data               需要加密的数据
      * @param  {string}    encoding           'hex'、'binary:二进制'或者'base64'，默认为hex
      *
      * @return 加密后的字符串
      */

     static md5Encode(data: string, encoding: string ="hex"): string {
         var mySign = crypto.createHash('md5').update(utf8.encode(data)).digest(encoding);
         return mySign;
     }
      




}

export=EncryptTool;