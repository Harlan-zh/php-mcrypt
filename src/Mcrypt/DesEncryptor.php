<?php

namespace Mcrypt;

use Mcrypt\StringPadding;
use Mcrypt\McryptException;

/**
 * 3DES加解密类
 *
 * 支持加密类型
 *   1. ecb, 2. cbc, 3. cfb, 4. ofb, 5. nofb
 * @Author: 胡志立
 * @version: v1.0
 * 2019年8月09日
 */
class DesEncryptor
{
    /**
     * 密钥
     * @var string
     */
    private $key;

    /**
     * 密钥偏移量
     * @var string
     */
    private $iv;

    /**
     * 算法模式
     * @var int
     */
    private $mode = '';

    /**
     * 全部算法模式
     * @var array
     */
    private $modeAll = array(
        MCRYPT_MODE_ECB,
        MCRYPT_MODE_CBC,
        MCRYPT_MODE_CFB,
        MCRYPT_MODE_OFB,
        MCRYPT_MODE_NOFB
    );

    /**
     * 字符串偏移方式
     * @var int
     */
    private $paddingMode = StringPadding::zeroPadding;

    /**
     * 构造函数
     * @param string $key 密钥
     * @param string $iv 密钥偏移量
     */
    public function __construct($key, $iv)
    {
        $this->key = $key;
        $this->iv = $iv;
    }

    /**
     * 设置算法模式
     * @param int $keySize 设置密钥长度，可选择的值有
     * MCRYPT_MODE_CBC 
     */
    public function setMode($mode)
    {
        $this->mode = $mode;
    }

    /**
     * 设置补码方式
     * @param int $keySize 设置密钥长度
     */
    public function setPaddingMode($paddingMode)
    {
        $this->paddingMode = $paddingMode;
    }


    /**
     * 对字符串进行3DES加密
     * @param $str string 加密明文
     * @return string
     * @throws \Mcrypt\McryptException
     */
    public function encrypt3DES($str)
    {
        if (!in_array($this->mode, $this->modeAll, true)) {
            throw new McryptException("加密模式不支持！");
        }
        $td = mcrypt_module_open(MCRYPT_3DES, "", $this->mode, "");
        if ($td === false) {
            throw new McryptException("打开算法和模式对应的模块失败！");
        }

        // 检查加密key的长度是否符合算法要求
        // 如果密钥大于当前的算法模式的最大长度则截取最大长度的密钥(0 ~ keyMaxSize)
        $keyMaxSize = mcrypt_enc_get_key_size($td);
        if (strlen($this->key) > $keyMaxSize) {
            $key = StringPadding::padding($this->key, $keyMaxSize, '\0');
        } else {
            $key = $this->key;
        }

        //检查加密iv的长度是否符合算法要求
        $ivMaxSize = mcrypt_enc_get_iv_size($td);
        if (!empty($this->iv)) {

            if (strlen($this->iv) > $ivMaxSize) {
                throw new McryptException("IV长度不符合规范，必须小于{$ivMaxSize}字节！");
            }
            $iv = StringPadding::padding($this->iv, $ivMaxSize, '\0');
        } else {
            $iv = ($this->mode === MCRYPT_MODE_ECB) ? mcrypt_create_iv($ivMaxSize, MCRYPT_RAND) : StringPadding::padding($this->iv, $ivMaxSize, '\0');
        }

        //初始化加密所需的缓冲区
        if (mcrypt_generic_init($td, $key, $iv) !== 0) {
            throw new McryptException("初始化加密所需的缓冲区失败！");
        }

        //对$str进行分组处理
        $blockSize =  mcrypt_enc_get_block_size($td);
        switch ($this->paddingMode) {
            case StringPadding::pkcs5Padding:
                $str = StringPadding::pkcs5Padding($str);
                break;
            case StringPadding::pkcs7Padding:
                $str = StringPadding::pkcs7Padding($str, $blockSize);
                break;
            default:
                $str = StringPadding::zeroPadding($str, $blockSize);
        }

        $result = mcrypt_generic($td, $str);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return $result;
    }

    /**
     * 对加密的字符串进行3DES解密
     * @param string 要解密的字符串
     * @return mixed 加密成功返回加密后的字符串，否则返回false
     */
    public function decrypt3DES($str)
    {
        if (!in_array($this->mode, $this->modeAll, true)) {
            throw new McryptException("加密模式不支持！");
        }
        $td = mcrypt_module_open(MCRYPT_3DES, "", $this->mode, "");
        if ($td === false) {
            throw new McryptException("打开算法和模式对应的模块失败！");
        }


        $keyMaxSize = mcrypt_enc_get_key_size($td);
        if (strlen($this->key) > $keyMaxSize) {
            $key = StringPadding::padding($this->key, $keyMaxSize, '\0');
        } else {
            $key = $this->key;
        }


        $ivMaxSize = mcrypt_enc_get_iv_size($td);
        if (!empty($this->iv)) {

            if (strlen($this->iv) > $ivMaxSize) {
                throw new McryptException("IV长度不符合规范，必须小于{$ivMaxSize}字节！");
            }
            $iv = StringPadding::padding($this->iv, $ivMaxSize, '\0');
        } else {
            $iv = ($this->mode === MCRYPT_MODE_ECB) ? mcrypt_create_iv($ivMaxSize, MCRYPT_DEV_URANDOM) : StringPadding::padding($this->iv, $ivMaxSize, '\0');
        }


        if (mcrypt_generic_init($td, $key, $iv) !== 0) {
            throw new McryptException("初始化加密所需的缓冲区失败！");
        }

        $result = mdecrypt_generic($td, $str);
        $blockSize =  mcrypt_enc_get_block_size($td);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        switch ($this->paddingMode) {
            case StringPadding::pkcs5Padding:
                $result = StringPadding::unPkcs5Padding($result);
                break;
            case StringPadding::pkcs7Padding:
                $result = StringPadding::unPkcs7Padding($result, $blockSize);
                break;
            default:
                $result = rtrim($result, chr(0));
        }

        return $result;
    }
}
