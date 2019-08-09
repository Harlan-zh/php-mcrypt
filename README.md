php-mcrypt - Library
===

"PHP 3DES加密解密类库"

Use Composer Install
======
```shell
composer require harlan-zh/php-mcrypt
```

Usage:
======

Example : (3Des Encrypt and Decrypt)
```php
define('MCRYPT_ROOT', dirname(__FILE__));

// 包含自动加载文件
require MCRYPT_ROOT . "/autoload.php";

use Mcrypt\DesEncryptor;
use Mcrypt\StringPadding;
use Mcrypt\McryptException;

$key = "qwert!@#^*";
// $iv = "bibiblili";
$iv = "";
$str = 'ILoveMe';

try {
    // 实例化加密类
    $desEncryptor = new DesEncryptor($key, $iv);

    // 设置加密的参数
    $desEncryptor->setMode(MCRYPT_MODE_CBC);
    $desEncryptor->setPaddingMode(StringPadding::pkcs7Padding);

    // 将加密结果放在
    $encrypt = base64_encode($desEncryptor->encrypt3DES($str));
    $decrypt = $desEncryptor->decrypt3DES(base64_decode($encrypt));    $encrypt)); = $desEncryptor->decrypt3DES(base64_decode($encrypt));
} catch (McryptException $e) {
    print $e->getMcryptMsg();
    exit;
}

echo "原文：${str}" . PHP_EOL;     // 需要加密的字符串
echo "加密：${encrypt}" . PHP_EOL; // 加密结果   
echo "解密：${decrypt}";           // 将加密字符转化明文

//result：
//    '原文：ILoveMe'
//    '加密：wMIpQDwfDXI='
//    '解密：ILoveMe'
```
