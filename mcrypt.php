<?php

define('MCRYPT_ROOT', dirname(__FILE__));

require MCRYPT_ROOT . "/autoload.php";

use Mcrypt\DesEncryptor;
use Mcrypt\StringPadding;
use Mcrypt\McryptException;

$key = '1oneSign!@#^*';
// $iv = "1one8888";
$iv = "";
$str = 'ILoveMe';

try {
    $desEncryptor = new DesEncryptor($key, $iv);

    $desEncryptor->setMode(MCRYPT_MODE_CBC);
    $desEncryptor->setPaddingMode(StringPadding::pkcs7Padding);

    $encrypt = base64_encode($desEncryptor->encrypt3DES($str));
    $unEncrypt = $desEncryptor->decrypt3DES(base64_decode($encrypt));
} catch (McryptException $e) {
    print $e->getMcryptMsg();
    exit;
}

echo "原文：${str}" . PHP_EOL;
echo "加密：${encrypt}" . PHP_EOL;
echo "解密：${unEncrypt}";
