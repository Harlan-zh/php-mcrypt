<?php

namespace Mcrypt;

class McryptException extends \Exception
{
    function getMcryptMsg()
    {
        return $this->getMessage();
    }
}
