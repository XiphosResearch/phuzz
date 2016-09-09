# PHP Phuzzer

It uses feedback from xdebug and strace to generate random and arbitrary input
parameters to a PHP script and find code paths which lead to exploitation.


## Running

### Linux / Ubuntu

	sudo apt-get install php56-cli php56-xdebug
	pip install requests
	./phuzz.py

### OSX

    brew install php56 php56-xdebug
    pip install requests
    ./phuzz.py

## Example

The first request is made to analyse which inputs the script uses.

	[Thu Sep  8 17:36:00 2016] 127.0.0.1:36996 [200]: /rce1.php

It then generates random values for the required parameters, and finds all the
PHP and system calls that.

	[Thu Sep  8 17:36:00 2016] 127.0.0.1:36998 [200]: /rce1.php?cmd=SWGAGI55
	<webroot>/rce1.php
		 system ( 'SWGAGI55' )

	syscalls:
		 stat ( "/usr/local/sbin/SWGAGI55", 0x7ffff9f76140 )
		 stat ( "/usr/local/bin/SWGAGI55", 0x7ffff9f76140 )
		 stat ( "/usr/sbin/SWGAGI55", 0x7ffff9f76140 )
		 stat ( "/usr/bin/SWGAGI55", 0x7ffff9f76140 )
		 stat ( "/sbin/SWGAGI55", 0x7ffff9f76140 )
		 stat ( "/bin/SWGAGI55", 0x7ffff9f76140 )
		 stat ( "/usr/games/SWGAGI55", 0x7ffff9f76140 )
		 stat ( "/usr/local/games/SWGAGI55", 0x7ffff9f76140 )
