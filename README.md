# PHP Hardening Phuzzer

[![Build Status](https://drone.io/github.com/HarryR/phuzz/status.png)](https://drone.io/github.com/HarryR/phuzz/latest)

It uses feedback from xdebug and strace to generate random and arbitrary input
parameters to a PHP script and find code paths which lead to exploitation.

## TODO

 * Make it suck less
 * Analysis of collected Phuzz cases/traces, automatic exploit generation
 * [dtrace](https://blogs.oracle.com/opal/entry/tracing_silex_from_php_to) and [systemtap](http://php.net/manual/en/features.dtrace.systemtap.php) support


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

## Installation

### Debian / Ubuntu

	sudo apt-get install php5.6-cli php-xdebug
	pip install -r requirements.txt
	python -mphuzz

### OSX

    brew install php56 php56-xdebug
    pip install -r requirements.txt
    python -mphuzz

### Microsoft Windows (XP or above)

  * Click on `Start` button (bottom left hand corner of screen)
  * Click `My Computer`
  * Navigate to `C:\Program Files\Microsoft Internet Explorer Professional Edition 2016\`
  * Locate `iexplore.exe`, you may have to use the scroll bars
  * Click on it... twice, quickly!
  * Wait until new window opens up
  * Find the white bar with `http://worldwideweb.msn.com/en-US/` in it
  * Click the text, just once!
  * Press the `Ctrl` and `A` buttons on your keyboard, together, at the same time.
  * Type in `www.google.com`
  * Wait until your computer starts responding again
  * Type in `Self immoliation techniques for beginners`
  * Press the `Search` button
  * Follow instructions until warm throughout

TL;DR any ideas on porting this to Win32 API?