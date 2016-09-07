# PHP Phuzzer

It uses feedback from xdebug to generate random and arbitrary input
parameters to a PHP script and find code paths which lead to exploitation:

## TODO:

  * strace / dtruss analysis, systemcall control

## Running

### Linux / Ubuntu

	sudo apt-get install php56-cli php56-xdebug

### OSX

    brew install php56 php56-xdebug
