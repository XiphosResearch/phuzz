# PHP Audit Fuzz

Feedback from xdebug and PHP error logs is used to generate random and arbitrary input
parameters to a PHP script, the functions which this data passes through collected from
runtime traces and triggers warnings if it gains control over exploitable functions, e.g. 

  * system
  * readfile
  * include
  * fopen

## TODO:

  * strace / dtruss analysis, systemcall control

## Running

### Linux / Ubuntu

	sudo apt-get install php56-cli php56-xdebug

### OSX

    brew install php56 php56-xdebug
