<?php
if( ! class_exists('_PHPAUDFUZZ') ) {	
	class _PHPAUDFUZZ extends ArrayObject {
		protected $name;
		function __construct($name, $data) {
			$this->name = $name;
			parent::__construct($data);
		}
		function offsetGet($k) {
			trigger_error("TRACE GET {$this->name} $k");
			if( isset($this[$k]) ) {				
				$val = parent::offsetGet($k);
				if( is_array($val) ) {
					$name = get_called_class();
					return new $name($name."['$k']", $val);
				}
				return $val;
			}
		}
		function offsetExists($k) {
			trigger_error("TRACE EXISTS {$this->name} $k");
			return parent::offsetExists($k);
		}
		static function begin_request ($vars) {
			//trigger_error("TRACE BEGIN $vars");
		}
	}
}
date_default_timezone_set('UTC');
set_time_limit(1);
$vars = ['_GET', '_POST', '_COOKIE', '_SERVER', '_REQUEST', '_FILES'];
_PHPAUDFUZZ::begin_request(json_encode(compact($vars)));
class _GET extends _PHPAUDFUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
class _POST extends _PHPAUDFUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
class _COOKIE extends _PHPAUDFUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
class _SERVER extends _PHPAUDFUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
class _REQUEST extends _PHPAUDFUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
class _FILES extends _PHPAUDFUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }	
foreach ( compact($vars) AS $K => $V )
{
	$GLOBALS[$K] = new $K($K, $V);
}

