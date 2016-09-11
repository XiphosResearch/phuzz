<?php
if( ! class_exists('__PHUZZ') ) {
	class __PHUZZ extends ArrayObject {
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
class _GET extends __PHUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
class _POST extends __PHUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
class _COOKIE extends __PHUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
class _SERVER extends __PHUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
class _REQUEST extends __PHUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
class _FILES extends __PHUZZ { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
}
date_default_timezone_set('UTC');
set_time_limit(1);
$vars = ['_GET', '_POST', '_COOKIE', '_SERVER', '_REQUEST', '_FILES'];
__PHUZZ::begin_request(json_encode(compact($vars)));
foreach ( compact($vars) AS $K => $V )
{
	$GLOBALS[$K] = new $K($K, $V);
}

