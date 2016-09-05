<?php
if( ! class_exists('_TracedArray') ) {	
	date_default_timezone_set('UTC');
	class _TracedArray extends ArrayObject {
		protected $name;
		function __construct($name, $data) {
			$this->name = $name;
			parent::__construct($data);
		}
		function offsetGet($k) {
			trigger_error("TRACE GET {$this->name} $k");
			$val = parent::offsetGet($k);
			if( is_array($val) ) {
				$name = get_called_class();
				return new $name($name."['$k']", $val);
			}
			return $val;
		}
		function offsetExists($k) {
			trigger_error("TRACE EXISTS {$this->name} $k");
			return parent::offsetExists($k);
		}
	}
	class _GET extends _TracedArray { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
	class _POST extends _TracedArray { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
	class _COOKIE extends _TracedArray { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
	class _SERVER extends _TracedArray { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
	class _REQUEST extends _TracedArray { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
	class _FILES extends _TracedArray { function offsetGet($k) { return parent::offsetGet($k); } function offsetExists($k) { return parent::offsetExists($k); } }
	$vars = ['_GET', '_POST', '_COOKIE', '_SERVER', '_REQUEST', '_FILES'];
	foreach ( compact($vars) AS $K => $V )
	{
		$GLOBALS[$K] = new $K($K, $V);
	}
	set_time_limit(1);
}

