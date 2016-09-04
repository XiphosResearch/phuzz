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
			return parent::offsetGet($k);
		}
		function offsetExists($k) {
			trigger_error("TRACE EXISTS {$this->name} $k");
			return parent::offsetExists($k);
		}
	}
	$vars = ['_GET', '_POST', '_COOKIE', '_SERVER', '_REQUEST'];
	foreach ( compact($vars) AS $K => $V )
	{
		$GLOBALS[$K] = new _TracedArray($K, $V);
	}
	set_time_limit(1);
}

