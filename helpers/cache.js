var async = require('async');

var MAX_RETRIES = 15;		// Maximum times to retry calling the AWS API
var MAX_TIMEOUT = 20000;	// How long to wait for each AWS response before failing

var cacher = function(cache, service, command, callback) {
	if (!service.config.region) { service.config.region = 'global'; }

	var endpoint = service.config.endpoint;
	var region = service.config.region;

	if (cache[endpoint] &&
		cache[endpoint][command] &&
		cache[endpoint][command][region]) {

		if (cache[endpoint][command][region].data) {
			return callback(null, cache[endpoint][command][region].data);
		}

		if (cache[endpoint][command][region].err) {
			return callback(cache[endpoint][command][region].err);
		}

		if (cache[endpoint][command][region].calling) {
			cache[endpoint][command][region].callbacks.push(callback);
		}
	}

	if (!cache[endpoint]) { cache[endpoint] = {}; }
	if (!cache[endpoint][command]) { cache[endpoint][command] = {}; }
	
	if (!cache[endpoint][command][region]) {
		cache[endpoint][command][region] = {
			calling: true,
			callbacks: [callback]
		};

		var cbCalled = false;
		var tryNum = 0;

		async.retry(MAX_RETRIES, async.timeout(function(cb){
			service[command](function(err, data){
				if (!cbCalled) cb(err,data);
			});
		}, MAX_TIMEOUT), function(err, data) {
			cbCalled = true;

			if (!err && data) {
				cache[endpoint][command][region].data = data;

				for (c in cache[endpoint][command][region].callbacks) {
					cache[endpoint][command][region].callbacks[c](null, data);
				}
			} else {
				cache[endpoint][command][region].err = (err || 'No data in response');

				for (c in cache[endpoint][command][region].callbacks) {
					cache[endpoint][command][region].callbacks[c]((err || 'No data in response'));
				}
			}

			cache[endpoint][command][region].callbacks = [];
		});
	}
}

module.exports = cacher;