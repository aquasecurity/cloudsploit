var CACHE = {};

var cache = function(service, command, callback) {
	if (!service.config.region) { service.config.region = 'global'; }

	if (CACHE[service.config.endpoint] &&
		CACHE[service.config.endpoint][command] &&
		CACHE[service.config.endpoint][command][service.config.region]) {
		return callback(null, CACHE[service.config.endpoint][command][service.config.region]);
	}

	service[command](function(err, data){
		if (!err && data) {
			if (!CACHE[service.config.endpoint]) { CACHE[service.config.endpoint] = {}; }
			if (!CACHE[service.config.endpoint][command]) { CACHE[service.config.endpoint][command] = {}; }
			CACHE[service.config.endpoint][command][service.config.region] = data;
		}

		callback(err, data);
	});
}

module.exports = cache;