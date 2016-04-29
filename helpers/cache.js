var cacher = function(cache, service, command, callback) {
	if (!service.config.region) { service.config.region = 'global'; }

	if (cache[service.config.endpoint] &&
		cache[service.config.endpoint][command] &&
		cache[service.config.endpoint][command][service.config.region]) {
		return callback(null, cache[service.config.endpoint][command][service.config.region]);
	}

	service[command](function(err, data){
		if (!err && data) {
			if (!cache[service.config.endpoint]) { cache[service.config.endpoint] = {}; }
			if (!cache[service.config.endpoint][command]) { cache[service.config.endpoint][command] = {}; }
			cache[service.config.endpoint][command][service.config.region] = data;
		}

		callback(err, data);
	});
}

module.exports = cacher;