var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Minimum TLS Version',
    category: 'Redis Cache',
    domain: 'Databases',
    description: 'Ensures that Azure Cache for Redis is using the latest TLS version.',
    more_info: 'TLS versions 1.0 and 1.1 are known to be susceptible to attacks, and to have other Common Vulnerabilities and Exposures (CVE) weaknesses.So there\'s an industry- wide push toward the exclusive use of Transport Layer Security(TLS) version 1.2 or later.',
    recommended_action: 'Ensure that Azure cache for Redis is using the latest TLS version',
    link: 'https://docs.microsoft.com/en-us/azure/azure-cache-for-redis/cache-remove-tls-10-11',
    apis: ['redisCaches:listBySubscription'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.redisCaches, function(location, rcb) {
            const caches = helpers.addSource(cache, source,
                ['redisCaches', 'listBySubscription', location]);

            if (!caches) return rcb();

            if (caches.err || !caches.data) {
                helpers.addResult(results, 3, 'Unable to query Redis Caches: ' + helpers.addError(caches), location);
                return rcb();
            }

            if (!caches.data.length) {
                helpers.addResult(results, 0, 'No Redis Caches found', location);
                return rcb();
            }

            for (let cache of caches.data) {
                if (!cache.minimumTlsVersion) {
                    helpers.addResult(results, 2, 'Redis Cache is using the default TLS Version', location, cache.id);
                } else if (cache.minimumTlsVersion && (cache.minimumTlsVersion === '1.0' || cache.minimumTlsVersion === '1.1')) {
                    helpers.addResult(results, 2, 'Redis Cache is not using the latest TLS Version', location, cache.id);
                } else {
                    helpers.addResult(results, 0, 'Redis Cache is using the latest TLS Version', location, cache.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};