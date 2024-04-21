var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Redis Version',
    category: 'Redis Cache',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures that Azure Cache for Redis is using the latest redis version.',
    more_info: 'Using the latest Redis Version ensures access to the latest features, improvements, and security patches, enhancing performance and reducing vulnerabilities.',
    recommended_action: 'Ensure that Azure cache for Redis is using the latest version',
    link: 'https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-overview#redis-versions',
    apis: ['redisCaches:listBySubscription'],
    realtime_triggers: ['microsoftcache:redis:write','microsoftcache:redis:delete'],

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
                if (!cache.id || !cache.redisVersion) return;
              
                let version = parseFloat(cache.redisVersion);
                if (version && version >= 6) {
                    helpers.addResult(results, 0, 'Redis Cache is using the latest redis version', location, cache.id);
                } else {
                    helpers.addResult(results, 2, 'Redis Cache is not using the latest redis version', location, cache.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};