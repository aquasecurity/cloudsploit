var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Redis Cache Private Endpoint',
    category: 'Redis Cache',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures that Azure Cache for Redis is only accessible through private endpoints.',
    more_info: 'Enabling a private endpoint for Azure Cache for Redis enhances security by isolating the cache from the public internet and providing controlled access within a private network.',
    recommended_action: 'Ensure that Azure Cache for Redis has public network access disabled.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-network-isolation#azure-private-link-recommended',
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
                if (cache.publicNetworkAccess && cache.publicNetworkAccess.toLowerCase() === 'enabled') {
                    helpers.addResult(results, 2, 'Redis Cache is publicly accessible', location, cache.id);
                } else {
                    helpers.addResult(results, 0, 'Redis Cache is only accessible through private endpoints', location, cache.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};