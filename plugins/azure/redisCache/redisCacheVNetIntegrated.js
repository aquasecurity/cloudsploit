var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Redis Cache VNet Integrated',
    category: 'Redis Cache',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that premium Redis Cache has VNet integrated.',
    more_info: 'Ensuring VNet deployment for Redis Cache provides enhanced security and isolation. When VNet is combined with restricted NSG policies, it helps reducing the risk of data exfiltration.',
    recommended_action: 'Ensure VNet (private access) is integrated for premium Redis Cache.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-network-isolation',
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
                if (!cache.id) continue;

                if (cache.sku && cache.sku.name && cache.sku.name.toLowerCase()!='premium') {
                    helpers.addResult(results, 0, 'VNet Integration is only available for premium tier Redis Caches', location, cache.id);
                } else if (cache.subnetId) {
                    helpers.addResult(results, 0, 'Redis Cache has VNet integrated', location, cache.id);
                } else {
                    helpers.addResult(results, 2, 'Redis Cache does not have VNet integrated', location, cache.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};