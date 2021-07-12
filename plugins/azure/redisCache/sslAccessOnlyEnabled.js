var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SSL Access Only Enabled',
    category: 'Redis Cache',
    description: 'Ensures that SSL Access Only feature is enabled for Azure Redis Caches.',
    more_info: 'SSL Access only should be enabled for Azure Cache for Redis to meet the organization\'s security compliance requirements.',
    recommended_action: 'Enable SSL Access Only for Azure cache for Redis',
    link: 'https://docs.microsoft.com/en-us/azure/azure-cache-for-redis/cache-management-faq#when-should-i-enable-the-non-tlsssl-port-for-connecting-to-redis',
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
                if (cache.enableNonSslPort) {
                    helpers.addResult(results, 2, 'SSL Access Only is not enabled for Azure Cache for Redis', location, cache.id);
                } else {
                    helpers.addResult(results, 0, 'SSL Access Only is enabled for Azure Cache for Redis', location, cache.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
