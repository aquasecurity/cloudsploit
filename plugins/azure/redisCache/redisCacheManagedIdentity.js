var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Redis Cache Managed Identity Enabled',
    category: 'Redis Cache',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that Azure Cache for Redis have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    recommended_action: 'Modify Azure Cache for Redis and add managed identity.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-managed-identity#enable-managed-identity',
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
                
                if (cache.identity){
                    helpers.addResult(results, 0, 'Redis Cache has managed identity enabled', location, cache.id);
                } else {
                    helpers.addResult(results, 2, 'Redis Cache does not have managed identity enabled', location, cache.id);
                } 
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};