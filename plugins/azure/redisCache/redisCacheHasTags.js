var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Redis Cache Has Tags',
    category: 'Redis Cache',
    domain: 'Databases',
    description: 'Ensures that Azure Cache for Redis have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Azure Cache for Redis and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
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
                if (!cache.id) continue;
                
                if (cache.tags && Object.entries(cache.tags).length > 0){
                    helpers.addResult(results, 0, 'Redis Cache has tags associated', location, cache.id);
                } else {
                    helpers.addResult(results, 2, 'Redis Cache does not have tags associated', location, cache.id);
                } 
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};