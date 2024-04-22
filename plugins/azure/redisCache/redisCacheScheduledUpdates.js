var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Redis Cache Scheduled Updates',
    category: 'Redis Cache',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures that Azure Cache for Redis has scheduled updates enabled.',
    more_info: 'Enabling schedule updates allows you to choose a maintenance window for your cache instance. A maintenance window allows you to control the day(s) and time(s) of a week during which the VM(s) hosting your cache can be updated. Azure Cache for Redis will make a best effort to start and finish updating Redis server software within the specified time window you define.',
    recommended_action: 'Enable schedule updates for Redis Cache.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-administration#update-channel-and-schedule-updates',
    apis: ['redisCaches:listBySubscription', 'patchSchedules:listByRedisCache'],
    realtime_triggers: ['microsoftcache:redis:write','microsoftcache:redis:delete','microsoftcache:redis:patchschedules:write','microsoftcache:redis:patchschedules:delete'],
    
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
                helpers.addResult(results, 0, 'No existing Redis Caches found', location);
                return rcb();
            }

            caches.data.forEach(function(redisCache) {
                if (!redisCache.id) return;
                const patchSchedules = helpers.addSource(cache, source,
                    ['patchSchedules', 'listByRedisCache', location, redisCache.id]);

                if (!patchSchedules || (patchSchedules && patchSchedules.err)) {
                    if (patchSchedules.err && patchSchedules.err.includes('There are no patch schedules found for redis cache')) {
                        helpers.addResult(results, 2, 'Redis Cache does not have scheduled updates enabled', location, redisCache.id);
                    } else {
                        helpers.addResult(results, 3, 'Unable to query Redis Cache scheduled updates ' + helpers.addError(patchSchedules), location, redisCache.id);
                    }
                } else {
                    helpers.addResult(results, 0, 'Redis Cache has scheduled updates enabled', location, redisCache.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};