var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Redis Cache Diagnostic Logs Enabled',
    category: 'Redis Cache',
    domain: 'Databases',
    description: 'Ensures diagnostic logging is enabled for Azure Cache for Redis.',
    more_info: 'Enabling diagnostic setting helps you understand who is connecting to your caches and the timestamp of those connections. The log data could be used to identify the scope of a security breach and for security auditing purposes.',
    recommended_action: 'Enable diagnostic logging for all Redis Caches.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-monitor-diagnostic-settings?tabs=basic-standard-premium',
    apis: ['redisCaches:listBySubscription','diagnosticSettings:listByRedisCache'],

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

                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByRedisCache', location, redisCache.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, 'Unable to query Redis Cache diagnostics settings: ' + helpers.addError(diagnosticSettings), location, redisCache.id);
                } else {
                    var redisCacheDiagnosticLogs = false;
                    diagnosticSettings.data.forEach(setting => {
                        var logs = setting.logs;
                        if (logs.some(log => (log.categoryGroup === 'audit' || log.categoryGroup === 'allLogs' || log.category === 'ConnectedClientList') && log.enabled)) {
                            redisCacheDiagnosticLogs = true;
                        }
                    });

                    if (redisCacheDiagnosticLogs) {
                        helpers.addResult(results, 0, 'Redis Cache has diagnostic logs enabled', location, redisCache.id);
                    } else {
                        helpers.addResult(results, 2, 'Redis Cache does not have diagnostic logs enabled', location, redisCache.id);
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};