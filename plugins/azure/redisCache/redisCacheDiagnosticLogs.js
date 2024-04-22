var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Redis Cache Diagnostic Logs Enabled',
    category: 'Redis Cache',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures diagnostic logging is enabled for Azure Cache for Redis.',
    more_info: 'Enabling diagnostic setting helps you understand who is connecting to your caches and the timestamp of those connections. The log data could be used to identify the scope of a security breach and for security auditing purposes.',
    recommended_action: 'Enable diagnostic logging for all Redis Caches.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-monitor-diagnostic-settings?tabs=basic-standard-premium',
    apis: ['redisCaches:listBySubscription', 'diagnosticSettings:listByRedisCache'],
    settings: {
        diagnostic_logs: {
            name: 'Diagnostic Logs Enabled',
            description: 'Comma separated list of diagnostic logs that should be enabled at minimum i.e. ConnectedClientList. If you have enabled allLogs, then resource produces pass result. If you only want to check if logging is enabled or not, irrespecitve of log type, then add * in setting.',
            regex: '^.*$',
            default: 'ConnectedClientList'
        },
    },
    realtime_triggers: ['microsoftcache:redis:write','microsoftcache:redis:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        var config = {
            diagnostic_logs: settings.diagnostic_logs || this.settings.diagnostic_logs.default,
        };

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
                    var found = true;
                    var missingLogs = [];
                    if (config.diagnostic_logs == '*') {
                        found = diagnosticSettings.data.some(ds => ds.logs && ds.logs.length);
                    } else {
                        config.diagnostic_logs = config.diagnostic_logs.replace(/\s/g, '');
                        missingLogs = config.diagnostic_logs.toLowerCase().split(',');
                        diagnosticSettings.data.forEach(settings => {
                            const logs = settings.logs;
                            missingLogs = missingLogs.filter(requiredCategory =>
                                !logs.some(log => (log.category && log.category.toLowerCase() === requiredCategory && log.enabled) || log.categoryGroup === 'allLogs' && log.enabled)
                            );
                        });

                    }
                    if (!missingLogs.length && found) {
                        helpers.addResult(results, 0, 'Redis Cache has diagnostic logs enabled', location, redisCache.id);
                    } else {
                        helpers.addResult(results, 2, `Redis Cache does not have diagnostic logs enabled ${missingLogs.length? `for following: ${missingLogs}`: ''}`, location, redisCache.id);
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