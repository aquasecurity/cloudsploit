var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Automatic Tuning Enabled',
    category: 'SQL Server',
    domain: 'Databases',
    description: 'Ensures that Microsoft Azure SQL servers have automatic tuning configured.',
    more_info: 'Automatic tuning is a fully managed intelligent performance service that uses built-in intelligence to continuously monitor queries executed on a database, and it automatically improves their performance.',
    recommended_action: 'Modify SQL server to enable automatic tuning',
    link: 'https://docs.microsoft.com/en-us/azure/azure-sql/database/automatic-tuning-overview',
    apis: ['servers:listSql', 'serverAutomaticTuning:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {
            var servers = helpers.addSource(cache, source,
                ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No SQL servers found', location);
                return rcb();
            }

            async.each(servers.data, function(server, scb) {
                const configs = helpers.addSource(cache, source,
                    ['serverAutomaticTuning', 'get', location, server.id]);

                if (!configs || configs.err || !configs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for SQL server automatic tuning configurations: ' + helpers.addError(servers), location);
                    return scb();
                }

                const config = configs.data.options;
                if (!config) {
                    helpers.addResult(results, 2,
                        'No automatic tuning configurations found for SQL server', location, server.id);
                    return scb();
                }

                let configuredFlagsCount = 0;

                if (config.createIndex && config.createIndex.reasonDesc &&
                    config.createIndex.reasonDesc.toLowerCase() === 'autoconfigured') {
                    configuredFlagsCount++;
                }

                if (config.dropIndex && config.dropIndex.reasonDesc &&
                    config.dropIndex.reasonDesc.toLowerCase() === 'autoconfigured') {
                    configuredFlagsCount++;
                }

                if (config.forceLastGoodPlan && config.forceLastGoodPlan.reasonDesc &&
                    config.forceLastGoodPlan.reasonDesc.toLowerCase() === 'autoconfigured') {
                    configuredFlagsCount++;
                }

                if (configuredFlagsCount === 3) {
                    helpers.addResult(results, 0,
                        'SQL server has Azure automatic tuning enabled', location, server.id);
                } else {
                    helpers.addResult(results, 2,
                        'SQL server does not have Azure automatic tuning enabled', location, server.id);
                }
                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};