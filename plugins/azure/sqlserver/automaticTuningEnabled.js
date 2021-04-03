var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Automatic Tuning Enabled',
    category: 'SQL Server',
    description: 'Ensures Microsoft Azure SQL Servers have Automatic Tuning configured.',
    more_info: 'Automatic tuning is a fully managed intelligent performance service that uses built-in intelligence to continuously monitor queries executed on a database, and it automatically improves their performance.',
    recommended_action: 'On SQL Server overview page, select Automatic Tuning under Intelligent Performance section select Revert to Defaults to let the database server to inherit the automatic tuning settings from Azure Defaults.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-sql/database/automatic-tuning-overview',
    apis: ['servers:listSql', 'tuningConfig:get'],

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
                    ['tuningConfig', 'get', location, server.id]);

                if (!configs || configs.err || !configs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for SQL Server Atomatic Tuning Configurations: ' + helpers.addError(servers), location);
                    return scb();
                }

                const config = configs.data.options;
                if (!config) {
                    helpers.addResult(results, 2,
                        'No Automatic Tuning Configurations found for SQL Server', location);
                    return scb();
                }

                if (config.createIndex && config.dropIndex && config.forceLastGoodPlan &&
                    config.createIndex.reasonDesc && config.dropIndex.reasonDesc && config.forceLastGoodPlan.reasonDesc &&
                    config.createIndex.reasonDesc.toLowerCase() === 'autoconfigured' &&
                    config.dropIndex.reasonDesc.toLowerCase() === 'autoconfigured' &&
                    config.forceLastGoodPlan.reasonDesc.toLowerCase() === 'autoconfigured') {
                    helpers.addResult(results, 0,
                        'SQL Server is configured to use Azure Default Automatic Tuning settings.', location);
                } else {
                    helpers.addResult(results, 2,
                        'SQL Server is not configured to use Azure Default Automatic Tuning settings.', location);
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