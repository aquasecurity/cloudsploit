const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Cosmos DB Diagnostic Logs',
    category: 'Cosmos DB',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that diagnostic logging is enabled for Azure Cosmos DB accounts.',
    more_info: 'Enabling diagnostic logs for Cosmos DB accounts is crucial to collect resource logs, which provide detailed data about resource operations. It helps to gain valuable insights into resource activity, assisting in monitoring, diagnosing issues, and optimizing the performance of Azure resources.',
    recommended_action: 'Enable diagnostic logging for all Azure Cosmos DB accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/cosmos-db/monitor-resource-logs',
    apis: ['databaseAccounts:list', 'diagnosticSettings:listByDatabaseAccounts'],
    realtime_triggers: ['microsoftdocumentdb:databaseaccounts:write','microsoftdocumentdb:databaseaccounts:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        
        async.each(locations.databaseAccounts, (location, rcb) => {
            var databaseAccounts = helpers.addSource(cache, source,
                ['databaseAccounts', 'list', location]);

            if (!databaseAccounts) return rcb();

            if (databaseAccounts.err || !databaseAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Cosmos DB accounts: ' + helpers.addError(databaseAccounts), location);
                return rcb();
            }

            if (!databaseAccounts.data.length) {
                helpers.addResult(results, 0, 'No Cosmos DB accounts found', location);
                return rcb();
            }


            for (let account of databaseAccounts.data) {
                if (!account.id) continue;

                var diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByDatabaseAccounts', location, account.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query Cosmos DB account diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, account.id);
                    continue;
                }
                
                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);
                if (found) {
                    helpers.addResult(results, 0, 'Cosmos DB account has diagnostic logs enabled', location, account.id);

                } else {
                    helpers.addResult(results, 2, 'Cosmos DB account does not have diagnostic logs enabled' , location, account.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
