var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Batch Account Diagnostic Logs',
    category: 'Batch',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that Batch account has diagnostic logs enabled.',
    more_info: 'Enabling diagnostics logs for Batch account helps to capture failures, security incidents that occurs when network is compromised. This helps identifying potential security threats and recreate activity trails to use for investigation purposes.',
    recommended_action: 'Enable diagnostic logging for all Batch accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/batch/monitor-batch#azure-monitor-resource-logs',
    apis: ['batchAccounts:list','diagnosticSettings:listByBatchAccounts'],
    realtime_triggers: ['microsoftbatch:batchaccounts:write','microsoftbatch:batchaccounts:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.batchAccounts, function(location, rcb){

            var batchAccounts = helpers.addSource(cache, source,
                ['batchAccounts', 'list', location]);

            if (!batchAccounts) return rcb();

            if (batchAccounts.err || !batchAccounts.data) {
                helpers.addResult(results, 3, 'Unable to query for Batch accounts: ' + helpers.addError(batchAccounts), location);
                return rcb();
            }
            if (!batchAccounts.data.length) {
                helpers.addResult(results, 0, 'No existing Batch accounts found', location);
                return rcb();
            }

            for (let batchAccount of batchAccounts.data) { 
                if (!batchAccount.id) continue;

                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByBatchAccounts', location, batchAccount.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for Batch account diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, batchAccount.id);
                    continue;
                }
    
                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);
    
                if (found) {
                    helpers.addResult(results, 0, 'Batch account has diagnostic logs enabled', location, batchAccount.id);
                } else {
                    helpers.addResult(results, 2, 'Batch account does not have diagnostic logs enabled', location, batchAccount.id);
                }    
                
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};