var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Batch Account Has Tags',
    category: 'Batch',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensures that Batch account have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Batch Account and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources-portal',
    apis: ['batchAccounts:list','diagnosticSettings:listByBatchAccounts'],
    realtime_triggers: ['microsoftbatch:batchaccounts:write','microsoftbatch:batchaccounts:delete'],

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
        
                if (batchAccount.tags && Object.entries(batchAccount.tags).length > 0 ) {
                    helpers.addResult(results, 0, 'Batch account has tags associated', location, batchAccount.id);
                } else {
                    helpers.addResult(results, 2, 'Batch account does not have tags associated', location, batchAccount.id);
                }    
                
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};