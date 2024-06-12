var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Batch Account AAD Auth Enabled',
    category: 'Batch',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that Batch account has AAD authentication mode enabled.',
    more_info: 'Enabling AAD Authentication for your Azure Batch Account ensures enhanced security by utilizing a robust authentication method required for several security-related features. By restricting the service API authentication to Microsoft Entra ID, you prevent access through less secure shared key methods, thereby safeguarding your batch resources from unauthorized access.',
    recommended_action: 'Enable diagnostic logging for all Batch accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/batch/security-best-practices#batch-account-authentication',
    apis: ['batchAccounts:list'],
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
                
                let found = false;
                if (batchAccount.allowedAuthenticationModes &&
                    batchAccount.allowedAuthenticationModes.length) {
                    batchAccount.allowedAuthenticationModes.forEach(mode => {
                        if (mode.toUpperCase() == 'AAD') {
                            found = true;
                        }
                    });

                    if (found) {
                        helpers.addResult(results, 0, 'Batch account is configured with AAD Authentication', location, batchAccount.id);
                    } else {
                        helpers.addResult(results, 2, 'Batch account is not configured with AAD Authentication', location, batchAccount.id);
                    }
                } else {
                    helpers.addResult(results, 2, 'Batch account is not configured with AAD Authentication', location, batchAccount.id);
                }
            }
            
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};