var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Batch Account AAD Auth Enabled',
    category: 'Batch',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that Batch account has Azure Active Directory (AAD) authentication mode enabled.',
    more_info: 'Enabling Azure Active Directory (AAD) authentication for Batch account ensures enhanced security by restricting the service API authentication to Microsoft Entra ID that prevents access through less secure shared key methods, thereby safeguarding batch resources from unauthorized access.',
    recommended_action: 'Enable diagnostic logging for all Batch accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/batch/batch-aad-auth',
    apis: ['batchAccounts:list'],
    realtime_triggers: ['microsoftbatch:batchaccounts:write', 'microsoftbatch:batchaccounts:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.batchAccounts, function(location, rcb) {

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

                let found = batchAccount.allowedAuthenticationModes && 
                            batchAccount.allowedAuthenticationModes.length?
                    batchAccount.allowedAuthenticationModes.some(mode => mode.toUpperCase() === 'AAD') : false;

                if (found) {
                    helpers.addResult(results, 0, 'Batch account has Active Directory authentication enabled', location, batchAccount.id);
                } else {
                    helpers.addResult(results, 2, 'Batch account does not have Active Directory authentication enabled', location, batchAccount.id);
                }

            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};