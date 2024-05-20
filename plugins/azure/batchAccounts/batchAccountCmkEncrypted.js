var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Batch Account CMK Encrypted',
    category: 'Batch',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that Azure Batch accounts are CMK encrypted.',
    more_info: 'Azure Batch allows you to encrypt data in your accounts using customer-managed keys (CMK) instead of using platform-managed keys, which are enabled by default. Using CMK encryption offers enhanced security and compliance, allowing centralized management and control of encryption keys through Azure Key Vault.',
    recommended_action: 'Enable CMK encryption for all Azure Batch accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/batch/batch-customer-managed-key',
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

                if (batchAccount.encryption && 
                    batchAccount.encryption.keySource && 
                    batchAccount.encryption.keySource.toLowerCase() == 'microsoft.keyvault') {
                    helpers.addResult(results, 0, 'Batch account is encrypted using CMK', location, batchAccount.id);
                } else {
                    helpers.addResult(results, 2, 'Batch account is not encrypted using CMK', location, batchAccount.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};