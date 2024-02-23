var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Infrastructure Encryption Enabled',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'High',
    description: 'Ensure that Azure Storage Accounts have infrastructure encryption enabled.',
    more_info: 'Azure Storage automatically encrypts all data in a storage account at the service level using 256-bit AES encryption. But customers who require higher levels of assurance that their data is secure can also enable 256-bit AES encryption at the Azure Storage infrastructure level for double encryption. Double encryption of Azure Storage data protects against a scenario where one of the encryption algorithms or keys may be compromised. In this scenario, the additional layer of encryption continues to protect your data.',
    recommended_action: 'Delete storage account and create new storage account with infrastructure encryption enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/infrastructure-encryption-enable',
    apis: ['storageAccounts:list'],
    realtime_triggers: ['microsoftstorage:storageaccounts:write', 'microsoftstorage:storageaccounts:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb) {
            var storageAccount = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccount) return rcb();

            if (storageAccount.err || !storageAccount.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccount), location);
                return rcb();
            }

            if (!storageAccount.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            }

            for (let account of storageAccount.data) {
                if (!account.id) continue;

                if (account.encryption && account.encryption.requireInfrastructureEncryption){
                    helpers.addResult(results, 0, 'Storage Account has infrastructure encryption enabled', location, account.id);
                } else {
                    helpers.addResult(results, 2, 'Storage Account does not have infrastructure encryption enabled', location, account.id);
                }
            }
            
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
