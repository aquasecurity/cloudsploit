var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Storage Accounts Encryption',
    category: 'Storage Accounts',
    description: 'Ensures encryption is properly configured in storage accounts to protect data-at-rest and meet compliance requirements.',
    more_info: 'Storage accounts can be configured to encrypt data-at-rest, by default Azure will create a set of keys to encrypt your storage account, but the recommended approach is to create your own keys using Azure Key Vault.',
    recommended_action: 'Go to your Storage Account, select Encryption, and check the box to use your own key, then select Key Vault, create a new vault if needed; then select Encryption key and create a new key if needed, at a minimum, set an activation date for your key to help with your key rotation policy, click Save when done.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption-customer-managed-keys',
    apis: ['storageAccounts:list', 'storageAccounts:listKeys'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
		var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb){
            var storageAccount = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccount) return rcb();

            if (storageAccount.err || !storageAccount.data) {
                helpers.addResult(results, 3,
                    'Unable to query Storage Accounts: ' + helpers.addError(storageAccount), location);
                return rcb();
            }

            if (!storageAccount.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
            } else {
                for (acct in storageAccount.data) {
                    var account = storageAccount.data[acct];

                    if (account.encryption && account.encryption.keySource &&
                        account.encryption.keySource == "Microsoft.Keyvault") {
						helpers.addResult(results, 0, 'Storage Account Encryption is configured with Microsoft Key vault', location, account.id);
					} else if (account.encryption && account.encryption.keySource &&
                        account.encryption.keySource == "Microsoft.Storage") {
						helpers.addResult(results, 1, 'Storage Account Encryption is configured using Microsoft Default Storage Keys', location, account.id);
					} else {
                        helpers.addResult(results, 2, 'Storage Account is not configured for data at rest encryption', location, account.id);
					}
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};