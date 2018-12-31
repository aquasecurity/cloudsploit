var util = require('util');
var async = require('async');

var helpers = require('../../../helpers/azure/');

var ACL_ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers';
var ACL_AUTHENTICATED_USERS = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers';

module.exports = {
    title: 'Storage Accounts Encryption',
    category: 'Storage Accounts',
    description: 'Ensures encryption is properly configured in storage accounts to protect data-at-rest and meet compliance requirements.',
    more_info: 'Storage accounts can be configured to encrypt data-at-rest, by default Azure will create a set of keys to encrypt your storage account, but the recommended approach is to create your own keys using Azure\'s Key Vault.',
    recommended_action: 'Go to your Storage Account, select Encryption, and check the box to use your own key, then select Key Vault, create a new vault if needed; then select Encryption key and create a new key if needed, at a minimum, set an activation date for your key to help with your key rotation policy, click Save when done.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption-customer-managed-keys?toc=%2fazure%2fstorage%2fblobs%2ftoc.json',
    apis: ['storageAccounts:list', 'storageAccounts:listKeys'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
		var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageaccounts, function(location, rcb){
            var storageAccount = helpers.addSource(cache, source,
                ['storageaccounts', 'list', location]);

            if (!storageAccount) return rcb();

            if (storageAccount.err || !storageAccount.data) {
                helpers.addResult(results, 3,
                    'Unable to query Storage Accounts: ' + helpers.addError(storageAccount), location);
                return rcb();
            }

            if (!storageAccount.data.length) {
                helpers.addResult(results, 2, 'No existing storage accounts', location);
            } else {
                for (acct in storageAccount.data) {
                    var account = storageAccount.data[acct];

                    if (account.encryption.keySource=="Microsoft.Keyvault") {
						helpers.addResult(results, 0, 'Storage Account Encryption is configured with Microsoft\'s Key vault', location, account.id);
					} else if (account.encryption.keySource=="Microsoft.Storage") {
						helpers.addResult(results, 2, 'Storage Account Encryption is configured using Microsoft\'s Default Storage Keys', location, account.id);
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