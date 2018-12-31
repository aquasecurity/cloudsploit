var util = require('util');
var async = require('async');

var helpers = require('../../../helpers/azure/');

var ACL_ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers';
var ACL_AUTHENTICATED_USERS = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers';

module.exports = {
    title: 'Storage Accounts HTTPS',
    category: 'Storage Accounts',
    description: 'Ensures general security is properly configured in storage accounts to meet compliance requirements.',
    more_info: 'Storage accounts have several settings to increase security for each account and undelying services, this plugin checks for compliance of each of those settings.',
    recommended_action: 'Go to your Storage Account, select Encryption, and check the box to use your own key, then select Key Vault, create a new vault if needed; then select Encryption key and create a new key if needed, at a minimum, set an activation date for your key to help with your key rotation policy, click Save when done.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-security-guide?toc=%2fazure%2fstorage%2fblobs%2ftoc.json',
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

                    if (account.enableHttpsTrafficOnly) {
						helpers.addResult(results, 0, 'Storage Account is configured with HTTPS traffic only', location, account.id);
					} else {
						helpers.addResult(results, 2, 'Storage Account is not configured with HTTPS traffic only', location, account.id);
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