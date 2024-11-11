var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Storage Account Public Network Access',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that Public Network Access is disabled for storage accounts.',
    more_info: 'Disabling public network access for Azure storage accounts enhances security by blocking anonymous access to data in containers and blobs. This restriction ensures that only trusted network sources can access the storage, reducing the risk of unauthorized access and data exposure.',
    recommended_action: 'Modify storage accounts and disable Public Network Access.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security',
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

                if (account.publicNetworkAccess && (account.publicNetworkAccess.toLowerCase() == 'disabled' || account.publicNetworkAccess.toLowerCase() == 'securedbyperimeter')){
                    helpers.addResult(results, 0, 'Storage account has public network access disabled', location, account.id);
                } else {
                    helpers.addResult(results, 2, 'Storage account does not have public network access disabled', location, account.id);
                }
            }
            
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
