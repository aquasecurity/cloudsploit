var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Storage Account Has Secure Transfer enabled',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensure that storage account has secure transfer is enabled.',
    more_info: 'The storage account provides a unique namespace for your Azure Storage data that is accessible from anywhere in the world over HTTP/HTTPS. All data stored within your Azure Storage account is secure, scalable, durable, and highly available.',
    recommended_action: 'Modify storage account and enable secure transfer.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer',
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

                if (account.supportsHttpsTrafficOnly){
                    helpers.addResult(results, 0, 'Storage Account has secure transfer enabled', location, account.id);
                } else {
                    helpers.addResult(results, 2, 'Storage Account does not have secure transfer enabled', location, account.id);
                }
            }
            
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};