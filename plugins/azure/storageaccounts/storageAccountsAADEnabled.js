var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Storage Accounts AAD Enabled',
    category: 'Storage Accounts',
    description: 'Ensures that identity-based Directory Service for Azure File Authentication is enabled for all Azure Files',
    more_info: 'Enabling identity-based Authentication ensures that only the authorized Active Directory members can access or connect to the file shares, enforcing granular access control.',
    recommended_action: 'Ensure that identity-based Directory Service for Azure File Authentication is enabled for all Azure File Shares.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/files/storage-files-active-directory-overview',
    apis: ['storageAccounts:list', 'resourceGroups:list'],

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
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccount), location);
                return rcb();
            }

            if (!storageAccount.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
            } else {
                for (acct in storageAccount.data) {
                    var account = storageAccount.data[acct];

                    if (account.enableAzureFilesAadIntegration) {
                        helpers.addResult(results, 0, 'Storage Account is configured with AAD Authentication', location, account.id);
                    } else {
                        helpers.addResult(results, 2, 'Storage Account is not configured with AAD Authentication', location, account.id);
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