const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Blob Anonymous Access Disabled',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'High',
    description: 'Ensures that anonymous access to blob data is disabled for Microsoft Azure Storage Accounts.',
    more_info: 'When Allow Blob Anonymous Access is enabled, blobs can be accessed by adding the blob name to the URL without authentication. An attacker can enumerate blobs using methods such as brute force and access them, resulting in exfiltration of data.',
    recommended_action: 'Disable Allow Blob Anonymous Access from the configuration settings of the storage account.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent',
    apis: ['storageAccounts:list'],
    realtime_triggers: ['microsoftstorage:storageaccounts:write', 'microsoftstorage:storageaccounts:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb) {
            const storageAccounts = helpers.addSource(
                cache, source, ['storageAccounts', 'list', location]);

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for storage accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            }

            if (!storageAccounts.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            }

            storageAccounts.data.forEach(storageAccount => {
                if (!storageAccount.id) return;

                if (!storageAccount.allowBlobPublicAccess) {
                    helpers.addResult(results, 0,
                        'Storage Account has blob anonymous access disabled',
                        location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2,
                        'Storage Account has blob anonymous access enabled',
                        location, storageAccount.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
