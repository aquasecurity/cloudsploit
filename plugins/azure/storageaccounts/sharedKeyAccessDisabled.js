const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Storage Account Shared Key Access Disabled',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that shared key access is disabled for Microsoft Azure Storage Accounts.',
    more_info: 'Requests to a storage account can be authorized with either Microsoft Entra credentials or with the account access key using Shared Key authorization. Disabling Shared Key access requires clients to use Microsoft Entra ID, which provides superior security and ease of use compared to Shared Key.',
    recommended_action: 'Disable Allow storage account key access from the configuration settings of the storage account.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent',
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

                if (storageAccount.allowSharedKeyAccess === false) {
                    helpers.addResult(results, 0,
                        'Storage Account has shared key access disabled',
                        location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2,
                        'Storage Account does not have shared key access disabled',
                        location, storageAccount.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
