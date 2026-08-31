const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Storage Account Entra ID Authorization Default',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that the Azure portal defaults to Microsoft Entra authorization for Microsoft Azure Storage Accounts.',
    more_info: 'When this property is enabled, the Azure portal authorizes requests to blobs, files, queues, and tables with Microsoft Entra ID by default, which provides superior security and ease of use over Shared Key.',
    recommended_action: 'Enable Default to Microsoft Entra authorization in the Azure portal from the configuration settings of the storage account.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access',
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

                if (storageAccount.defaultToOAuthAuthentication) {
                    helpers.addResult(results, 0,
                        'Storage Account defaults to Microsoft Entra authorization in the Azure portal',
                        location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2,
                        'Storage Account does not default to Microsoft Entra authorization in the Azure portal',
                        location, storageAccount.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
