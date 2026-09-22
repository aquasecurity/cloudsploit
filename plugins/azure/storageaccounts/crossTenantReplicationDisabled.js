const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Storage Account Cross Tenant Replication Disabled',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that cross tenant replication is not enabled for Microsoft Azure Storage Accounts.',
    more_info: 'Cross tenant replication allows data to be replicated across different Azure tenant boundaries. Disabling this setting minimizes the risk of unauthorized data access, data leakage, and inadvertent replication of data outside the organization\'s tenant.',
    recommended_action: 'Disable Allow cross-tenant replication from the object replication settings of the storage account.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/blobs/object-replication-overview',
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

                if (!storageAccount.allowCrossTenantReplication) {
                    helpers.addResult(results, 0,
                        'Storage Account has cross tenant replication disabled',
                        location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2,
                        'Storage Account has cross tenant replication enabled',
                        location, storageAccount.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
