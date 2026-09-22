const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Blob Versioning Enabled',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that blob versioning is enabled for Microsoft Storage Account blob service.',
    more_info: 'Enabling blob versioning allows for the automatic retention of previous versions of blobs, allowing data to be recovered in the event of accidental modification or deletion.',
    recommended_action: 'Enable versioning for blobs on the storage account blob service.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview',
    apis: ['storageAccounts:list', 'blobServices:getServiceProperties'],
    realtime_triggers: ['microsoftstorage:storageaccounts:write', 'microsoftstorage:storageaccounts:delete', 'microsoftstorage:storageaccounts:blobservices:write'],

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
                const getServiceProperties = helpers.addSource(cache, source,
                    ['blobServices', 'getServiceProperties', location, storageAccount.id]);

                if (!getServiceProperties || getServiceProperties.err || !getServiceProperties.data) {
                    helpers.addResult(results, 3,
                        `Unable to get blob service properties: ${helpers.addError(getServiceProperties)}`,
                        location, storageAccount.id);
                } else {
                    if (getServiceProperties.data.isVersioningEnabled) {
                        helpers.addResult(results, 0,
                            'Blob versioning is enabled for Storage Account',
                            location, storageAccount.id);
                    } else {
                        helpers.addResult(results, 2,
                            'Blob versioning is not enabled for Storage Account',
                            location, storageAccount.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
