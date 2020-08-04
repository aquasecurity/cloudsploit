var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Blob Service Immutable',
    category: 'Blob Service',
    description: 'Ensures data immutability is properly configured for blob services to protect critical data against deletion',
    more_info: 'Immutable storage helps store data securely by protecting critical data against deletion.',
    recommended_action: 'Enable a data immutability policy for all storage containers in the Azure storage account.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-immutable-storage#Getting-started',
    apis: ['storageAccounts:list', 'blobContainers:list'],
    compliance: {
        hipaa: 'Blob immutability preserves the integrity of stored data and protects against ' +
            'accidental or malicious destruction.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, (location, rcb) => {
            const storageAccounts = helpers.addSource(
                cache, source, ['storageAccounts', 'list', location]
            );

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            }

            if (!storageAccounts.data.length) {
                helpers.addResult(
                    results, 0, 'No existing Storage Accounts found', location);
                return rcb();
            }

            storageAccounts.data.forEach(function(storageAccount) {
                const blobContainers = helpers.addSource(
                    cache, source, ['blobContainers', 'list', location, storageAccount.id]
                );

                if (!blobContainers || blobContainers.err || !blobContainers.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Blob Containers: ' + helpers.addError(blobContainers),
                        location, storageAccount.id);
                } else if (!blobContainers.data.length) {
                    helpers.addResult(results, 0, 'Storage Account does not contain blob containers', location, storageAccount.id);
                } else {
                    blobContainers.data.forEach(function(blob) {
                        if (blob.hasImmutabilityPolicy) {
                            helpers.addResult(results, 0, 'Immutability has been configured for the blob service', location, blob.id);
                        } else {
                            helpers.addResult(results, 2, 'Immutability has not been configured for the blob service', location, blob.id);
                        }
                    });
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};