const async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Blob Container Private Access',
    category: 'Blob Service',
    description: 'Ensures that all blob containers do not have anonymous public access set',
    more_info: 'Blob containers set with public access enables anonymous users to read blobs within a publicly accessible container without authentication. All blob containers should have private access configured.',
    recommended_action: 'Ensure each blob container is configured to restrict anonymous access',
    link: 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blobs-introduction',
    apis: ['storageAccounts:list', 'blobContainers:list'],
    compliance: {
        hipaa: 'Strict access controls to all data is a core requirement for HIPAA. ' +
            'Restricting anonymous blob access ensures all access is limited to those ' +
            'with explicit approval.',
        pci: 'PCI requires all access to be restricted and identified. Limiting public blob ' +
            'access ensures compliance.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

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
                    blobContainers.data.forEach(function(blob){
                        if (blob.publicAccess &&
                            blob.publicAccess.toLowerCase() == 'none') {
                            helpers.addResult(results, 0, 'Blob container does not allow public access', location, blob.id);
                        } else {
                            helpers.addResult(results, 2, 'Blob container allows public access', location, blob.id);
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
