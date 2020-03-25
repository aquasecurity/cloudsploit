var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Blob Service Immutable',
    category: 'Blob Service',
    description: 'Ensures data immutability is properly configured for blob services to protect critical data against deletion',
    more_info: 'Immutable storage helps store data securely by protecting critical data against deletion.',
    recommended_action: 'Enable a data immutability policy for all storage containers in the Azure storage account.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-immutable-storage#Getting-started',
    apis: ['resourceGroups:list', 'storageAccounts:list', 'storageAccounts:listKeys', 'BlobService:listContainersSegmented'],
    compliance: {
        hipaa: 'Blob immutability preserves the integrity of stored data and protects against ' +
            'accidental or malicious destruction.'
  },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.BlobService, function(location, rcb){
            var blobService = helpers.addSource(cache, source,
                ['BlobService', 'listContainersSegmented', location]);

            if (!blobService) return rcb();

            if (blobService.err) {
                helpers.addResult(results, 3,
                    'Unable to query Blob Service: ' + helpers.addError(blobService), location);
                return rcb();
            }

            if (!blobService.data || !blobService.data.length) {
                helpers.addResult(results, 0, 'No existing blob services', location);
            } else {
                for (srvc in blobService.data) {
                    for (entry in blobService.data[srvc].entries) {
                        var blob = blobService.data[srvc].entries[entry];

                        if (blob.hasImmutabilityPolicy) {
                            helpers.addResult(results, 0, 'Immutability has been configured for the blob service', location, blob.name + ' etag:' + blob.etag);
                        } else {
                            helpers.addResult(results, 2, 'Immutability has not been configured for the blob service', location, blob.name + ' etag:' + blob.etag);
                        }

                        // if (blob.hasLegalHold) {
                        //     helpers.addResult(results, 0, 'Legal Hold has been configured for the blob service', location, blob.name + ' etag:' + blob.etag);
                        // } else {
                        //     helpers.addResult(results, 2, 'Legal Hold has not configured for the blob service', location, blob.name + ' etag:' + blob.etag);
                        // }
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