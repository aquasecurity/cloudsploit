var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Blob Service Immutable',
    category: 'Blob Service',
    description: 'Ensures data immutability is properly configured in blob services to protect critical data against deletion.',
    more_info: 'Immutable storage helps financial institutions and related industries--particularly broker-dealer organizations--to store data securely. It can also be leveraged in any scenario to protect critical data against deletion.',
    recommended_action: 'In your Azure\'s storage account, select an existing container, then select access policy under container settings, and the Add Policy under Immutable Blob Storage.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-immutable-storage#Getting-started',
    apis: ['BlobService:listContainersSegmented'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
		var locations = helpers.locations(settings.govcloud);

        async.each(locations.blobservice, function(location, rcb){
            var blobService = helpers.addSource(cache, source,
                ['blobservice', 'listContainersSegmented', location]);

            if (!blobService) return rcb();

            if (blobService.err || !blobService.data) {
                helpers.addResult(results, 3,
                    'Unable to query Blob Service: ' + helpers.addError(blobService), location);
                return rcb();
            }

            if (!blobService.data.entries.length) {
                helpers.addResult(results, 0, 'No existing blob services', location);
            } else {
                for (srvc in blobService.data.entries) {
                    var blob = blobService.data.entries[srvc];

                    if (blob.hasImmutabilityPolicy) {
						helpers.addResult(results, 0, 'Immutability has been configured for the blob service', location, blob.name +  ' etag:' + blob.etag);
					} else {
						helpers.addResult(results, 2, 'Immutability has not been configured for the blob service', location, blob.name +  ' etag:' + blob.etag);
					}

					if (blob.hasLegalHold) {
						helpers.addResult(results, 0, 'Legal Hold has been configured for the blob service', location, blob.name +  ' etag:' + blob.etag);
					} else {
						helpers.addResult(results, 2, 'Legal Hold has not configured for the blob service', location, blob.name +  ' etag:' + blob.etag);
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