var async = require('async');

module.exports = function(collection, reliesOn, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    var azureStorage = require('azure-storage');

    if (!collection['blobService']['listContainersSegmented']) collection['blobService']['listContainersSegmented'] = {};
    if (!collection['blobService']['getContainerAcl']) collection['blobService']['getContainerAcl'] = {};

    // Loop through regions and properties in reliesOn
    async.eachOf(reliesOn['storageAccounts.listKeys'], function(regionObj, region, cb) {
        collection['blobService']['listContainersSegmented'][region] = {};
        collection['blobService']['getContainerAcl'][region] = {};

        async.eachOf(regionObj, function(subObj, resourceId, sCb) {
            collection['blobService']['listContainersSegmented'][region][resourceId] = {};

            if (subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value) {
                // Extract storage account name from resourceId
                var storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                var storageService = new azureStorage['BlobService'](storageAccountName, subObj.data.keys[0].value);

                storageService.listContainersSegmented(null, function(serviceErr, serviceResults) {
                    if (serviceErr || !serviceResults) {
                        collection['blobService']['listContainersSegmented'][region][resourceId].err = (serviceErr || 'No data returned');
                        sCb();
                    } else {
                        collection['blobService']['listContainersSegmented'][region][resourceId].data = serviceResults.entries;

                        // Add ACLs
                        async.each(serviceResults.entries, function(entryObj, entryCb) {
                            var entryId = `${resourceId}/blobService/${entryObj.name}`;
                            collection['blobService']['getContainerAcl'][region][entryId] = {};

                            storageService.getContainerAcl(entryObj.name, function(getErr, getData) {
                                if (getErr || !getData) {
                                    collection['blobService']['getContainerAcl'][region][entryId].err = (getErr || 'No data returned');
                                } else {
                                    collection['blobService']['getContainerAcl'][region][entryId].data = getData;
                                }
                                entryCb();
                            });
                        }, function() {
                            sCb();
                        });
                    }
                });
            } else {
                sCb();
            }
        }, function() {
            cb();
        });
    }, function() {
        callback();
    });
};