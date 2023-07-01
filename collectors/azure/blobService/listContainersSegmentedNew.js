var async = require('async');

module.exports = function(collection, reliesOn, callback) {

    if (!reliesOn['storageAccounts.listKeys']) return callback();

    var azureStorage = require('@azure/storage-blob');

    if (!collection['blobService']['listContainersSegmented']) collection['blobService']['listContainersSegmented'] = {};
    if (!collection['blobService']['getContainerAcl']) collection['blobService']['getContainerAcl'] = {};
    // Loop through regions and properties in reliesOn
    async.eachOf(reliesOn['storageAccounts.listKeys'], function(regionObj, region, cb) {
        collection['blobService']['listContainersSegmented'][region] = {};
        collection['blobService']['getContainerAcl'][region] = {};

        async.eachOfLimit(regionObj, 5, async function(subObj, resourceId, sCb) {
            collection['blobService']['listContainersSegmented'][region][resourceId] = {};
            if (subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value) {

                const blobList = [];
                try {
                    const storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                    const connectionString = `DefaultEndpointsProtocol=https;AccountName=${storageAccountName};AccountKey=${subObj.data.keys[0].value};EndpointSuffix=core.windows.net`;
                    const storageService = azureStorage.BlobServiceClient.fromConnectionString(connectionString);
                    const iterator = storageService.listContainers();
                    let item = await iterator.next();

                    while (!item.done) {
                        let blobContainer = item.value.name;
                        blobList.push({ name: blobContainer});
                        var entryId = `${resourceId}/blobService/${blobContainer}`;
                        collection['blobService']['getContainerAcl'][region][entryId] = {};
                        const containerClient = storageService.getContainerClient(blobContainer);
                        containerClient.getAccessPolicy()
                            .then(result => {
                                collection['blobService']['getContainerAcl'][region][entryId].data = result;
                            })
                            .catch(err => {
                                collection['blobService']['getContainerAcl'][region][entryId].err = err;
                            });
                        item = await iterator.next();
                    }
                } catch (exception) {
                    collection['blobService']['listContainersSegmented'][region][resourceId].err = exception.message;
                }
                if (blobList.length) {
                    collection['blobService']['listContainersSegmented'][region][resourceId].data = blobList;
                } else {
                    collection['blobService']['listContainersSegmented'][region][resourceId].data = [];
                }
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