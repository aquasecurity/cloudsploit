const { BlobServiceClient, StorageSharedKeyCredential } = require('@azure/storage-blob');
var async = require('async');

module.exports = function(collection, reliesOn, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    if (!collection['blobService']['listContainersSegmented']) collection['blobService']['listContainersSegmented'] = {};
    if (!collection['blobService']['getContainerAcl']) collection['blobService']['getContainerAcl'] = {};

    async.eachOfLimit(reliesOn['storageAccounts.listKeys'], 10, function(regionObj, region, cb) {
        collection['blobService']['listContainersSegmented'][region] = {};
        collection['blobService']['getContainerAcl'][region] = {};

        async.eachOfLimit(regionObj, 10, function(subObj, resourceId, sCb) {
            collection['blobService']['listContainersSegmented'][region][resourceId] = {};

            const key = subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value? subObj.data.keys[0].value : null;
            if (!key) return sCb();

            const storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
            const credential = new StorageSharedKeyCredential(storageAccountName, key);
            const blobServiceClient = new BlobServiceClient(
                `https://${storageAccountName}.blob.core.windows.net`,
                credential
            );

            const containers = [];

            (async() => {
                try {
                    for await (const container of blobServiceClient.listContainers()) {
                        containers.push(container);
                    }

                    collection['blobService']['listContainersSegmented'][region][resourceId].data = containers;

                    // Get ACLs for each container
                    async.eachLimit(containers, 10, async(entryObj, entryCb) => {
                        const entryId = `${resourceId}/blobService/${entryObj.name}`;
                        collection['blobService']['getContainerAcl'][region][entryId] = {};

                        try {
                            const containerClient = blobServiceClient.getContainerClient(entryObj.name);
                            const aclResponse = await containerClient.getAccessPolicy();
                            collection['blobService']['getContainerAcl'][region][entryId].data = aclResponse;
                        } catch (getErr) {
                            collection['blobService']['getContainerAcl'][region][entryId].err = getErr.message || getErr;
                        }

                        entryCb();
                    }, sCb);
                } catch (serviceErr) {
                    collection['blobService']['listContainersSegmented'][region][resourceId].err = serviceErr.message || serviceErr;
                    sCb();
                }
            })();
        }, cb);
    }, callback);
};
