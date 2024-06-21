var async = require('async');
var azureStorage = require('@azure/storage-file-share');

module.exports = function(collection, reliesOn, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    if (!collection['fileService']['listSharesSegmented']) collection['fileService']['listSharesSegmented'] = {};
    if (!collection['fileService']['getShareAcl']) collection['fileService']['getShareAcl'] = {};

    // Loop through regions and properties in reliesOn
    async.eachOfLimit(reliesOn['storageAccounts.listKeys'], 10,function(regionObj, region, cb) {
        collection['fileService']['listSharesSegmented'][region] = {};
        collection['fileService']['getShareAcl'][region] = {};

        async.eachOfLimit(regionObj, 10, async function(subObj, resourceId, sCb) {
            collection['fileService']['listSharesSegmented'][region][resourceId] = {};

            if (subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value) {
                // Extract storage account name from resourceId
                const shareItemList = [];
                try {
                    const storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                    const connectionString = `DefaultEndpointsProtocol=https;AccountName=${storageAccountName};AccountKey=${subObj.data.keys[0].value};EndpointSuffix=core.windows.net`;
                    const storageService = azureStorage.ShareServiceClient.fromConnectionString(connectionString);
                    const iterator = storageService.listShares();
                    let item = await iterator.next();

                    while (!item.done) {
                        let fileShare = item.value.name;
                        var entryId = `${resourceId}/fileService/${fileShare}`;
                        shareItemList.push({ name: fileShare, id: entryId});
                        collection['fileService']['getShareAcl'][region][entryId] = {};
                        const shareClient = storageService.getShareClient(fileShare);
                        shareClient.getAccessPolicy()
                            .then(result => {
                                collection['fileService']['getShareAcl'][region][entryId].data = result;
                            })
                            .catch(err => {
                                collection['fileService']['getShareAcl'][region][entryId].err = err;
                            });
                        item = await iterator.next();
                    }
                } catch (exception) {
                    collection['fileService']['listSharesSegmented'][region][resourceId].err = exception.message;
                }
                if (shareItemList.length) {
                    collection['fileService']['listSharesSegmented'][region][resourceId].data = shareItemList;
                } else {
                    collection['fileService']['listSharesSegmented'][region][resourceId].data = [];
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
