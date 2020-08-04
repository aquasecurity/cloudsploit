var async = require('async');

module.exports = function(collection, reliesOn, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    var azureStorage = require('azure-storage');

    if (!collection['fileService']['listSharesSegmented']) collection['fileService']['listSharesSegmented'] = {};
    if (!collection['fileService']['getShareAcl']) collection['fileService']['getShareAcl'] = {};

    // Loop through regions and properties in reliesOn
    async.eachOf(reliesOn['storageAccounts.listKeys'], function(regionObj, region, cb) {
        collection['fileService']['listSharesSegmented'][region] = {};
        collection['fileService']['getShareAcl'][region] = {};

        async.eachOf(regionObj, function(subObj, resourceId, sCb) {
            collection['fileService']['listSharesSegmented'][region][resourceId] = {};

            if (subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value) {
                // Extract storage account name from resourceId
                var storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                var storageService = new azureStorage['FileService'](storageAccountName, subObj.data.keys[0].value);

                storageService.listSharesSegmented(null, function(serviceErr, serviceResults) {
                    if (serviceErr || !serviceResults) {
                        collection['fileService']['listSharesSegmented'][region][resourceId].err = (serviceErr || 'No data returned');
                        sCb();
                    } else {
                        collection['fileService']['listSharesSegmented'][region][resourceId].data = serviceResults.entries;

                        // Add ACLs
                        async.each(serviceResults.entries, function(entryObj, entryCb) {
                            var entryId = `${resourceId}/fileService/${entryObj.name}`;
                            collection['fileService']['getShareAcl'][region][entryId] = {};

                            storageService.getShareAcl(entryObj.name, function(getErr, getData) {
                                if (getErr || !getData) {
                                    collection['fileService']['getShareAcl'][region][entryId].err = (getErr || 'No data returned');
                                } else {
                                    collection['fileService']['getShareAcl'][region][entryId].data = getData;
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