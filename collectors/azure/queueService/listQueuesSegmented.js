var async = require('async');

module.exports = function(collection, reliesOn, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    var azureStorage = require('azure-storage');

    if (!collection['queueService']['listQueuesSegmented']) collection['queueService']['listQueuesSegmented'] = {};
    if (!collection['queueService']['getQueueAcl']) collection['queueService']['getQueueAcl'] = {};

    // Loop through regions and properties in reliesOn
    async.eachOf(reliesOn['storageAccounts.listKeys'], function(regionObj, region, cb) {
        collection['queueService']['listQueuesSegmented'][region] = {};
        collection['queueService']['getQueueAcl'][region] = {};

        async.eachOf(regionObj, function(subObj, resourceId, sCb) {
            collection['queueService']['listQueuesSegmented'][region][resourceId] = {};

            if (subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value) {
                // Extract storage account name from resourceId
                var storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                var storageService = new azureStorage['QueueService'](storageAccountName, subObj.data.keys[0].value);

                storageService.listQueuesSegmented(null, function(serviceErr, serviceResults) {
                    if (serviceErr || !serviceResults) {
                        collection['queueService']['listQueuesSegmented'][region][resourceId].err = (serviceErr || 'No data returned');
                        sCb();
                    } else {
                        collection['queueService']['listQueuesSegmented'][region][resourceId].data = serviceResults.entries;

                        // Add ACLs
                        async.each(serviceResults.entries, function(entryObj, entryCb) {
                            var entryId = `${resourceId}/queueService/${entryObj.name}`;
                            collection['queueService']['getQueueAcl'][region][entryId] = {};

                            storageService.getQueueAcl(entryObj.name, function(getErr, getData) {
                                if (getErr || !getData) {
                                    collection['queueService']['getQueueAcl'][region][entryId].err = (getErr || 'No data returned');
                                } else {
                                    collection['queueService']['getQueueAcl'][region][entryId].data = getData;
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