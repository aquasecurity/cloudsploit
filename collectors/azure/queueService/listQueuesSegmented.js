var async = require('async');

module.exports = function(collection, reliesOn, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    var azureStorage = require('@azure/storage-queue');

    if (!collection['queueService']['listQueuesSegmented']) collection['queueService']['listQueuesSegmented'] = {};
    if (!collection['queueService']['getQueueAcl']) collection['queueService']['getQueueAcl'] = {};

    // Loop through regions and properties in reliesOn
    async.eachOf(reliesOn['storageAccounts.listKeys'], function(regionObj, region, cb) {
        collection['queueService']['listQueuesSegmented'][region] = {};
        collection['queueService']['getQueueAcl'][region] = {};

        async.eachOfLimit(regionObj, 5, async function(subObj, resourceId, sCb) {
            collection['queueService']['listQueuesSegmented'][region][resourceId] = {};

            if (subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value) {
                // Extract storage account name from resourceId
                var storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                var connectionString = `DefaultEndpointsProtocol=https;AccountName=${storageAccountName};AccountKey=${subObj.data.keys[0].value};EndpointSuffix=core.windows.net`;
                var storageService = azureStorage.QueueServiceClient.fromConnectionString(connectionString);
                let queueItemList = [];     
                let iterator = storageService.listQueues();
                let item = await iterator.next();
                while (!item.done) {
                    let queueName = item.value.name;
                    queueItemList.push({ name: queueName});
                    var entryId = `${resourceId}/queueService/${queueName}`;
                    collection['queueService']['getQueueAcl'][region][entryId] = {};
                    const queueClient = storageService.getQueueClient(queueName);
                    queueClient.getAccessPolicy()
                        .then(result => {
                            collection['queueService']['getQueueAcl'][region][entryId].data = result;
                        })
                        .catch(err => {
                            collection['queueService']['getQueueAcl'][region][entryId].err = err;
                        });
                    item = await iterator.next();
                }

                if (queueItemList.length) {
                    collection['queueService']['listQueuesSegmented'][region][resourceId].data = queueItemList;
                } else {
                    collection['queueService']['listQueuesSegmented'][region][resourceId].data = [];
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