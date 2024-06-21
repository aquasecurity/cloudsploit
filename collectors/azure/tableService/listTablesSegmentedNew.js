var async = require('async');
var azureStorage = require('@azure/data-tables');

module.exports = function(collection, reliesOn, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    if (!collection['tableService']['listTablesSegmented']) collection['tableService']['listTablesSegmented'] = {};
    if (!collection['tableService']['getTableAcl']) collection['tableService']['getTableAcl'] = {};

    // Loop through regions and properties in reliesOn
    async.eachOf(reliesOn['storageAccounts.listKeys'], function(regionObj, region, cb) {
        collection['tableService']['listTablesSegmented'][region] = {};
        collection['tableService']['getTableAcl'][region] = {};

        async.eachOfLimit(regionObj, 5, async function(subObj, resourceId, sCb) {
            collection['tableService']['listTablesSegmented'][region][resourceId] = {};

            if (subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value) {
                // Extract storage account name from resourceId
                let storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                let connectionString = `DefaultEndpointsProtocol=https;AccountName=${storageAccountName};AccountKey=${subObj.data.keys[0].value};EndpointSuffix=core.windows.net`;
                let tableList = [];
                try {
                    let storageService = azureStorage.TableServiceClient.fromConnectionString(connectionString); 
                    let iterator = storageService.listTables();
                    let item = await iterator.next();
               
                    while (!item.done) {
                        collection['tableService']['listTablesSegmented'][region][resourceId].data = [];
                        let tableName = item.value.name;
                        tableList.push({ name: tableName});

                        let tableId = `${resourceId}/tableService/${tableName}`;
                        collection['tableService']['getTableAcl'][region][tableId] = {};
                        const credential = new azureStorage.AzureNamedKeyCredential(storageAccountName, subObj.data.keys[0].value);
                        const tableClient = new azureStorage.TableClient(`https://${storageAccountName}.table.core.windows.net`, tableName, credential);

                        tableClient.getAccessPolicy()
                            .then(result => {
                                collection['tableService']['getTableAcl'][region][tableId].data = {signedIdentifiers: result};
                            })
                            .catch(err => {

                                collection['tableService']['getTableAcl'][region][tableId].err = err;
                            });
                        item = await iterator.next();
                    }
                } catch (exception) {
                    collection['tableService']['listTablesSegmented'][region][resourceId].err = exception.message;
                }

                if (tableList.length) {
                    collection['tableService']['listTablesSegmented'][region][resourceId].data = tableList;
                } else {
                    collection['tableService']['listTablesSegmented'][region][resourceId].data = [];
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