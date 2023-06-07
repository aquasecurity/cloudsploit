var async = require('async');

module.exports = function(collection, reliesOn, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    var azureStorage = require('@azure/data-tables');

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
                var storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                var connectionString = `DefaultEndpointsProtocol=https;AccountName=${storageAccountName};AccountKey=${subObj.data.keys[0].value};EndpointSuffix=core.windows.net`;
                
                var storageService = azureStorage.TableServiceClient.fromConnectionString(connectionString);
                let tableList = [];     
                
                let iterator = storageService.listTables();
                let item = await iterator.next();
                
                while (!item.done) {
                    let tableName = item.value.name;
                    tableList.push({ name: tableName});

                    var tableId = `${resourceId}/tableService/${tableName}`;
                    if (tableName =='AzureFunctionsScaleMetrics202306') console.log(tableId)
                    collection['tableService']['getTableAcl'][region][tableId] = {};
                    const credential = new azureStorage.AzureNamedKeyCredential(storageAccountName, subObj.data.keys[0].value);
                    const tableClient = new azureStorage.TableClient(`https://${storageAccountName}.table.core.windows.net`, tableName, credential);

                    tableClient.getAccessPolicy()
                        .then(result => {
                            //console.log(result);
                            collection['tableService']['getTableAcl'][region][tableId].data = result;
                            console.log(collection['tableService']['getTableAcl'][region][tableId].data)
                            
                        })
                        .catch(err => {
                            console.log("err", err)
                            collection['tableService']['getTableAcl'][region][tableId].err = err;
                        });
                    item = await iterator.next();
                }

                if (tableList.length) {
                    collection['tableService']['listTablesSegmented'][region][resourceId].data = tableList;
                } else {
                    collection['tableService']['listTablesSegmented'][region][resourceId].data = [];
                }

                // storageService.listTablesSegmented(null, function(tableErr, tableResults) {
                //     if (tableErr || !tableResults) {
                //         collection['tableService']['listTablesSegmented'][region][resourceId].err = (tableErr || 'No data returned');
                //         sCb();
                //     } else {
                //         collection['tableService']['listTablesSegmented'][region][resourceId].data = tableResults.entries;

                //         // Add table ACLs
                //         async.eachLimit(tableResults.entries, 10, function(tableName, tableCb){
                //             var tableId = `${resourceId}/tableService/${tableName}`;
                //             collection['tableService']['getTableAcl'][region][tableId] = {};

                //             storageService.getTableAcl(tableName, function(getErr, getData){
                //                 if (getErr || !getData) {
                //                     collection['tableService']['getTableAcl'][region][tableId].err = (getErr || 'No data returned');
                //                 } else {
                //                     collection['tableService']['getTableAcl'][region][tableId].data = getData;
                //                 }
                //                 tableCb();
                //             });
                //         }, function(){
                //             sCb();
                //         });
                //     }
                // });
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