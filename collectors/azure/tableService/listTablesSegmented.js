var async = require('async');

module.exports = function(collection, reliesOn, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    var azureStorage = require('azure-storage');

    if (!collection['tableService']['listTablesSegmented']) collection['tableService']['listTablesSegmented'] = {};
    if (!collection['tableService']['getTableAcl']) collection['tableService']['getTableAcl'] = {};

    // Loop through regions and properties in reliesOn
    async.eachOf(reliesOn['storageAccounts.listKeys'], function(regionObj, region, cb) {
        collection['tableService']['listTablesSegmented'][region] = {};
        collection['tableService']['getTableAcl'][region] = {};

        async.eachOf(regionObj, function(subObj, resourceId, sCb) {
            collection['tableService']['listTablesSegmented'][region][resourceId] = {};

            if (subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value) {
                // Extract storage account name from resourceId
                var storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                var storageService = new azureStorage['TableService'](storageAccountName, subObj.data.keys[0].value);
                
                storageService.listTablesSegmented(null, function(tableErr, tableResults) {
                    if (tableErr || !tableResults) {
                        collection['tableService']['listTablesSegmented'][region][resourceId].err = (tableErr || 'No data returned');
                        sCb();
                    } else {
                        collection['tableService']['listTablesSegmented'][region][resourceId].data = tableResults.entries;

                        // Add table ACLs
                        async.each(tableResults.entries, function(tableName, tableCb){
                            var tableId = `${resourceId}/tableService/${tableName}`;
                            collection['tableService']['getTableAcl'][region][tableId] = {};

                            storageService.getTableAcl(tableName, function(getErr, getData){
                                if (getErr || !getData) {
                                    collection['tableService']['getTableAcl'][region][tableId].err = (getErr || 'No data returned');
                                } else {
                                    collection['tableService']['getTableAcl'][region][tableId].data = getData;
                                }
                                tableCb();
                            });
                        }, function(){
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