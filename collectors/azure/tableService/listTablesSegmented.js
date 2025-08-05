const { TableServiceClient, AzureNamedKeyCredential } = require('@azure/data-tables');
var async = require('async');

module.exports = function(collection, reliesOn, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    if (!collection['tableService']['listTablesSegmented']) collection['tableService']['listTablesSegmented'] = {};
    if (!collection['tableService']['getTableAcl']) collection['tableService']['getTableAcl'] = {};

    async.eachOfLimit(reliesOn['storageAccounts.listKeys'], 10, function(regionObj, region, cb) {
        collection['tableService']['listTablesSegmented'][region] = {};
        collection['tableService']['getTableAcl'][region] = {};

        async.eachOfLimit(regionObj, 10, function(subObj, resourceId, sCb) {
            collection['tableService']['listTablesSegmented'][region][resourceId] = {};

            const key = subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value? subObj.data.keys[0].value:null;
            if (!key) return sCb();

            const storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
            const credential = new AzureNamedKeyCredential(storageAccountName, key);
            const serviceClient = new TableServiceClient(
                `https://${storageAccountName}.table.core.windows.net`,
                credential
            );

            const tables = [];

            (async() => {
                try {
                    for await (const table of serviceClient.listTables()) {
                        tables.push(table.name);
                    }

                    collection['tableService']['listTablesSegmented'][region][resourceId].data = tables;

                    async.eachLimit(tables, 10, async(tableName, tableCb) => {
                        const tableId = `${resourceId}/tableService/${tableName}`;
                        collection['tableService']['getTableAcl'][region][tableId] = {};

                        try {
                            const aclResponse = await serviceClient.getAccessPolicy(tableName);
                            collection['tableService']['getTableAcl'][region][tableId].data = aclResponse;
                        } catch (getErr) {
                            collection['tableService']['getTableAcl'][region][tableId].err = getErr.message || getErr;
                        }

                        tableCb();
                    }, sCb);
                } catch (tableErr) {
                    collection['tableService']['listTablesSegmented'][region][resourceId].err = tableErr.message || tableErr;
                    sCb();
                }
            })();
        }, cb);
    }, callback);
};
