var async = require('async');

var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Table Service All Access ACL',
    category: 'Table Service',
    description: 'Ensures Tables do not allow full write, delete, or read ACL permissions',
    more_info: 'Tables can be configured to allow to read, write or delete objects. This option should not be configured unless there is a strong business requirement.',
    recommended_action: 'Disable global read/write/detele policies on all Tables and ensure the ACL is configured with least privileges.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/tables/table-storage-quickstart-portal',
    apis: ['resourceGroups:list', 'storageAccounts:list', 'storageAccounts:listKeys', 'TableService:listTablesSegmented', 'TableService:getTableAcl'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
		var locations = helpers.locations(settings.govcloud);

        async.each(locations.TableService, function(location, rcb){
            var tableService = helpers.addSource(cache, source,
                ['TableService', 'getTableAcl', location]);

            if (!tableService) return rcb();

            if (tableService.err) {
                helpers.addResult(results, 3,
                    'Unable to query Table Service: ' + helpers.addError(tableService), location);
                return rcb();
            }

            if (!tableService.data || !tableService.data.length) {
                helpers.addResult(results, 0, 'No existing table services', location);
            } else {
                for (t in tableService.data) {
                    var table = tableService.data[t];
                    var alertWrite = false;
                    var alertRead = false;

                    if (table.signedIdentifiers && Object.keys(table.signedIdentifiers).length>0) {
                        for(ident in table.signedIdentifiers){
                            var permissions = table.signedIdentifiers[ident].Permissions;
                            for(i=0;i<=permissions.length;i++){
                                switch(permissions.charAt(i)){
                                    case "r":
                                        alertRead = true;
                                        break;
                                    case "c":
                                        alertWrite = true;
                                        break;
                                    case "w":
                                        alertWrite = true;
                                        break;
                                    case "d":
                                        alertWrite = true;
                                        break;
                                    case "l":
                                        alertRead = true;
                                        break;
                                }
                            }
                            if (alertRead && alertWrite) {
                                helpers.addResult(results, 2, 'Acl is allows both read and write access for the table ', location, table.name +  ' etag:' + table.etag + ' policy:' + ident);
                            } else if (alertRead && !alertWrite) {
                                helpers.addResult(results, 1, 'Acl is allows both read access for the table ', location, table.name +  ' etag:' + table.etag + ' policy:' + ident);
                            } else if (!alertRead && alertWrite) {
                                helpers.addResult(results, 1, 'Acl is allows write access for the table ', location, table.name +  ' etag:' + table.etag + ' policy:' + ident);
                            }
                        }
                    } else {
                        helpers.addResult(results, 2, 'Acl has not been configured for the table ', location, table.name +  ' etag:' + table.etag);
                    }
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};