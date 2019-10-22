var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Table Service All Access ACL',
    category: 'Table Service',
    description: 'Ensures tables do not allow full write, delete, or read ACL permissions',
    more_info: 'Table Service tables can be configured to allow to read, write or delete on objects. This option should not be configured unless there is a strong business requirement.',
    recommended_action: 'Disable global read, write, and delete policies on all tables and ensure the ACL is configured with least privileges.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/tables/table-storage-quickstart-portal',
    apis: ['resourceGroups:list', 'storageAccounts:list', 'storageAccounts:listKeys', 'TableService:listTablesSegmented', 'TableService:getTableAcl'],
    compliance: {
        hipaa: 'HIPAA access controls require data to be secured with least-privileged ' +
                'ACLs. Table Service ACLs enable granular permissions for data access.',
        pci: 'PCI data must be secured via least-privileged ACLs. Table Service ACLs ' +
                'enable granular permissions for data access.'
    },

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
                helpers.addResult(results, 0, 'No existing table services found', location);
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
                                helpers.addResult(results, 2, 'ACL allows both read and write access for the table', location, table.id);
                            } else if (alertRead && !alertWrite) {
                                helpers.addResult(results, 2, 'ACL allows read access for the table', location, table.id);
                            } else if (!alertRead && alertWrite) {
                                helpers.addResult(results, 2, 'ACL allows write access for the table', location, table.id);
                            } else {
                                helpers.addResult(results, 0, 'ACL restricts read and write access for the table', location, table.id);
                            }
                        }
                    } else {
                        helpers.addResult(results, 2, 'ACL has not been configured for the table', location, table.id);
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