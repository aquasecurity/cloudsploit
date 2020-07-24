var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Table Service All Access ACL',
    category: 'Table Service',
    description: 'Ensures tables do not allow full write, delete, or read ACL permissions',
    more_info: 'Table Service tables can be configured to allow to read, write or delete on objects. This option should not be configured unless there is a strong business requirement.',
    recommended_action: 'Disable global read, write, and delete policies on all tables and ensure the ACL is configured with least privileges.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/tables/table-storage-quickstart-portal',
    apis: ['storageAccounts:list', 'storageAccounts:listKeys', 'tableService:listTablesSegmented', 'tableService:getTableAcl'],
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

        async.each(locations.storageAccounts, function(location, rcb) {
            const storageAccounts = helpers.addSource(
                cache, source, ['storageAccounts', 'list', location]);

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for for storage accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            }

            if (!storageAccounts.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            }

            storageAccounts.data.forEach(function(storageAccount) {
                // Attempt to list keys to see if future calls will succeed
                var listKeys = helpers.addSource(cache, source,
                    ['storageAccounts', 'listKeys', location, storageAccount.id]);

                if (!listKeys || listKeys.err || !listKeys.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for for Table Service using Storage Account SAS: ' + helpers.addError(listKeys), location, storageAccount.id);
                } else {
                    var listTablesSegmented = helpers.addSource(cache, source,
                        ['tableService', 'listTablesSegmented', location, storageAccount.id]);

                    if (!listTablesSegmented || listTablesSegmented.err || !listTablesSegmented.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for for Table Service: ' + helpers.addError(listTablesSegmented), location, storageAccount.id);
                    } else if (!listTablesSegmented.data.length) {
                        helpers.addResult(results, 0,
                            'No existing Table Service tables found', location, storageAccount.id);
                    } else {
                        listTablesSegmented.data.forEach(function(table) {
                            var tableId = `${storageAccount.id}/tableService/${table}`;

                            // Add ACL
                            var getTableAcl = helpers.addSource(cache, source,
                                ['tableService', 'getTableAcl', location, tableId]);

                            if (!getTableAcl || getTableAcl.err || !getTableAcl.data) {
                                helpers.addResult(results, 3,
                                    'Unable to query Table Service table ACL: ' + helpers.addError(getTableAcl), location, tableId);
                            } else {
                                var acl = getTableAcl.data;
                                var fullPermissions = [];

                                if (acl.signedIdentifiers && Object.keys(acl.signedIdentifiers).length) {
                                    for (var ident in acl.signedIdentifiers) {
                                        var permissions = acl.signedIdentifiers[ident].Permissions;
                                        for (var i = 0; i <= permissions.length; i++) {
                                            switch (permissions.charAt(i)) {
                                            // case "r":
                                            //     fullPermissions.push('read');
                                            //     break;
                                            case 'c':
                                                fullPermissions.push(`create (via identifier ${ident})`);
                                                break;
                                            case 'w':
                                                fullPermissions.push(`write (via identifier ${ident})`);
                                                break;
                                            case 'd':
                                                fullPermissions.push(`delete (via identifier ${ident})`);
                                                break;
                                            case 'l':
                                                fullPermissions.push(`list (via identifier ${ident})`);
                                                break;
                                            default:
                                                break;
                                            }
                                        }
                                    }

                                    if (fullPermissions.length) {
                                        helpers.addResult(results, 2, `Table ACL allows: ${fullPermissions.join(', ')}`, location, tableId);
                                    } else {
                                        helpers.addResult(results, 0, 'Table ACL does not contain full access permissions', location, tableId);
                                    }
                                } else {
                                    helpers.addResult(results, 0, 'Table ACL has not been configured', location, tableId);
                                }
                            }
                        });
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};