var async = require('async');

var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'File Service All Access ACL',
    category: 'File Service',
    description: 'Ensures file shares do not allow full write, delete, or read ACL permissions',
    more_info: 'File shares can be configured to allow to read, write, or delete permissions from a share. This option should not be configured unless there is a strong business requirement.',
    recommended_action: 'Disable global read, write, and delete policies on all file shares and ensure the share ACL is configured with least privileges.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-create-file-share#create-a-file-share-through-the-azure-portal',
    apis: ['storageAccounts:list', 'storageAccounts:listKeys', 'fileService:listSharesSegmented', 'fileService:getShareAcl'],
    compliance: {
        hipaa: 'HIPAA access controls require data to be secured with least-privileged ' +
                'ACLs. File Service ACLs enable granular permissions for data access.',
        pci: 'PCI data must be secured via least-privileged ACLs. File Service ACLs ' +
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

            storageAccounts.data.forEach(function(storageAccount){
                // Attempt to list keys to see if future calls will succeed
                var listKeys = helpers.addSource(cache, source,
                    ['storageAccounts', 'listKeys', location, storageAccount.id]);

                if (!listKeys || listKeys.err || !listKeys.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for for File Service using Storage Account SAS: ' + helpers.addError(listKeys), location, storageAccount.id);
                } else {
                    var listSharesSegmented = helpers.addSource(cache, source,
                        ['fileService', 'listSharesSegmented', location, storageAccount.id]);

                    if (!listSharesSegmented || listSharesSegmented.err || !listSharesSegmented.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for for File Shares: ' + helpers.addError(listSharesSegmented), location, storageAccount.id);
                    } else if (!listSharesSegmented.data.length) {
                        helpers.addResult(results, 0,
                            'No existing File Service shares found', location, storageAccount.id);
                    } else {
                        listSharesSegmented.data.forEach(function(fileShare) {
                            fileShare.id = `${storageAccount.id}/fileService/${fileShare.name}`;
                            // Add share ACL
                            var getShareAcl = helpers.addSource(cache, source,
                                ['fileService', 'getShareAcl', location, fileShare.id]);

                            if (!getShareAcl || getShareAcl.err || !getShareAcl.data) {
                                helpers.addResult(results, 3,
                                    'Unable to query File Service share ACL: ' + helpers.addError(getShareAcl), location, fileShare.id);
                            } else {
                                var acl = getShareAcl.data;
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
                                        helpers.addResult(results, 2, `File Share ACL allows: ${fullPermissions.join(', ')}`, location, fileShare.id);
                                    } else {
                                        helpers.addResult(results, 0, 'File Share ACL does not contain full access permissions', location, fileShare.id);
                                    }
                                } else {
                                    helpers.addResult(results, 0, 'File Share ACL has not been configured', location, fileShare.id);
                                }
                            }
                        });
                    }
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};