var async = require('async');

var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Queue Service All Access ACL',
    category: 'Queue Service',
    description: 'Ensures queues do not allow full write, delete, or read ACL permissions',
    more_info: 'Queues can be configured to allow object read, write or delete. This option should not be configured unless there is a strong business requirement.',
    recommended_action: 'Disable global read, write, delete policies on all queues and ensure the ACL is configured with least privileges.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/queues/storage-quickstart-queues-portal',
    apis: ['storageAccounts:list', 'storageAccounts:listKeys', 'queueService:listQueuesSegmented', 'queueService:getQueueAcl'],
    compliance: {
        hipaa: 'HIPAA access controls require data to be secured with least-privileged ' +
                'ACLs. Queue Service ACLs enable granular permissions for data access.',
        pci: 'PCI data must be secured via least-privileged ACLs. Queue Service ACLs ' +
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
                        'Unable to query for for Queue Service using Storage Account SAS: ' + helpers.addError(listKeys), location, storageAccount.id);
                } else {
                    var listQueuesSegmented = helpers.addSource(cache, source,
                        ['queueService', 'listQueuesSegmented', location, storageAccount.id]);

                    if (!listQueuesSegmented || listQueuesSegmented.err || !listQueuesSegmented.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for for Queue Service: ' + helpers.addError(listQueuesSegmented), location, storageAccount.id);
                    } else if (!listQueuesSegmented.data.length) {
                        helpers.addResult(results, 0,
                            'No existing Queue Service queues found', location, storageAccount.id);
                    } else {
                        listQueuesSegmented.data.forEach(function(queue) {
                            queue.id = `${storageAccount.id}/queueService/${queue.name}`;
                            // Add ACL
                            var getQueueAcl = helpers.addSource(cache, source,
                                ['queueService', 'getQueueAcl', location, queue.id]);

                            if (!getQueueAcl || getQueueAcl.err || !getQueueAcl.data) {
                                helpers.addResult(results, 3,
                                    'Unable to query Queue Service queue ACL: ' + helpers.addError(getQueueAcl), location, queue.id);
                            } else {
                                var acl = getQueueAcl.data;
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
                                        helpers.addResult(results, 2, `Queue ACL allows: ${fullPermissions.join(', ')}`, location, queue.id);
                                    } else {
                                        helpers.addResult(results, 0, 'Queue ACL does not contain full access permissions', location, queue.id);
                                    }
                                } else {
                                    helpers.addResult(results, 0, 'Queue ACL has not been configured', location, queue.id);
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