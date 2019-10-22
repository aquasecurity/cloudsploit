var async = require('async');

var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Queue Service All Access ACL',
    category: 'Queue Service',
    description: 'Ensures queues do not allow full write, delete, or read ACL permissions',
    more_info: 'Queues can be configured to allow object read, write or delete. This option should not be configured unless there is a strong business requirement.',
    recommended_action: 'Disable global read, write, delete policies on all queues and ensure the ACL is configured with least privileges.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/queues/storage-quickstart-queues-portal',
    apis: ['resourceGroups:list', 'storageAccounts:list', 'storageAccounts:listKeys', 'QueueService:listQueuesSegmented','QueueService:getQueueAcl'],
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

        async.each(locations.QueueService, function(location, rcb){
            var queueService = helpers.addSource(cache, source,
                ['QueueService', 'getQueueAcl', location]);

            if (!queueService) return rcb();

            if (queueService.err || !queueService.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Queue Service: ' + helpers.addError(queueService), location);
                return rcb();
            }

            if (!queueService.data.length) {
                helpers.addResult(results, 0, 'No existing Queue Services found', location);
            } else {
                for (q in queueService.data) {
                    var queue = queueService.data[q];
                    var alertWrite = false;
                    var alertRead = false;

                    if (queue.signedIdentifiers && Object.keys(queue.signedIdentifiers).length>0) {
                        for(ident in queue.signedIdentifiers){
                            var permissions = queue.signedIdentifiers[ident].Permissions;
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
                                helpers.addResult(results, 2, 'ACL allows both read and write access for the queue', location, queue.id);
                            } else if (alertRead && !alertWrite) {
                                helpers.addResult(results, 2, 'ACL allows read access for the queue', location, queue.id);
                            } else if (!alertRead && alertWrite) {
                                helpers.addResult(results, 2, 'ACL allows write access for the queue', location, queue.id);
                            } else {
                                helpers.addResult(results, 0, 'ACL restricts read and write access for the queue', location, queue.id);
                            }
                        }
                    } else {
                        helpers.addResult(results, 2, 'ACL has not been configured for the queue', location, queue.id);
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