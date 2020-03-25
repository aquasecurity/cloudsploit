var async = require('async');

var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'File Service All Access ACL',
    category: 'File Service',
    description: 'Ensures file shares do not allow full write, delete, or read ACL permissions',
    more_info: 'File shares can be configured to allow to read, write, or delete permissions from a share. This option should not be configured unless there is a strong business requirement.',
    recommended_action: 'Disable global read, write, and delete policies on all file shares and ensure the share ACL is configured with least privileges.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-create-file-share#create-a-file-share-through-the-azure-portal',
    apis: ['resourceGroups:list', 'storageAccounts:list', 'storageAccounts:listKeys', 'FileService:listSharesSegmented','FileService:getShareAcl'],
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

        async.each(locations.FileService, function(location, rcb){
            var fileService = helpers.addSource(cache, source,
                ['FileService', 'getShareAcl', location]);

            if (!fileService) return rcb();

            if (fileService.err || !fileService.data) {
                helpers.addResult(results, 3,
                    'Unable to query File Service: ' + helpers.addError(fileService), location);
                return rcb();
            }

            if (!fileService.data.length) {
                helpers.addResult(results, 0, 'No existing File Services', location);
            } else {
                for (share in fileService.data) {
                    var fileShare = fileService.data[share];
                    var alertWrite = false;
                    var alertRead = false;

                    if (fileShare.signedIdentifiers && Object.keys(fileShare.signedIdentifiers).length>0) {
                        for(ident in fileShare.signedIdentifiers){
                            var permissions = fileShare.signedIdentifiers[ident].Permissions;
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
                                helpers.addResult(results, 2, 'ACL allows both read and write access for the file share', location, fileShare.name +  ' etag: ' + fileShare.etag + ' policy: ' + ident);
                            } else if (alertRead && !alertWrite) {
                                helpers.addResult(results, 2, 'ACL allows both read access for the file share', location, fileShare.name +  ' etag: ' + fileShare.etag + ' policy: ' + ident);
                            } else if (!alertRead && alertWrite) {
                                helpers.addResult(results, 2, 'ACL allows write access for the file share', location, fileShare.name +  ' etag: ' + fileShare.etag + ' policy: ' + ident);
                            } else {
                                helpers.addResult(results, 0, 'ACL does not allow read or write access for the file share', location, fileShare.name +  ' etag: ' + fileShare.etag + ' policy: ' + ident);
                            }
                        }
                    } else {
                        helpers.addResult(results, 2, 'ACL has not been configured for the file share', location, fileShare.name +  ' etag:' + fileShare.etag);
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