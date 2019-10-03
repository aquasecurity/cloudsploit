var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'File Service Encryption',
    category: 'Storage Accounts',
    description: 'Enable data encryption at rest for File Service.',
    more_info: 'File Service encryption protects your data at rest. Azure Storage encrypts your data and automatically decrypts it for you as you access it.',
    recommended_action: '1. Go to Storage Accounts 2. For each storage account, go to Encryption under FILE SERVICE 3. Ensure that Storage service encryption is set to Enabled',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption',
    apis: ['storageAccounts:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb){
            var storageAccounts = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query Storage Accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            };

            if (!storageAccounts.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            };
            
            storageAccounts.data.forEach(storageAccount => {
                if (storageAccount["encryption"] &&
                    storageAccount["encryption"]["services"] &&
                    storageAccount["encryption"]["services"]["file"] &&
                    storageAccount["encryption"]["services"]["file"]["enabled"]) {
                    helpers.addResult(results, 0, 'Encryption is enabled on the File Service', location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2, 'Encryption is disabled on the File Service', location, storageAccount.id);
                };
            });
            
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};