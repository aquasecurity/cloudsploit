var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Storage Account Private Endpoints',
    category: 'Storage Accounts',
    domain: 'Storage',
    description: 'Ensure that Azure Storage Accounts are Accessible only through Private Endpoints.',
    more_info: 'Azure Private Endpoint is a network interface that connects you privately and securely to a service powered by Azure Private Link. Private Endpoint uses a private IP address from your VNet, effectively bringing the service such as Azure Storage Accounts into your VNet.',
    recommended_action: 'Modify storage accounts and configure private endpoints.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints',
    apis: ['storageAccounts:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb) {
            var storageAccount = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccount) return rcb();

            if (storageAccount.err || !storageAccount.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccount), location);
                return rcb();
            }

            if (!storageAccount.data.length) {
                helpers.addResult(results, 0, 'No Storage Accounts found', location);
                return rcb();
            }
            for (let account of storageAccount.data) {

                if (!account.id) continue;

                if (account.privateEndpointConnections && account.privateEndpointConnections.length){
                    helpers.addResult(results, 0, 'Private Endpoints are configured for the storage account', location, account.id);
                } else {
                    helpers.addResult(results, 2, 'Private Endpoints are not configured for the storage account', location, account.id);
                }
            }
            
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
