var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Trusted MS Access Enabled',
    category: 'Storage Accounts',
    description: 'Ensure that Trusted Microsoft Services Access is enabled on Storage Accounts.',
    more_info: 'By turning on firewall rules, all access to an account gets blocked by default. To ensure that microsoft and azure services that connect to the storage account still retain access, enable Allow Trusted Microsoft services to access storage account allows for those services to retain their connections.',
    recommended_action: '1. Navigate to Storage Accounts. 2. Select Firewalls and virtual networks 3. Ensure that access the storage account is not allowed. 4. In Exceptions section, check the box for Allow Trusted Microsoft services to access storage account.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security',
    apis: ['storageAccounts:list'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function (location, rcb) {
            var storageAccount = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccount) return rcb();

            if (storageAccount.err || !storageAccount.data) {
                helpers.addResult(results, 3,
                    'Unable to query Storage Accounts: ' + helpers.addError(storageAccount), location);
                return rcb();
            };

            if (!storageAccount.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            };

            storageAccount.data.forEach(account => {
                if (account.networkRuleSet && 
                    account.networkRuleSet.bypass &&
                    account.networkRuleSet.bypass.toLowerCase().indexOf("azureservices") !== -1) {
                    helpers.addResult(results, 0, 'Allow trusted Microsoft services is set', location, account.id);
                } else {
                    helpers.addResult(results, 2, 'Allow trusted Microsoft services is not set', location, account.id);
                }
            });
            
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};