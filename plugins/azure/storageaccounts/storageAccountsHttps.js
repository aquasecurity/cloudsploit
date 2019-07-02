var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Storage Accounts HTTPS',
    category: 'Storage Accounts',
    description: 'Ensures HTTPS-only traffic is allowed to storage account endpoints.',
    more_info: 'Storage accounts can contain sensitive information and should only be accessed over HTTPS. Enabling the HTTPS-only flag ensures that Azure does not allow HTTP traffic to storage accounts.',
    recommended_action: 'Enable the HTTPS-only option for all storage accounts.',
    link: 'https://docs.microsoft.com/en-us/azure/governance/policy/samples/ensure-https-storage-account',
    apis: ['storageAccounts:list', 'storageAccounts:listKeys', 'resourceGroups:list'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
                'Storage Account HTTPS should be used to ensure all data access ' +
                'connects over a secure channel.',
        pci: 'All card holder data must be transmitted over secure channels. ' +
                'Storage Account HTTPS should be used to ensure all data access ' +
                'connects over a secure channel.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb){
            var storageAccount = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccount) return rcb();

            if (storageAccount.err || !storageAccount.data) {
                helpers.addResult(results, 3,
                    'Unable to query Storage Accounts: ' + helpers.addError(storageAccount), location);
                return rcb();
            }

            if (!storageAccount.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
            } else {
                for (acct in storageAccount.data) {
                    var account = storageAccount.data[acct];

                    if (account.enableHttpsTrafficOnly) {
                        helpers.addResult(results, 0, 'Storage Account is configured with HTTPS traffic only', location, account.id);
                    } else {
                        helpers.addResult(results, 2, 'Storage Account is not configured with HTTPS traffic only', location, account.id);
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