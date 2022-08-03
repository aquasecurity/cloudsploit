var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Trusted Microsoft Services for Key Vault Access',
    category: 'Key Vaults',
    domain: 'Application Integration',
    description: 'Ensure that trusted Microsoft services to allowed to bypass the firewall.',
    more_info: 'Enabling network firewall rules for your Key Vaults will block access to incoming requests for data, including from other Azure services.',
    recommended_action: 'Ensure that Microsoft Azure Key Vaults have Trusted Microsoft Services that are allowed to bypass.',
    link: 'https://docs.microsoft.com/en-us/azure/key-vault/general/overview-vnet-service-endpoints',
    apis: ['vaults:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.vaults, function(location, rcb) {
            var vaults = helpers.addSource(cache, source,
                ['vaults', 'list', location]);

            if (!vaults) return rcb();

            if (vaults.err || !vaults.data) {
                helpers.addResult(results, 3, 'Unable to query for Key Vaults: ' + helpers.addError(vaults), location);
                return rcb();
            }

            if (!vaults.data.length) {
                helpers.addResult(results, 0, 'No Key Vaults found', location);
                return rcb();
            }

            vaults.data.forEach((vault) => {
                if (vault.networkAcls){
                    if (vault.networkAcls && vault.networkAcls.bypass && vault.networkAcls.bypass === 'None') {
                        helpers.addResult(results, 2,
                            'no trusted Microsoft Azure cloud services are allowed to access the key vault resources', location, vault.id);
                    } else {
                        helpers.addResult(results, 0,
                            'trusted Microsoft Azure cloud services are allowed to access the key vault resources', location, vault.id);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'Network Acls are not configured', location, vault.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};