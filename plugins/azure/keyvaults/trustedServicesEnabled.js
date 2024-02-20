var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'KeyVault Trusted Services Enabled',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure that "Allow trusted Microsoft services to bypass this firewall" feature is enabled for Azure Key Vault network firewall configuration.',
    more_info: 'Enabling network firewall rules for your Key Vaults will block access to incoming requests for data, including from other Azure services. ' +
        'To allow certain Azure cloud services access your vault resources, you need to add an exception so that the trusted cloud services can bypass the firewall rules.',
    recommended_action: 'Ensure that Microsoft Azure Key Vault network firewall configuration allows trusted Microsoft services to bypass the firewall.',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/general/network-security',
    apis: ['vaults:list'],
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete'],

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
                            'Trusted Microsoft services are not allowed to access the key vault resources', location, vault.id);
                    } else {
                        helpers.addResult(results, 0,
                            'Trusted Microsoft services are allowed to access the key vault resources', location, vault.id);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'Network Acls are not configured for key vault', location, vault.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};