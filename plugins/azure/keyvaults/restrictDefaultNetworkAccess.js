var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Restrict Default Network Access',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure that Microsoft Azure Key Vaults are configured to deny access to traffic from all networks.',
    more_info: 'Access to Azure Key Vaults should be granted to specific Virtual Networks, which allow a secure network boundary for specific applications, or to public IP addresses/IP address ranges, which can enable connections from trusted Internet services and on-premises networks.',
    recommended_action: 'Ensure that Microsoft Azure Key Vaults can only be accessed by specific Virtual Networks.',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/general/overview-vnet-service-endpoints',
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
                    if (vault.networkAcls && ((!vault.networkAcls.defaultAction) ||
                        (vault.networkAcls.defaultAction  && vault.networkAcls.defaultAction === 'Allow'))) {
                        helpers.addResult(results, 2,
                            'Key Vault allows access to all networks', location, vault.id);
                    } else {
                        helpers.addResult(results, 0,
                            'Key Vault does not allow access to all networks', location, vault.id);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'Network Acl is not configured for Key Vault', location, vault.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
