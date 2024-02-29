var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Private Endpoint',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensure that Azure Key vaults have private endpoints enabled.',
    more_info: 'Azure Private Endpoint is a network interface that connects you privately and securely to a service powered by Azure Private Link. The private endpoint uses a private IP address from your VNet, effectively bringing the service into your VNet.',
    recommended_action: 'Add private endpoint to Key vault',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service',
    apis: ['vaults:list'],
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete','microsoftnetwork:privatednszones:virtualnetworklinks:write','microsoftkeyvault:vaults:privateendpointconnections:delete'],

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

            for (let vault of vaults.data) {
                let publicEndpoint = vault.privateEndpointConnections;
                if (publicEndpoint && publicEndpoint[0].id) {
                    helpers.addResult(results, 0, 'Key Vault private endpoint is enabled', location, vault.id);
                } else {
                    helpers.addResult(results, 2, 'Key Vault private endpoint is not enabled', location, vault.id);
                }
            } 
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};