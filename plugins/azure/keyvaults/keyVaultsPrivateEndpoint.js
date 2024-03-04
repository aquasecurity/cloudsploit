var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vaults Private Endpoint',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensure that Azure Key vaults have private endpoints configured.',
    more_info: 'Configuring private link ensures connection of virtual networks to Azure services without a public IP address at the source or destination. Private endpoints minimize the risk of public internet exposure and protect against external attacks.',
    recommended_action: 'Ensure that private endpoints are configured properly and public network access is disabled for Key Vaults.',
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
                if (!vault.id) continue;

                if (vault.privateEndpointConnections && vault.privateEndpointConnections.length ) {
                    helpers.addResult(results, 0, 'Key Vault has private endpoints configured', location, vault.id);
                } else {
                    helpers.addResult(results, 2, 'Key Vault does not have private endpoints configured', location, vault.id);
                }
            } 
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};