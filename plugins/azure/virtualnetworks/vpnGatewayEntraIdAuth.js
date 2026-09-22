var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VPN Gateway Entra ID Authentication',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensures that VPN gateway point-to-site configuration uses Entra ID authentication only.',
    more_info: 'Entra ID authentication provides centralized identity management and conditional access for point-to-site VPN users. Allowing certificate or RADIUS authentication relies on static credentials that are harder to rotate, revoke and audit.',
    recommended_action: 'In the point-to-site configuration of the VPN gateway, set the authentication type to Entra ID only and remove Azure certificate and RADIUS authentication.',
    link: 'https://learn.microsoft.com/en-us/azure/vpn-gateway/point-to-site-about',
    apis: ['resourceGroups:list', 'virtualNetworkGateways:listByResourceGroup'],
    realtime_triggers: ['microsoftnetwork:virtualnetworkgateways:write', 'microsoftnetwork:virtualnetworkgateways:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualNetworkGateways, function(location, rcb) {
            var resourceGroups = helpers.addSource(cache, source,
                ['resourceGroups', 'list', location]);

            if (!resourceGroups) return rcb();

            if (resourceGroups.err || !resourceGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for resource groups: ' + helpers.addError(resourceGroups), location);
                return rcb();
            }

            if (!resourceGroups.data.length) {
                helpers.addResult(results, 0, 'No existing resource groups found', location);
                return rcb();
            }

            var found = false;

            resourceGroups.data.forEach(resourceGroup => {
                var virtualNetworkGateways = helpers.addSource(cache, source,
                    ['virtualNetworkGateways', 'listByResourceGroup', location, resourceGroup.id]);

                if (!virtualNetworkGateways || virtualNetworkGateways.err || !virtualNetworkGateways.data) {
                    helpers.addResult(results, 3, 'Unable to query for virtual network gateways: ' + helpers.addError(virtualNetworkGateways), location, resourceGroup.id);
                    return;
                }

                for (let gateway of virtualNetworkGateways.data) {
                    if (!gateway.gatewayType || gateway.gatewayType.toLowerCase() !== 'vpn') continue;

                    found = true;

                    var authTypes = gateway.vpnClientConfiguration && gateway.vpnClientConfiguration.vpnAuthenticationTypes ?
                        gateway.vpnClientConfiguration.vpnAuthenticationTypes : [];

                    if (!authTypes.length) {
                        helpers.addResult(results, 0, 'VPN gateway does not have point-to-site configuration enabled', location, gateway.id);
                    } else if (authTypes.length === 1 && authTypes[0].toLowerCase() === 'aad') {
                        helpers.addResult(results, 0, 'VPN gateway point-to-site configuration is using Entra ID authentication only', location, gateway.id);
                    } else {
                        helpers.addResult(results, 2, 'VPN gateway point-to-site configuration is not using Entra ID authentication only', location, gateway.id);
                    }
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'No existing VPN gateways found', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
