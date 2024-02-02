var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'No VPN Gateways',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    description: 'Ensures that virtual network gateways type is not VPC.',
    more_info: 'Use ExpressRoute as gateway type instead of VPN for virtual network gateways to meet your organization\'s security and compliance requirements.',
    link: 'https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways',
    recommended_action: 'Ensure gateway type is not configured as VPC for all virtual network gateways.',
    apis: ['resourceGroups:list','virtualNetworkGateways:listByResourceGroup'],
    realtime_triggers: ['microsoftnetwork:virtualnetworkgateways:write','microsoftnetwork:virtualnetworkgateways:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.resourceGroups, function(location, rcb) {

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

            resourceGroups.data.forEach(resourceGroup => {
                var virtualNetworkGateways = helpers.addSource(cache, source, 
                    ['virtualNetworkGateways', 'listByResourceGroup', location, resourceGroup.id]);

                if (!virtualNetworkGateways || virtualNetworkGateways.err || !virtualNetworkGateways.data) {
                    helpers.addResult(results, 3, 'Unable to query for virtual Network Gateways: ' + helpers.addError(virtualNetworkGateways), location, resourceGroup.id);
                    return;
                }
                
                if (!virtualNetworkGateways.data.length) {
                    helpers.addResult(results, 0, 'No existing virtual network gateways found', location, resourceGroup.id);
                    return;
                }
                virtualNetworkGateways.data.forEach((virtualNetworkGateway) => {
                    if (!virtualNetworkGateway) return;
                    if (virtualNetworkGateway.gatewayType && virtualNetworkGateway.gatewayType.toLowerCase() == 'vpn') {
                        helpers.addResult(results, 2,
                            'gateway is of VPN type', location, virtualNetworkGateway.id);
                    } else {
                        helpers.addResult(results, 0,
                            'gateway is not of VPN type', location, virtualNetworkGateway.id);
                    }
                });
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};