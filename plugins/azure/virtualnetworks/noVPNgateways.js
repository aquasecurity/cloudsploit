var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'No VPN Gateways',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    description: 'Ensures virtual networks do not have VPN gateways configured.',
    more_info: 'Use ExpressRoute as gateway type instead of VPN for virtual network gateways to meet your organization\'s security and compliance requirements. Azure ExpressRoute lets you extend your on-premises networks into the Microsoft cloud over a private connection with the help of a connectivity provider. With ExpressRoute, you can establish connections to Microsoft cloud services, such as Microsoft Azure and Microsoft 365.',
    link: 'https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways',
    recommended_action: 'Delete all VPN gateways for your virtual networks.',
    apis: ['resourceGroups:list','virtualNetworks:listAll','virtualNetworkGateways:listByResourceGroup'],
    realtime_triggers: ['microsoftnetwork:virtualnetworks:write','microsoftnetwork:virtualnetworks:delete','microsoftnetwork:virtualnetworkgateways:write','microsoftnetwork:virtualnetworkgateways:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualNetworks, function(location, rcb){
            var virtualNetworks = helpers.addSource(cache, source, 
                ['virtualNetworks', 'listAll', location]);

            if (!virtualNetworks) return rcb();

            if (virtualNetworks.err || !virtualNetworks.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Networks: ' + helpers.addError(virtualNetworks), location);
                return rcb();
            }

            if (!virtualNetworks.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Networks found', location);
                return rcb();
            }
            var resourceGroups = helpers.addSource(cache, source, 
                ['resourceGroups', 'list', location]);

            if (!resourceGroups || resourceGroups.err || !resourceGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for resource groups: ' + helpers.addError(resourceGroups), location);
                return rcb();
            }

            if (!resourceGroups.data.length) {
                helpers.addResult(results, 0, 'No existing resource groups found', location);
                return rcb();
            }

            let vpnGatewaysList = [];
            resourceGroups.data.forEach(resourceGroup => {
                var virtualNetworkGateways = helpers.addSource(cache, source, 
                    ['virtualNetworkGateways', 'listByResourceGroup', location, resourceGroup.id]);

                if (!virtualNetworkGateways || virtualNetworkGateways.err || !virtualNetworkGateways.data) {
                    helpers.addResult(results, 3, 'Unable to query for virtual Network Gateways: ' + helpers.addError(virtualNetworkGateways), location);
                    return;
                }
                
                if (virtualNetworkGateways.data.length) {

                    for (let virtualNetworkGateway of virtualNetworkGateways.data) {
                        if (virtualNetworkGateway.gatewayType && virtualNetworkGateway.gatewayType.toLowerCase()==='vpn')
                            vpnGatewaysList.push({id:virtualNetworkGateway.id, name: virtualNetworkGateway.name });
                    }
                }
            });
            virtualNetworks.data.forEach(virtualNetwork => {
                let vpnGatewayFound = [];
                if (virtualNetwork.subnets.length) {
                    for (let subnet of virtualNetwork.subnets) {

                        if (subnet.properties && subnet.properties.ipConfigurations && subnet.properties.ipConfigurations.length) {
                            for (let vpnGateway of vpnGatewaysList) {
                                if (subnet.properties.ipConfigurations.some(configuration => (configuration.id.toLowerCase().indexOf(vpnGateway.id.toLowerCase()) > -1))) {
                                    vpnGatewayFound.push(vpnGateway.name);
                                }
                            }
                        }
                    }
                } 
                if (!vpnGatewayFound.length) {
                    helpers.addResult(results, 0, 'Virtual network is not using VPN network gateways', location, virtualNetwork.id);
                } else {
                    helpers.addResult(results, 2, `Virtual network is using VPN network gateways: ${vpnGatewayFound.join(',')}`, location, virtualNetwork.id);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};