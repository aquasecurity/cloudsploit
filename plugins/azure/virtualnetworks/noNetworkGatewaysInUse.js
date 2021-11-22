var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'No Network Gateways In Use',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    description: 'Ensures that Virtual Networks are using subnets and network security groups instead of virtual network gateways.',
    more_info: 'Use subnets and network security groups to control network traffic instead of using virtual network gateways to meet your organization\'s security and compliance requirements.',
    link: 'https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways',
    recommended_action: 'Configure subnets and network security groups instead of virtual network gateways',
    apis: ['resourceGroups:list','virtualNetworks:listAll','virtualNetworkGateways:listByResourceGroup'],

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

            let gatewaysList = [];
            resourceGroups.data.forEach(resourceGroup => {
                var virtualNetworkGateways = helpers.addSource(cache, source, 
                    ['virtualNetworkGateways', 'listByResourceGroup', location, resourceGroup.id]);

                if (!virtualNetworkGateways || virtualNetworkGateways.err || !virtualNetworkGateways.data) {
                    helpers.addResult(results, 3, 'Unable to query for virtual Network Gateways: ' + helpers.addError(virtualNetworkGateways), location);
                    return;
                }
                
                if (virtualNetworkGateways.data.length) {
                    for (let virtualNetworkGateway of virtualNetworkGateways.data) {
                        gatewaysList.push(virtualNetworkGateway.id);
                    }
                }
            });

            virtualNetworks.data.forEach(virtualNetwork => {
                let gatewayUsed = true;
                let subnetFound = false;
                if (virtualNetwork.subnets.length) {
                    for (let subnet of virtualNetwork.subnets) {
                        if (subnet.properties && subnet.properties.ipConfigurations && subnet.properties.ipConfigurations.length) {
                            let gatewayFound = false;
                            for (let gatewayId of gatewaysList) {
                                gatewayFound = subnet.properties.ipConfigurations.some(configuration => (configuration.id.indexOf(gatewayId) > -1));
                            }

                            if (gatewayFound) {
                                subnetFound = true;
                                break;
                            }
                        }
                    }
                } else {
                    gatewayUsed = false;
                }

                if ((gatewayUsed && !subnetFound) || !gatewayUsed) {
                    helpers.addResult(results, 0, 'Virtual network is not using network gateways', location, virtualNetwork.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual network is using network gateways', location, virtualNetwork.id);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};