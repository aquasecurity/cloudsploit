var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'No Network Gateways Connections',
    category: 'Virtual Networks',
    description: 'Ensures that virtual network gateways do not have any established connections.',
    more_info: 'To meet your organization\'s security compliance requirements.',
    link: 'https://docs.microsoft.com/en-us/azure/vpn-gateway/tutorial-site-to-site-portal',
    recommended_action: 'Delete network gateway connections',
    apis: ['resourceGroups:list', 'networkGatewayConnections:listByResourceGroup'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.resourceGroups, function(location, rcb) {
            let resourceGroups = helpers.addSource(cache, source,
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

            async.each(resourceGroups.data, function(resourceGroup, scb) {
                let networkGatewayConnections = helpers.addSource(cache, source,
                    ['networkGatewayConnections', 'listByResourceGroup', location, resourceGroup.id]);

                if (!networkGatewayConnections || networkGatewayConnections.err || !networkGatewayConnections.data) {
                    helpers.addResult(results, 3, 'Unable to query for network gateway connections : ' + helpers.addError(networkGatewayConnections), location);
                    return scb();
                }

                if (!networkGatewayConnections.data.length) {
                    helpers.addResult(results, 0, 'No connections found for network gateways', location);
                    return scb();
                }

                networkGatewayConnections.data.forEach(networkGatewayConnection => {
                    if (networkGatewayConnection.virtualNetworkGateway1 && networkGatewayConnection.virtualNetworkGateway1.id && 
                        networkGatewayConnection.virtualNetworkGateway2 && networkGatewayConnection.virtualNetworkGateway2.id) {
                        let gateway1 = networkGatewayConnection.virtualNetworkGateway1.id.split('/');
                        gateway1 = gateway1[gateway1.length - 1];
                        let gateway2 = networkGatewayConnection.virtualNetworkGateway2.id.split('/');
                        gateway2 = gateway2[gateway2.length - 1];
                        helpers.addResult(results, 2, `${gateway1} has an established connection with ${gateway2}`, location, networkGatewayConnection.virtualNetworkGateway1.id);
                        helpers.addResult(results, 2, `${gateway2} has an established connection with ${gateway1}`, location, networkGatewayConnection.virtualNetworkGateway2.id);
                    }
                });
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};