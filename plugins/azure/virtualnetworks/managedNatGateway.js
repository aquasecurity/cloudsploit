var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Managed NAT Gateway In Use',
    category: 'Virtual Networks',
    description: 'Ensure Azure Virtual Network Managed NAT (Network Address Translation) Gateway service is enabled for Virtual Network.',
    more_info: 'To meet your organization\'s security compliance requirements.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/nat-overview',
    recommended_action: 'Enable Virtual Network NAT gateway for Virtual Networks',
    apis: ['virtualNetworks:listAll', 'natGateways:listBySubscription'],

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
            
            let natSubnets = [];
            var natGateways = helpers.addSource(cache, source, 
                ['natGateways', 'listBySubscription', location]);

            if (!natGateways || natGateways.err || !natGateways.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Network NAT Gateways: ' + helpers.addError(natGateways), location);
                return rcb();
            }

            if (natGateways.data.length) {
                natGateways.data.forEach(natGateway => {
                    if (natGateway.subnets && natGateway.subnets.length) {
                        for (let subnet of natGateway.subnets) {
                            natSubnets.push(subnet.id);
                        }
                    }
                });
            }

            virtualNetworks.data.forEach(virtualNetwork => {
                if (!virtualNetwork.id) return;
                let found = (virtualNetwork.subnets && virtualNetwork.subnets.length) ? virtualNetwork.subnets.some(subnet => natSubnets.includes(subnet.id)) : false;

                if (found) {
                    helpers.addResult(results, 0, 'Virtual Network Managed NAT (Network Address Translation) Gateway service is enabled for Virtual Network', location, virtualNetwork.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual Network Managed NAT (Network Address Translation) Gateway service is disabled for Virtual Network', location, virtualNetwork.id);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};