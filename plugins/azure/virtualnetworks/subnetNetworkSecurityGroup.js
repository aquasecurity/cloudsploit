var async = require('async');
var helpers = require('../../../helpers/azure');

var exemptSubnets = ['gatewaysubnet', 'azurefirewallsubnet', 'azurefirewallmanagementsubnet', 'routeserversubnet'];

module.exports = {
    title: 'Subnet Network Security Group Association',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensures that virtual network subnets are associated with a network security group.',
    more_info: 'Network security groups filter inbound and outbound traffic for a subnet using security rules. Subnets without an associated network security group do not have this filtering in place and can expose their resources to unauthorized access.',
    recommended_action: 'Associate a network security group with each subnet from the subnet security settings.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview',
    apis: ['virtualNetworks:listAll'],
    realtime_triggers: ['microsoftnetwork:virtualnetworks:write', 'microsoftnetwork:virtualnetworks:delete', 'microsoftnetwork:virtualnetworks:subnets:write', 'microsoftnetwork:virtualnetworks:subnets:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualNetworks, function(location, rcb) {
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

            var found = false;

            for (let virtualNetwork of virtualNetworks.data) {
                if (!virtualNetwork.subnets || !virtualNetwork.subnets.length) continue;

                for (let subnet of virtualNetwork.subnets) {
                    if (!subnet.id || !subnet.properties) continue;

                    if (subnet.name && exemptSubnets.includes(subnet.name.toLowerCase())) continue;

                    found = true;

                    if (subnet.properties.networkSecurityGroup && subnet.properties.networkSecurityGroup.id) {
                        helpers.addResult(results, 0, 'Subnet has a network security group associated', location, subnet.id);
                    } else {
                        helpers.addResult(results, 2, 'Subnet does not have a network security group associated', location, subnet.id);
                    }
                }
            }

            if (!found) {
                helpers.addResult(results, 0, 'No existing subnets found', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
