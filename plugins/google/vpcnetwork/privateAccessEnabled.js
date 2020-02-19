var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Private Access Enabled',
    category: 'VPC Network',
    description: 'Ensures Private Google Access is enabled for all Subnets',
    more_info: 'Private Google Access allows VM instances on a subnet to reach Google APIs and services without an IP address. This creates a more secure network for the internal communication.',
    link: 'https://cloud.google.com/vpc/docs/configure-private-google-access',
    recommended_action: '1. Enter the VPC Network service. 2. Enter the VPC. 3. Select the subnet in question. 4. Edit the subnet and enable Private Google Access.',
    apis: ['subnetworks:list'],
    compliance: {
        pci: 'PCI recommends implementing additional security features for ' +
            'any required service. This includes using secured technologies ' +
            'such as Private Google Access.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.subnetworks, function(region, rcb){
            let subnetworks = helpers.addSource(
                cache, source, ['subnetworks', 'list', region]);

            if (!subnetworks) return rcb();

            if (subnetworks.err || !subnetworks.data) {
                helpers.addResult(results, 3, 'Unable to query subnetworks: ' + helpers.addError(subnetworks), region);
                return rcb();
            };

            if (!subnetworks.data.length) {
                helpers.addResult(results, 0, 'No subnetworks present', region);
                return rcb();
            };

            var badSubnets = [];
            var regionSubnets = false;
            subnetworks.data.forEach(subnet => {
                if (subnet.creationTimestamp &&
                    !subnet.privateIpGoogleAccess) {
                    badSubnets.push(subnet.id);
                } else if (subnet.creationTimestamp) {
                    regionSubnets = true
                }
            });

            if (badSubnets.length) {
                var badSubnetStr = badSubnets.join(', ');
                helpers.addResult(results, 2,
                    `The following Subnets do not have Private Google Access Enabled: ${badSubnetStr}`, region);
            } else if (regionSubnets){
                helpers.addResult(results, 0, 'All Subnets in the Region have Private Google Access Enabled', region);
            } else {
                helpers.addResult(results, 0, 'No subnetworks present', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}