var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Private Access Enabled',
    category: 'VPC Network',
    description: 'Ensures Private Google Access is enabled for all Subnets',
    more_info: 'Private Google Access allows VM instances on a subnet to reach Google APIs and services without an IP address. This creates a more secure network for the internal communication.',
    link: 'https://cloud.google.com/vpc/docs/configure-private-google-access',
    recommended_action: '1. Enter the VPC Network service. 2. Enter the VPC. 3. Select the subnet in question. 4. Edit the subnet and enable Private Google Access.',
    apis: ['subnetworks:list', 'projects:get'],
    compliance: {
        pci: 'PCI recommends implementing additional security features for ' +
            'any required service. This includes using secured technologies ' +
            'such as Private Google Access.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.subnetworks, function(region, rcb){
            let subnetworks = helpers.addSource(
                cache, source, ['subnetworks', 'list', region]);

            if (!subnetworks) return rcb();

            if (subnetworks.err || !subnetworks.data) {
                helpers.addResult(results, 3, 'Unable to query subnetworks: ' + helpers.addError(subnetworks), region, null, null, subnetworks.err);
                return rcb();
            }

            if (!subnetworks.data.length) {
                helpers.addResult(results, 0, 'No subnetworks present', region);
                return rcb();
            }

            let found = false;
            subnetworks.data.forEach(subnet => {
                let resource = helpers.createResourceName('subnetworks', subnet.name, project, 'region', region);

                if (subnet.creationTimestamp &&
                    !subnet.privateIpGoogleAccess) {
                    found = true;
                    helpers.addResult(results, 2,
                        'Subnet does not have Private Google Access Enabled', region, resource);
                } else if (subnet.creationTimestamp) {
                    found = true;
                    helpers.addResult(results, 0, 'Subnet has Private Google Access Enabled', region, resource);
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'No subnetworks present', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};