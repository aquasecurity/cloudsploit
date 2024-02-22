var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Default VPC Exists',
    category: 'VPC Network',
    domain: 'Network Access Control',
    severity: 'Low',
    description: 'Ensures that your Google Cloud Project does not a default network.',
    more_info: 'The default network has a preconfigured network configuration and automatically generates some insecure firewall rules which do not get audit logged and cannot be configured to enable firewall rule logging. Moreover, the subnets in default network use the same predefined range of IP addresses which makes it impossible to use Cloud VPN or VPC Network Peering with the default network.',
    link: 'https://cloud.google.com/vpc/docs/vpc',
    recommended_action: 'Delete the default network and create a new network with a different name.',
    apis: ['networks:list'],
    realtime_triggers: ['compute.networks.insert' , 'compute.networks.delete'],

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

        async.each(regions.networks, function(region, rcb){
            let networks = helpers.addSource(
                cache, source, ['networks', 'list', region]);

            if (!networks) return rcb();

            if (networks.err || !networks.data) {
                helpers.addResult(results, 3, 'Unable to query VPC networks: ' + helpers.addError(networks), region, null, null, networks.err);
                return rcb();
            }

            if (!networks.data.length) {
                helpers.addResult(results, 0, 'No VPC networks found', region);
                return rcb();
            }

            let found;

            networks.data.forEach(network => {
                let resource = helpers.createResourceName('networks', network.name, project, 'region', region);

                if (network.name === 'default') {
                    found = true;
                    helpers.addResult(results, 2, 'Default VPC Network exists in the project', region, resource);
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'Default VPC Network does not exist in the project', region, project);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};