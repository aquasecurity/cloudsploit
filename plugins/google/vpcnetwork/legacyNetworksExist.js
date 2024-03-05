var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Legacy Network Exists',
    category: 'VPC Network',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensures that your Google Cloud Project does not have legacy networks',
    more_info: 'Legacy networks have a single network IPv4 prefix range and a single gateway IP address for the whole network, they do not allow creation of subnets which can impact high network traffic projects.',
    link: 'https://cloud.google.com/vpc/docs/legacy',
    recommended_action: 'Ensure that there are no legacy networks in the GCP Project.',
    apis: ['networks:list'],
    realtime_triggers: ['compute.networks.insert', 'compute.networks.delete', 'compute.networks.patch'],

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

            networks.data.forEach(network => {
                let resource = helpers.createResourceName('networks', network.name, project, 'region', region);

                if (Object.prototype.hasOwnProperty.call(network, 'autoCreateSubnetworks')) {
                    helpers.addResult(results, 0,
                        'VPC Network is not in legacy mode', region, resource);
                } else {
                    helpers.addResult(results, 2, 'VPC Network is in legacy mode', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};