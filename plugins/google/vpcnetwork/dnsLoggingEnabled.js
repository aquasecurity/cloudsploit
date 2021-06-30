var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'VPC DNS Logging Enabled',
    category: 'VPC Network',
    description: 'Ensure that All VPC Network has DNS logging enabled.',
    more_info: 'Cloud DNS logging records the queries coming from Compute Engine VMs, GKE containers, or other GCP resources provisioned within the VPC to Stackdriver.',
    link: 'https://cloud.google.com/dns/docs/monitoring',
    recommended_action: 'Create Cloud DNS Server Policy with logging enabled for VPC Networks',
    apis: ['networks:list', 'policies:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.networks, function(region, rcb){
            let networks = helpers.addSource(
                cache, source, ['networks', 'list', region]);

            if (!networks) return rcb();

            if (networks.err || !networks.data) {
                helpers.addResult(results, 3, 'Unable to query networks: ' + helpers.addError(networks), region, null, null, networks.err);
                return rcb();
            }

            if (!networks.data.length) {
                helpers.addResult(results, 0, 'No networks found', region);
                return rcb();
            }

            let policies = helpers.addSource(
                cache, source, ['policies', 'list', region]);

            if (!policies || policies.err || !policies.data) {
                helpers.addResult(results, 3, 'Unable to query DNS policies: ' + helpers.addError(policies), region, null, null, policies.err);
                return rcb();
            }

            var loggedVpcs = [];
            policies.data.forEach(policy => {
                if (policy.enableLogging && policy.networks && policy.networks.length) {
                    policy.networks.forEach(network => {
                        if (network.networkUrl) loggedVpcs.push(network.networkUrl);
                    });
                }
            });

            networks.data.forEach(network => {
                if (loggedVpcs.includes(network.selfLink)){
                    helpers.addResult(results, 0,
                        'VPC Network has DNS logging enabled', region, network.name);
                } else {
                    helpers.addResult(results, 2,
                        'VPC Network does not have DNS logging enabled', region, network.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
