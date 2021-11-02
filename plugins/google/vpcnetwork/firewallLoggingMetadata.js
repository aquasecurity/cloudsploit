var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Firewall Logging Metadata',
    category: 'VPC Network',
    description: 'Ensure that VPC Network firewall logging is configured to exclude logging metadata in order to reduce the size of the log files.',
    more_info: 'You can significantly reduce the size of your log files and optimize storage costs by not including metadata. By default, metadata is included in firewall rule log files.',
    link: 'https://cloud.google.com/vpc/docs/firewall-rules-logging',
    recommended_action: 'Ensure that metadata is not included in firewall rule log files.',
    apis: ['networks:list', 'firewalls:list', 'projects:get'],

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
                helpers.addResult(results, 3, 'Unable to query networks: ' + helpers.addError(networks), region, null, null, networks.err);
                return rcb();
            }

            if (!networks.data.length) {
                helpers.addResult(results, 0, 'No networks found', region);
                return rcb();
            }

            let firewalls = helpers.addSource(
                cache, source, ['firewalls', 'list', region]);

            if (!firewalls) return rcb();

            if (firewalls.err || !firewalls.data) {
                helpers.addResult(results, 3, 'Unable to query firewall rules', region, null, null, firewalls.err);
                return rcb();
            }

            if (!firewalls.data.length) {
                helpers.addResult(results, 0, 'No firewall rules found', region);
                return rcb();
            }

            var loggedMetadataVPCs = [];
            firewalls.data.forEach(firewall => {
                if (!firewall.disabled && firewall.logConfig && firewall.logConfig.enable && firewall.logConfig.metadata == 'INCLUDE_ALL_METADATA') {
                    loggedMetadataVPCs.push(firewall.network);
                }   
            });

            networks.data.forEach(network => {
                if (!network.name) return;

                let resource = helpers.createResourceName('networks', network.name, project, 'global');
                if (loggedMetadataVPCs.includes(network.selfLink)){
                    helpers.addResult(results, 2,
                        'VPC Network has firewall metadata logging enabled', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'VPC Network does not have firewall metadata logging enabled', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};