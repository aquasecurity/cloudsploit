var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Default Network',
    category: 'VPC Network',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensure no VM instances exist in default network.',
    more_info: 'Every GCP project comes with a default network with pre-populated firewall rules. A default network is suitable for getting started quickly, and for launching public instances for simple websites. But, if you need to host a complex multi-tier application or add more layers of security to your infrastructure it is a best practice to create non-default network with public, private subnets & demilitarized (DMZ) zones. This segregates the network based on their functionality, services, and security.',
    link: 'https://cloud.google.com/vpc/docs/vpc',
    recommended_action: 'Ensure the default network does not have any VM instances.',
    apis: ['networks:list', 'compute:list'],
    realtime_triggers: ['compute.networks.insert' , 'compute.networks.delete', 'compute.instances.insert', 'compute.instances.delete', 'compute.instances.updateNetworkInterface'],

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
        let defaultNetwork, resource;
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

            defaultNetwork = networks.data.find(network => network.name === 'default');
            if (defaultNetwork) {
                resource = helpers.createResourceName('networks', defaultNetwork.name, project, 'region', region);
            }
            rcb();
        }, function(){
            if (!defaultNetwork) {
                helpers.addResult(results, 0, 'Default Network does not exist in the project', 'global');
                return callback(null, results, source);
            }
            let instanceCount = 0;
            async.each(regions.compute, (region, rcb) => {
                var zones = regions.zones;
                async.each(zones[region], function(zone, zcb) {
                    var instances = helpers.addSource(cache, source,
                        ['compute','list', zone ]);
    
                    if (!instances) return zcb();
    
                    if (instances.err || !instances.data) {
                        helpers.addResult(results, 3, 'Unable to query compute instances', region, null, null, instances.err);
                        return zcb();
                    }
    
                    if (!instances.data.length) {
                        return zcb();
                    }
    
                    instances.data.forEach(instance => {
                        if (instance.networkInterfaces && 
                            instance.networkInterfaces.find(interface => interface.network === defaultNetwork.selfLink)) {
                            instanceCount++;
                        }
                    });
                    zcb();
                }, function() {
                    rcb();
                });
            }, function() {
                if (instanceCount > 0) {
                    helpers.addResult(results, 2, `Default Network has ${instanceCount} VM instances`, 'global', resource);
                } else {
                    helpers.addResult(results, 0, 'Default Network does not have any VM instances', 'global', resource);
                }
                callback(null, results, source);
            });
            
        });
    }
};