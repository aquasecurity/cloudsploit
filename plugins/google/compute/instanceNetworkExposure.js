var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Network Exposure',
    category: 'Compute',
    domain: 'Compute',
    severity: 'Info',
    description: 'Check if GCP virtual machines are exposed to the internet.',
    more_info: 'Virtual machines exposed to the internet are at a higher risk of unauthorized access, data breaches, and cyberattacks. It’s crucial to limit exposure by securing access through proper configuration of network and firewall rules.',
    link: 'https://cloud.google.com/firewall/docs/firewalls',
    recommended_action: 'Secure VM instances by restricting access with properly configured security group and firewall rules.',
    apis: ['compute:list', 'firewalls:list'],
    realtime_triggers: ['compute.instances.insert', 'compute.instances.delete','compute.firewalls.insert', 'compute.firewalls.delete', 'compute.firewalls.patch'],

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


        async.each(regions.compute, (region, rcb) => {
            var zones = regions.zones;
            var noInstances = [];

            let firewalls = helpers.addSource(
                cache, source, ['firewalls', 'list', 'global']);

            if (!firewalls) return rcb();

            if (!firewalls || firewalls.err || !firewalls.data) {
                helpers.addResult(results, 3, 'Unable to query firewall rules', region, null, null, firewalls.err);
                return rcb();
            }

            if (!firewalls.data.length) {
                helpers.addResult(results, 0, 'No firewall rules found', region);
                return rcb();
            }

            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['compute','list', zone]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3, 'Unable to query compute instances', region, null, null, instances.err);
                    return zcb();
                }

                if (!instances.data.length) {
                    noInstances.push(zone);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    let networks = instance.networkInterfaces.map(nic => nic.network);
                    let tags = instance.tags && instance.tags.items ? instance.tags.items : [];
                    let serviceAccount = instance.serviceAccounts && instance.serviceAccounts[0] && instance.serviceAccounts[0].email ? instance.serviceAccounts[0].email : '';

                    let firewallRules = firewalls.data.filter(rule => {
                        let isNetworkMatch = networks.some(network => rule.network.endsWith(network));

                        let isTagMatch = rule.targetTags ? rule.targetTags.some(tag => tags.includes(tag)) : true;

                        let isServiceAccountMatch = rule.targetServiceAccounts ?
                            rule.targetServiceAccounts.includes(serviceAccount) : true;

                        return isNetworkMatch && isTagMatch && isServiceAccountMatch;
                    });


                    networks = networks.map(network => network.split('/').pop());
                    let internetExposed =  helpers.checkNetworkExposure(cache, source, networks, firewallRules, region, results);

                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);

                    if (internetExposed && internetExposed.length) {
                        helpers.addResult(results, 2, `VM is exposed to the internet through ${internetExposed}`, region, resource);
                    } else {
                        helpers.addResult(results, 0, 'VM is not exposed to the internet', region, resource);
                    }

                });
                zcb();
            }, function() {
                if (noInstances.length) {
                    helpers.addResult(results, 0, `No instances found in following zones: ${noInstances.join(', ')}`, region);
                }
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
