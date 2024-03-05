var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open Internal web',
    category: 'VPC Network',
    domain: 'Network Access Control',
    severity: 'High',
    description: 'Determines if internal web port 8080 is open to the public',
    more_info: 'Internal web port 8080 is used for web applications and proxy services. Allowing Inbound traffic from any IP address to TCP port 8080 is vulnerable to exploits like backdoor trojan attacks. It is a best practice to block port 8080 from the public internet.',
    link: 'https://cloud.google.com/vpc/docs/using-firewalls',
    recommended_action: 'Restrict TCP port 8080 to known IP addresses.',
    apis: ['firewalls:list'],
    realtime_triggers: ['compute.firewalls.insert', 'compute.firewalls.delete', 'compute.firewalls.patch'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.firewalls, function(region, rcb){
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

            let ports = {
                'tcp': [8080]
            };

            let service = 'Internal Web';

            helpers.findOpenPorts(firewalls.data, ports, service, region, results, cache, source);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};