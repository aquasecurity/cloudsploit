var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open SNMP',
    category: 'VPC Network',
    domain: 'Network Access Control',
    description: 'Determines if UDP port 161 for SNMP is open to the public',
    more_info: 'SNMP UDP 161 used by various devices and applications for logging events, monitoring and management. Allowing Inbound traffic from any external IP address on port 161 is vulnerable to  DoS attack. It is a best practice to block port 161 completely unless explicitly required.',
    link: 'https://cloud.google.com/vpc/docs/using-firewalls',
    recommended_action: 'Restrict UDP port 161 to known IP addresses.',
    apis: ['firewalls:list'],

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
                'udp': [161]
            };

            let service = 'SNMP';

            helpers.findOpenPorts(firewalls.data, ports, service, region, results, cache, source);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};