var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open Memcached',
    category: 'VPC Network',
    domain: 'Network Access Control',
    severity: 'High',
    description: 'Determines if TCP or UDP port 11211 for Memcached is open to the public',
    more_info: 'Memcached port 11211 is used for caching system and to reduce response times and the load on components. Allowing inbound traffic from any external IP address on memcached port is vulnerable to DoS attacks. It is a best practice to restrict access from specific IP addresses to port 11211.',
    link: 'https://cloud.google.com/vpc/docs/using-firewalls',
    recommended_action: 'Restrict TCP and UDP port 11211 to known IP addresses.',
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
                'udp' : [11211],
                'tcp' : [11211]
            };

            let service = 'Memcached';

            helpers.findOpenPorts(firewalls.data, ports, service, region, results, cache, source);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};