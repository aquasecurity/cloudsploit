var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open LDAP',
    category: 'VPC Network',
    domain: 'Network Access Control',
    description: 'Determines if TCP or UDP port 389 for LDAP is open to the public',
    more_info: 'Allowing Inbound traffic from external IPv4 addresses to LDAP ports can lead to attacks like DoS, Brute Force, Smurf, and reconnaissance. It is a best practice to restrict the Inbound traffic from specific addresses.',
    link: 'https://cloud.google.com/vpc/docs/using-firewalls',
    recommended_action: 'Restrict TCP and UDP port 389 to known IP addresses.',
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
                'udp' : [389],
                'tcp' : [389]
            };

            let service = 'LDAP';

            helpers.findOpenPorts(firewalls.data, ports, service, region, results, cache, source);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};