var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open LDAPS',
    category: 'VPC Network',
    domain: 'Network Access Control',
    severity: 'High',
    description: 'Determines if TCP port 636 for LDAP SSL is open to the public',
    more_info: 'LDAP SSL port 636 is used for Secure LDAP authentication. Allowing Inbound traffic from any IP address to TCP port 636 is vulnerable to DoS attacks. It is a best practice to block port 636 from the public internet.',
    link: 'https://cloud.google.com/vpc/docs/using-firewalls',
    recommended_action: 'Restrict TCP port 636 to known IP addresses.',
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
                'tcp': [636]
            };

            let service = 'LDAPS';

            helpers.findOpenPorts(firewalls.data, ports, service, region, results, cache, source);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};