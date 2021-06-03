var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open CIFS',
    category: 'VPC Network',
    description: 'Determines if UDP port 445 for CIFS is open to the public',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as CIFS should be restricted to known IP addresses.',
    link: 'https://cloud.google.com/vpc/docs/using-firewalls',
    recommended_action: 'Restrict UDP port 445 to known IP addresses.',
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
                'udp': [445]
            };

            let service = 'CIFS';

            helpers.findOpenPorts(firewalls.data, ports, service, region, results);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}