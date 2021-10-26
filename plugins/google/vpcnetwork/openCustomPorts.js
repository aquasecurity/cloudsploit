var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open Custom Ports',
    category: 'VPC Network',
    description: 'Ensure that defined custom ports are not open to public.',
    more_info: 'To prevent attackers from identifying and exploiting the services running on your instances, make sure the VPC Network custom ports are not open to public.',
    link: 'https://cloud.google.com/vpc/docs/firewalls',
    recommended_action: 'Ensure that your VPC Network firewall rules do not allow inbound traffic for a range of ports.',
    apis: ['firewalls:list', 'projects:get'],
    settings: {
        restricted_open_ports: {
            name: 'Restricted Open Ports',
            description: 'Comma separated list of ports that should be restricted and not publicly open. Example: tcp:80,tcp:443',
            regex: '[a-zA-Z0-9,:]',
            default: 'tcp:80'
        },
    },


    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var restricted_open_ports = settings.restricted_open_ports || this.settings.restricted_open_ports.default;

        if (!restricted_open_ports.length) return callback(null, results, source);

        restricted_open_ports = restricted_open_ports.split(',');

        var ports = {};
        restricted_open_ports.forEach(port => {
            var [protocol, portNo] = port.split(':');
            if (ports[protocol]) {
                ports[protocol].push(parseInt(portNo));
            } else {
                ports[protocol] = [parseInt(portNo)];
            }
        });

        async.each(regions.firewalls, function(region, rcb) {
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

            helpers.findOpenPorts(firewalls.data, ports, 'custom', region, results, cache, callback, source);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};