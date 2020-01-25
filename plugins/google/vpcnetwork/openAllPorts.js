var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open All Ports',
    category: 'VPC Network',
    description: 'Determines if all ports are open to the public',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, services should be restricted to known IP addresses.',
    link: 'https://cloud.google.com/vpc/docs/using-firewalls',
    recommended_action: 'Restrict ports to known IP addresses.',
    apis: ['firewalls:list'],
    compliance: {
        hipaa: 'HIPAA requires strict access controls to networks and services ' +
            'processing sensitive data. Firewalls are the built-in ' +
            'method for restricting access to services and should be ' +
            'configured to allow least-privilege access.',
        pci: 'PCI has explicit requirements around firewalled access to systems. ' +
            'Firewalls should be properly secured to prevent access to ' +
            'backend services.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.firewalls, function(region, rcb){
            let firewalls = helpers.addSource(
                cache, source, ['firewalls', 'list', region]);

            if (!firewalls) return rcb();

            if (firewalls.err || !firewalls.data) {
                helpers.addResult(results, 3, 'Unable to query firewall rules: ' + helpers.addError(firewalls), region);
                return rcb();
            }

            if (!firewalls.data.length) {
                helpers.addResult(results, 0, 'No firewall rules found', region);
                return rcb();
            }

            helpers.findOpenAllPorts(firewalls.data, region, results);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}