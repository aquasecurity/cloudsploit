var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open All Ports Egress',
    category: 'VPC Network',
    domain: 'Network Access Control',
    severity: 'High',
    description: 'Ensure no firewall rules allow egress to all ports and protocols.',
    more_info: 'Allowing outbound traffic to all protocols and ports can lead to internal resources accessing unwanted and untrusted resources. It is a best practice to follow the principle of least privilege, and grant access to only required protocols and ports.',
    link: 'https://cloud.google.com/vpc-service-controls/docs/ingress-egress-rules',
    recommended_action: 'Restrict outbound traffic to only required protocols and ports.',
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

            helpers.findOpenAllPortsEgress(firewalls.data, region, results, cache, source);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};