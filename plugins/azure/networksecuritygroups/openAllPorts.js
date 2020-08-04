const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Open All Ports',
    category: 'Network Security Groups',
    description: 'Ensures Network Security Groups do not expose all ports to the public',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, almost all services should be restricted to known IP addresses.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/manage-network-security-group',
    recommended_action: 'Restrict ports to known IP addresses',
    apis: ['networkSecurityGroups:listAll'],
    compliance: {
        hipaa: 'HIPAA requires strict access controls to networks and services ' +
                'processing sensitive data. Security groups are the built-in ' +
                'method for restricting access to services and should be ' +
                'configured to allow least-privilege access.',
        pci: 'PCI has explicit requirements around firewalled access to systems. ' +
             'Security groups should be properly secured to prevent access to ' +
             'backend services.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.networkSecurityGroups, function(location, rcb) {

            let networkSecurityGroups = helpers.addSource(
                cache, source, ['networkSecurityGroups', 'listAll', location]
            );

            if (!networkSecurityGroups) return rcb();

            if (networkSecurityGroups.err || !networkSecurityGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for Network Security Groups: ' + helpers.addError(networkSecurityGroups), location);
                return rcb();
            }

            if (!networkSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups found', location);
                return rcb();
            }

            let ports = {
                'TCP': ['*'],
                'UCP': ['*'],
                '*' : ['*']
            };

            let service = 'All Ports';

            helpers.findOpenPorts(networkSecurityGroups.data, ports, service, location, results);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};