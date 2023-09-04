const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Open SNMP',
    category: 'Network Security Groups',
    domain: 'Network Access Control',
    description: 'Determine if UDP port 161 for SNMP is open to the public',
    more_info: 'SNMP UDP 161 used by various devices and applications for logging events, monitoring and management. Allowing Inbound traffic from any external IP address on port 161 is vulnerable to DoS attack. It is a best practice to block port 161 completely unless explicitly required.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/manage-network-security-group',
    recommended_action: 'Restrict UDP port 161 to known IP addresses.',
    apis: ['networkSecurityGroups:listAll'],
    
    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.networkSecurityGroups, function(location, rcb) {

            let networkSecurityGroups = helpers.addSource(cache, source,
                ['networkSecurityGroups', 'listAll', location]);

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
                'UDP': [161],
            };

            let service = 'SNMP';

            helpers.findOpenPorts(networkSecurityGroups.data, ports, service, location, results);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};