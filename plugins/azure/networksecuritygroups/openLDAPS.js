const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Open LDAPS',
    category: 'Network Security Groups',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Determine if TCP port 636 for LDAP SSL is open to the public',
    more_info: 'LDAP SSL port 636 is used for Secure LDAP authentication. Allowing Inbound traffic from any IP address to TCP port 636 is vulnerable to DoS attacks. It is a best practice to block port 636 from the public internet.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group',
    recommended_action: 'Restrict TCP port 636 to known IP addresses.',
    apis: ['networkSecurityGroups:listAll'],
    realtime_triggers: ['microsoftnetwork:networksecuritygroups:write','microsoftnetwork:networksecuritygroups:delete','microsoftnetwork:networksecuritygroups:securityrules:write','microsoftnetwork:networksecuritygroups:securityrules:delete'],
    
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
                'TCP': [636]
            };

            let service = 'LDAPS';

            helpers.findOpenPorts(networkSecurityGroups.data, ports, service, location, results);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};