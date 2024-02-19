const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Open Elasticsearch',
    category: 'Network Security Groups',
    domain: 'Network Access Control',
    severity: 'High',
    description: 'Determine if TCP port 9200 or 9300 for Elasticsearch is open to the public',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Elasticsearch should be restricted to known IP addresses.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group',
    recommended_action: 'Restrict TCP port 9200 or 9300 to known IP addresses',
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
                'TCP': [9200, 9300]
            };

            let service = 'Elasticsearch';

            helpers.findOpenPorts(networkSecurityGroups.data, ports, service, location, results);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};