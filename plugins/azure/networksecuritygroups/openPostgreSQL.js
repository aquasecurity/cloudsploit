const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Open PostgreSQL',
    category: 'Network Security Groups',
    description: 'Determine if TCP port 5432 for PostgreSQL is open to the public',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as PostgreSQL should be restricted to known IP addresses.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/manage-network-security-group',
    recommended_action: 'Restrict TCP port 5432 to known IP addresses',
    apis: ['networkSecurityGroups:listAll'],

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
            
            var ports = {
                'TCP': [5432]
            };

            var service = 'PostgreSQL';

            helpers.findOpenPorts(networkSecurityGroups.data, ports, service, location, results);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};