var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Open Oracle Auto Data Warehouse',
    category: 'Network Security Groups',
    description: 'Determine if TCP port 1522 for Oracle Auto Data Warehouse is open to the public',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Oracle Auto Data Warehouse should be restricted to known IP addresses.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/manage-network-security-group',
    recommended_action: 'Restrict TCP ports 1522 to known IP addresses',
    apis: ['networkSecurityGroups:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.networkSecurityGroups, function(location, rcb) {

            var networkSecurityGroups = helpers.addSource(
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
                'TCP': [1522]
            };

            var service = 'Oracle Auto Data Warehouse';

            helpers.findOpenPorts(networkSecurityGroups.data, ports, service, location, results);

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};