var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open Elasticsearch',
    category: 'VPC Network',
    domain: 'Network Access Control',
    severity: 'High',
    description: 'Determines if TCP ports 9200, 9300 for Elasticsearch are open to the public',
    more_info: 'Databases are the placeholders for most sensitive and confidential information in an organization. Allowing Inbound traffic from external IPv4 addresses to the database ports can lead to attacks like DoS, Brute Force, Smurf and reconnaissance. It is a best practice to block public access, and restrict the Inbound traffic from specific addresses and make the connection secure.',
    link: 'https://cloud.google.com/vpc/docs/using-firewalls',
    recommended_action: 'Restrict TCP ports 9200, 9300 to known IP addresses.',
    apis: ['firewalls:list'],
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

            let ports = {
                'tcp' : [9200, 9300]
            };

            let service = 'Elasticsearch';

            helpers.findOpenPorts(firewalls.data, ports, service, region, results, cache, source);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};