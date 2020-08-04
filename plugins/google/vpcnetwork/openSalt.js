var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Open Salt',
    category: 'VPC Network',
    description: 'Determine if TCP ports 4505 or 4506 for the Salt master are open to the public',
    more_info: 'Active Salt vulnerabilities, CVE-2020-11651 and CVE-2020-11652 are exploiting Salt instances exposed to the internet. These ports should be closed immediately.',
    link: 'https://help.saltstack.com/hc/en-us/articles/360043056331-New-SaltStack-Release-Critical-Vulnerability',
    recommended_action: 'Restrict TCP ports 4505 and 4506 to known IP addresses',
    apis: ['firewalls:list'],

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

            let ports = {
                'tcp': [4505,4506]
            };

            let service = 'Salt';

            helpers.findOpenPorts(firewalls.data, ports, service, region, results);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}