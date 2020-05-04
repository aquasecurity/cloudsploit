var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open Salt',
    category: 'EC2',
    description: 'Determine if TCP ports 4505 or 4506 for the Salt master are open to the public',
    more_info: 'Active Salt vulnerabilities, CVE-2020-11651 and CVE-2020-11652 are exploiting Salt instances exposed to the internet. These ports should be closed immediately.',
    link: 'https://help.saltstack.com/hc/en-us/articles/360043056331-New-SaltStack-Release-Critical-Vulnerability',
    recommended_action: 'Restrict TCP ports 4505 and 4506 to known IP addresses',
    apis: ['EC2:describeSecurityGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var ports = {
            'tcp': [4505, 4506]
        };

        var service = 'Salt';

        async.each(regions.ec2, function(region, rcb){
            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups present', region);
                return rcb();
            }

            helpers.findOpenPorts(describeSecurityGroups.data, ports, service, region, results);

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
