var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open HTTPS',
    category: 'EC2',
    domain: 'Compute',
    description: 'Determine if TCP port 443 for HTTPS is open to the public',
    more_info: 'While some ports are required to be open to the public to function properly, more sensitive services such as HTTPS should be restricted to known IP addresses.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Restrict TCP port 443 to known IP addresses.',
    apis: ['EC2:describeSecurityGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var ports = {
            'tcp': [443]
        };

        var service = 'HTTPS';

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

            helpers.findOpenPorts(describeSecurityGroups.data, ports, service, region, results, cache, rcb);

            rcb();
        }, function(){
            callback(null, results, source);
        });
    },
};
