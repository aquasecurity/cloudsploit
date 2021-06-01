var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Open Docker',
    category: 'ECS',
    description: 'Ensure that security groups does not have TCP port 2375 or 2376 for Docker open to the public.',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Docker should be restricted to known IP addresses.',
    link: 'https://www.alibabacloud.com/help/doc-detail/25471.htm',
    recommended_action: 'Restrict TCP ports 2375 and 2376 for Docker to known IP addresses',
    apis: ['ECS:DescribeSecurityGroups', 'ECS:DescribeSecurityGroupAttribute', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var ports = {
            'tcp': [2375, 2376]
        };

        var service = 'Docker';

        async.each(regions.ecs, function(region, rcb){
            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ecs', 'DescribeSecurityGroups', region]);

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    `Unable to describe security groups: ${helpers.addError(describeSecurityGroups)}`, region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups found', region);
                return rcb();
            }

            helpers.findOpenPorts(cache, describeSecurityGroups.data, ports, service, region, results);
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
