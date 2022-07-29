var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unused Security Groups',
    category: 'EC2',
    domain: 'Compute',
    description: 'Identify and remove unused EC2 security groups.',
    more_info: 'Keeping the number of security groups to a minimum makes the management easier and helps to avoid reaching the service limit.',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
    recommended_action: 'Remove security groups that are not being used.',
    apis: ['EC2:describeSecurityGroups', 'EC2:describeNetworkInterfaces', 'Lambda:listFunctions'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

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

            var groups = describeSecurityGroups.data;
            var usedGroups = helpers.getUsedSecurityGroups(cache, results, region);
            if (usedGroups && usedGroups.length && usedGroups[0] === 'Error') return rcb();
            for (var g in groups) {
                var resource = 'arn:aws:ec2:' + region + ':' + groups[g].OwnerId + ':security-group/' +
                               groups[g].GroupId;      
                if (groups[g].GroupId && usedGroups && usedGroups.includes(groups[g].GroupId)) {
                    helpers.addResult(results, 0, 'Security group is being used', region, resource);
                } else {
                    helpers.addResult(results, 2, 'Security group is not being used', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};