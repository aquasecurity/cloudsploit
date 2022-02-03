var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open All Ports Protocols',
    category: 'EC2',
    domain: 'Compute',
    description: 'Determine if security group has all ports or protocols open to the public',
    more_info: 'Security groups should be created on a per-service basis and avoid allowing all ports or protocols.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Modify the security group to specify a specific port and protocol to allow.',
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
            var usedGroups = helpers.getUsedSecurityGroups(cache, results, region, rcb);
          
            let strings = [];
            for (var g in groups) {
               
                var resource = 'arn:aws:ec2:' + region + ':' + groups[g].OwnerId + ':security-group/' +
                               groups[g].GroupId;      
                if (groups[g].GroupId && !usedGroups.includes(groups[g].GroupId)) {
                    strings.push(groups[g].GroupId);
                    continue;
                }
               
            }
            if (!strings.length) {
                helpers.addResult(results, 0,
                    'security groups are being used', region,
                    resource);
            }else {
                helpers.addResult(results, 2,
                    'Unused security groups'+ strings.join(' '), region,
                    resource);
                   
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};