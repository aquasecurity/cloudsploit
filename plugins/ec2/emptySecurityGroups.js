var async = require('async');
var helpers = require('../../helpers');

module.exports = {
    title: 'Empty Security Groups',
    category: 'EC2',
    description: 'Ensures that all security groups have rules to help \
        reduce management overhead and prevent future unexpected behavior',
    more_info: 'Security groups should be maintained with old groups deleted \
            if they no longer contain rules. This helps reduce the \
            management overhead of maintaining groups, as well as prevents \
            the accidental change of behavior if rules are added in the future.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#default-security-group',
    recommended_action: 'Delete security groups that contain no rules.',
    apis: ['EC2:describeSecurityGroups', 'EC2:describeInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        async.each(helpers.regions.ec2, function(region, rcb){
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

            async.each(describeSecurityGroups.data, function(sg, cb){
                // get instances for segurity groups
                var describeGroupInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);
                var resource = 'arn:aws:ec2:' + region + ':' + sg.OwnerId + ':security-group/' + sg.GroupId;

                if (!describeGroupInstances.data.length) {
                    helpers.addResult(results, 2, 'No Instances found ', region, resource);
                } else {
                    helpers.addResult(results, 0, 'Instances Found ', region, resource);
                }

            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
