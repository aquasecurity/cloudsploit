var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Security Group Has Tags',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure that AWS Security Groups have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2021/07/amazon-ec2-adds-resource-identifiers-tags-vpc-security-groups-rules/',
    recommended_action: 'Update Security Group and add Tags',
    apis: ['EC2:describeSecurityGroups'],

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

            for (var sg of describeSecurityGroups.data) {
                const arn = `arn:aws:ec2:${region}:${sg.OwnerId}:security-group/${sg.GroupId}`;
                if (!sg.Tags || !sg.Tags.length) {
                    helpers.addResult(results, 2, 'Security group does not have tags', region, arn);
                } else {
                    helpers.addResult(results, 0, 'Security group has tags', region, arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
