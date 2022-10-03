var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC Has Tags',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure that AWS VPC have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2020/07/amazon-vpc-resources-support-tag-on-create/',
    recommended_action: 'Modify VPCs and add new tags',
    apis: ['EC2:describeVpcs'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var awsOrGov = helpers.defaultPartition(settings);

        var regions = helpers.regions(settings);

        async.each(regions.vpc, function(region, rcb){
            var describeVpcs = helpers.addSource(cache, source, ['ec2', 'describeVpcs', region]);

            if (!describeVpcs) return rcb();

            if (describeVpcs.err || !describeVpcs.data) {
                helpers.addResult(results, 3, `Unable to query for VPCs: ${helpers.addError(describeVpcs)}`, region);
                return rcb();
            }

            if (!describeVpcs.data.length) {
                helpers.addResult(results, 0, 'No VPCs present', region);
                return rcb();
            }

            for (var v in describeVpcs.data) {
                var vpc = describeVpcs.data[v];
                // arn:${Partition}:ec2:${Region}:${Account}:vpc/${VpcId}
                var arn = 'arn:' + awsOrGov + ':ec2:' + region + ':' + vpc.OwnerId + ':vpc/' + vpc.VpcId;
                if (!vpc.Tags || !vpc.Tags.length) {
                    helpers.addResult(results, 2, 'VPC does not have tags', region, arn);
                } else {
                    helpers.addResult(results, 0, 'VPC has tags', region, arn);
                }
            }

            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
