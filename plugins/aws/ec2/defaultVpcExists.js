var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Default VPC Exists',
    category: 'EC2',
    description: 'Determines whether the default VPC exists.',
    more_info: 'The default VPC should not be used in order to avoid launching multiple services in the same network which may not require connectivity. Each application, or network tier, should use its own VPC.',
    link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/default-vpc.html',
    recommended_action: 'Move resources from the default VPC to a new VPC created for that application or resource group.',
    apis: ['EC2:describeVpcs', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

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
                var arn = 'arn:' + awsOrGov + ':ec2:' + region + ':' + accountId + ':vpc/' + vpc.VpcId;
                if (vpc.IsDefault) {
                    helpers.addResult(results, 2, 'Default VPC present', region, arn);
                    return rcb();
                }
            }

            helpers.addResult(results, 0, 'Default VPC not present', region);
            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
