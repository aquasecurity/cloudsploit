var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Network ACL has Tags',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that Amazon Network ACLs have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Network ACL and add tags.',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html',
    apis: ['EC2:describeNetworkAcls', 'STS:getCallerIdentity'],
    realtime_triggers: ['ec2:CreateNetworkAcl', 'ec2:AddTags', 'ec2:DeleteTags', 'ec2:DeleteNetworkAcl'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeNetworkAcls = helpers.addSource(cache, source,
                ['ec2', 'describeNetworkAcls', region]);

            if (!describeNetworkAcls) return rcb();

            if (describeNetworkAcls.err || !describeNetworkAcls.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Network ACLs: ${helpers.addError(describeNetworkAcls)}`, region);
                return rcb();
            }

            if (!describeNetworkAcls.data.length) {
                helpers.addResult(results, 0, 'No Network ACLs found', region);
                return rcb();
            }
            for (let nAcl of describeNetworkAcls.data) {
                if (!nAcl.NetworkAclId) continue;

                var resourceARN = `arn:${awsOrGov}:ec2:${region}:${accountId}:network-acl/${nAcl.NetworkAclId}`;

                if (!nAcl.Tags || !nAcl.Tags.length) {
                    helpers.addResult(results, 2, 'Network ACL does not have tags', region, resourceARN);
                } else {
                    helpers.addResult(results, 0, 'Network ACL has tags', region, resourceARN);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};