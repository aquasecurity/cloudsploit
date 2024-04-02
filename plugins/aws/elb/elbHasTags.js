var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB Has Tags',
    category: 'ELB',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensure that ELBs have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AddTags.html',
    recommended_action: 'Modify ELB and add tags.',
    apis: ['ELB:describeLoadBalancers', 'ResourceGroupsTaggingAPI:getResources', 'STS:getCallerIdentity'],
    realtime_triggers: ['elasticloadbalancing:CreateLoadBalancer', 'elasticloadbalancing:AddTags', 'elasticloadbalancing:RemoveTags', 'elasticloadbalancing:DeleteLoadBalancer'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elb', 'describeLoadBalancers', region]);
                
            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for load balancers: ' + helpers.addError(describeLoadBalancers), region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }
            const arnList = [];
            for (let lb of describeLoadBalancers.data){
                if (!lb.LoadBalancerName) continue;

                var elbArn = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;
                arnList.push(elbArn);
            }
            helpers.checkTags(cache, 'ElasticLoadbalancing', arnList, region, results, settings);
            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
