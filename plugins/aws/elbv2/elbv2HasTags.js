var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 Has Tags',
    category: 'ELBv2',
    domain: 'Content Delivery',
    description: 'Ensure that ELBv2 load balancers have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AddTags.html',
    recommended_action: 'Modify ELBv2 and add tags.',
    apis: ['ELBv2:describeLoadBalancers', 'ResourceGroupsTaggingAPI:getResources'],
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Application/Network load balancers: ' + helpers.addError(describeLoadBalancers), region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No Application/Network load balancers found', region);
                return rcb();
            }
            const arnList = [];
            for (let lb of describeLoadBalancers.data){
                arnList.push(lb.LoadBalancerArn);
            }
            helpers.checkTags(cache, 'ElasticLoadbalancing', arnList, region, results);
            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
