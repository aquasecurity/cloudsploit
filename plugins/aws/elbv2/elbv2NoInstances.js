var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 No Instances',
    category: 'ELBv2',
    description: 'Detects ELBs that have no target groups attached',
    more_info: 'All ELBs should have backend server resources. ' +
        'Those without any are consuming costs without providing ' +
        'any functionality. Additionally, old ELBs with no target groups ' +
        'present a security concern if new target groups are accidentally attached.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html',
    recommended_action: 'Delete old ELBs that no longer have backend resources.',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeTargetGroups'],

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
                    'Unable to query for load balancers: ' + helpers.addError(describeLoadBalancers), region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers present', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(lb, cb){
                var describeTargetGroups = helpers.addSource(cache, source,
                    ['elbv2', 'describeTargetGroups', region, lb.DNSName]);

                var elbArn = lb.LoadBalancerArn;
                if (describeTargetGroups.data && describeTargetGroups.data.TargetGroups && describeTargetGroups.data.TargetGroups.length){
                    helpers.addResult(results, 0,
                        'ELB has ' + describeTargetGroups.data.TargetGroups.length + ' target groups', region, elbArn);
                } else {
                    helpers.addResult(results, 2, 'ELB does not have target groups ', region, elbArn);
                }
                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
