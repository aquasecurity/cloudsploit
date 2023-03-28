var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 Cross-Zone Load Balancing',
    category: 'ELBv2',
    domain: 'Content Delivery',
    description: 'Ensures that AWS ELBv2 have cross-zone load balancing enabled.',
    more_info: 'AWS ELBv2 should have cross-zone load balancing enabled to distribute the traffic evenly across the registered instances in all enabled Availability Zones.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-disable-crosszone-lb.html',
    recommended_action: 'Update AWS ELBv2 to enable cross zone load balancing',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeLoadBalancerAttributes'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        
        async.each(regions.elbv2, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();
            
            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Application/Network load balancers: ' +  helpers.addError(describeLoadBalancers),
                    region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No Application/Network load balancers found', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(elb, cb){
                var resource = elb.LoadBalancerArn;

                var elbv2Attributes = helpers.addSource(cache, source,
                    ['elbv2', 'describeLoadBalancerAttributes', region, elb.DNSName]);

                if (!elbv2Attributes || elbv2Attributes.err || !elbv2Attributes.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Application/Network load balancer attributes: ' +  helpers.addError(elbv2Attributes),
                        region, resource);
                    return cb();
                }

                if (!elbv2Attributes.data.Attributes || !elbv2Attributes.data.Attributes.length){
                    helpers.addResult(results, 2,
                        'Application/Network load balancer attributes not found',
                        region, resource);
                    return cb();
                }

                var found = false;
                elbv2Attributes.data.Attributes.forEach(attribute => {
                    if (attribute.Key && attribute.Key === 'load_balancing.cross_zone.enabled') {
                        found = true;
                        if (attribute.Value && attribute.Value === 'true') {
                            helpers.addResult(results, 0,
                                'Load balancer :' + elb.LoadBalancerName + ': has cross-zone load balancing enabled',
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                'Load balancer :' + elb.LoadBalancerName + ': does not have cross-zone load balancing enabled',
                                region, resource);
                        }
                    }
                });

                if (!found) {
                    helpers.addResult(results, 2, 'Deletion protection not found', region, resource);
                }

                cb();
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};