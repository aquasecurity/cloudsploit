var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 Deletion Protection',
    category: 'ELBv2',
    description: 'Ensures ELBv2 load balancers are configured with deletion protection.',
    more_info: 'ELBv2 load balancers should be configured with deletion protection to prevent accidental' + 
                'deletion of live resources in production environments.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection',
    recommended_action: 'Update ELBv2 load balancers to use deletion protection to prevent accidental deletion',
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

                if(!elbv2Attributes.data.Attributes || !elbv2Attributes.data.Attributes.length){
                    helpers.addResult(results, 2,
                        'Application/Network load balancer attributes not found',
                        region, resource);
                    return cb();
                }

                var found = false;

                elbv2Attributes.data.Attributes.forEach(attribute => {
                    if (attribute.Key && attribute.Key === 'deletion_protection.enabled') {
                        found = true;
                        if (attribute.Value && attribute.Value === 'true') {
                            helpers.addResult(results, 0,
                                'Load balancer :' + elb.LoadBalancerName + ': has deletion protection enabled',
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                'Load balancer :' + elb.LoadBalancerName + ': does not have deletion protection enabled',
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