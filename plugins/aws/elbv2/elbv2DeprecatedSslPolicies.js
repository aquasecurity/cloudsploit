var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 Deprecated SSL Policies',
    category: 'ELBv2',
    domain: 'Content Delivery',
    description: 'Ensure that Elbv2 listeners are configured to use the latest predefined security policies.',
    more_info: 'Insecure or deprecated security policies can expose the client and the load balancer to various vulnerabilities.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html',
    recommended_action: 'Modify ELBv2 listeners with the latest predefined AWS security policies.',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeListeners'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var deprecatedALBPolicies = [
            'ELBSecurityPolicy-2016-08',
            'ELBSecurityPolicy-TLS-1-0-2015-04',
            'ELBSecurityPolicy-TLS-1-1-2017-01',
            'ELBSecurityPolicy-FS-2018-06',
            'ELBSecurityPolicy-FS-1-1-2019-08',
            'ELBSecurityPolicy-2015-05'
        ];

        var deprecatedNLBPolicies = [
            'ELBSecurityPolicy-TLS13-1-1-2021-06',
            'ELBSecurityPolicy-TLS13-1-0-2021-06',
            'ELBSecurityPolicy-FS-1-1-2019-08',
            'ELBSecurityPolicy-FS-2018-06',
            'ELBSecurityPolicy-TLS-1-1-2017-01',
            'ELBSecurityPolicy-2016-08',
            'ELBSecurityPolicy-TLS-1-0-2015-04',
            'ELBSecurityPolicy-2015-05'
        ];

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    `Unable to query for load balancers: ${helpers.addError(describeLoadBalancers)}`,region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No Application or Network load balancers found', region);
                return rcb();
            }

            for (var alb of describeLoadBalancers.data){
                if (!alb.DNSName) continue;

                var depPolicies = [];
                var SslPolicy = false;
                var describeListeners = helpers.addSource(cache, source,
                    ['elbv2', 'describeListeners', region, alb.DNSName]);

                if (describeListeners.err || !describeListeners.data || !describeListeners.data.Listeners) {
                    helpers.addResult(results, 3, `Unable to query for Listeners: ${helpers.addError(describeListeners)}`, region, alb.LoadBalancerArn);
                    continue;
                }

                if (!describeListeners.data.Listeners.length) {
                    helpers.addResult(results, 0, 'No Listeners found for load balancer', region, alb.LoadBalancerArn);
                    continue;
                }

                describeListeners.data.Listeners.forEach(function(listener){
                    if (listener.SslPolicy) {
                        SslPolicy = true;
                        if (deprecatedALBPolicies.includes(listener.SslPolicy) || deprecatedNLBPolicies.includes(listener.SslPolicy)) {
                            depPolicies.push(listener.SslPolicy);
                        }
                    }
                });
                if (!SslPolicy){
                    helpers.addResult(results, 0,'No SSL policies found for load balancer', region, alb.LoadBalancerArn);
                } else if (depPolicies && depPolicies.length){
                    helpers.addResult(results, 2, 'Load balancer listeners are using these deprecated policies : ' + depPolicies.join(', '), region, alb.LoadBalancerArn);
                } else {
                    helpers.addResult(results, 0, 'Load balancer listeners are using current SSL policies', region, alb.LoadBalancerArn);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};