var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 Insecure Ciphers',
    category: 'ELBv2',
    domain: 'Content Delivery',
    description: "Ensure that Elbv2 listeners are configured to use the latest predefined security policies.",
    more_info: 'Insecure or deprecated security policies can expose the client and the load balancer to various vulnerabilities.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html',
    recommended_action: 'Modify ELBv2 listeners with the latest predefined AWS security policies.',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeListeners'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var deprecatedALBCipherPolicies = [
            'ELBSecurityPolicy-TLS-1-2-2017-01',
            'ELBSecurityPolicy-TLS-1-2-Ext-2018-06',
            'ELBSecurityPolicy-FS-1-2-2019-08',
            'ELBSecurityPolicy-FS-1-2-Res-2019-08',
        ];

        var deprecatedNLBCipherPolicies = [
            'ELBSecurityPolicy-TLS13-1-2-2021-06',
            'ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06',
            'ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06',
            'ELBSecurityPolicy-FS-1-2-Res-2020-10',
            'ELBSecurityPolicy-FS-1-2-Res-2019-08',
            'ELBSecurityPolicy-FS-1-2-2019-08',
            'ELBSecurityPolicy-TLS-1-2-Ext-2018-06',
            'ELBSecurityPolicy-TLS-1-2-2017-01',
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
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            for (var alb of describeLoadBalancers.data){
                if (!alb.DNSName) continue;

                var depPolicies = [];
                var SslPolicy = false;
                var describeListeners = helpers.addSource(cache, source,
                    ['elbv2', 'describeListeners', region, alb.DNSName]);

                if (describeListeners.err || !describeListeners.data || !describeListeners.data.Listeners) {
                    helpers.addResult(results, 3, `Unable to query for Listeners: ${helpers.addError(describeListeners)}`, region);
                    continue;
                }

                if (!describeListeners.data.Listeners.length) {
                    helpers.addResult(results, 0, 'No Listeners found', region, alb.LoadBalancerArn);
                    continue;
                }

                describeListeners.data.Listeners.forEach(function(listener){
                    if (listener.SslPolicy) {
                        SslPolicy = true;
                        if (deprecatedALBCipherPolicies.includes(listener.SslPolicy) || deprecatedNLBCipherPolicies.includes(listener.SslPolicy)) {
                            depPolicies.push(listener.SslPolicy);
                        }
                    }
                });
                if (!SslPolicy){
                    helpers.addResult(results, 0,'No SSL policies found', region, alb.LoadBalancerArn);
                } else if (depPolicies && depPolicies.length){
                    helpers.addResult(results, 2, `The listeners on "${alb.LoadBalancerName}" are using following policies which contains insecure ciphers ` + depPolicies.join(', '), region, alb.LoadBalancerArn);
                } else if (depPolicies && !depPolicies.length){
                    helpers.addResult(results, 0, `All listeners on "${alb.LoadBalancerName}" are using policies which contains secure ciphers`, region, alb.LoadBalancerArn);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};