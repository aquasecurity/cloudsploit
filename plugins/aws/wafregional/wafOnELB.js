var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'WAF Regional on ELB',
    category: 'WAF',
    description: 'Ensures classic load balancers internet-facing have a WAF WebACL enabled.',
    more_info: 'Protect your LB with WAF is important for security. ELB do not support WAF. Switch to ALB.',
    link: 'https://docs.aws.amazon.com/fr_fr/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-waf',
    recommended_action: 'Switch to ALB with a WAF webacl',
    apis: ['ELB:describeLoadBalancers'],
    compliance: {
        hipaa: '.',
        pci: '.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

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
                helpers.addResult(results, 0, 'No load balancers present', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(lb, cb){
                if (lb.Scheme == 'internet-facing') {
                    helpers.addResult(results, 2, 'The ELB do not have an associated WebACL', region, lb.DNSName);
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
