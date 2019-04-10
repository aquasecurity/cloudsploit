var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'WAF Regional on ALB',
    category: 'WAF',
    description: 'Ensures internet-facing ALB have a WAF WebACL',
    more_info: 'internet-facing ALB need to be protected by a WAF Webacl.',
    recommended_action: 'Add a WebACL to your ALB.',
    link: 'http://xxxx',
    apis: ['WAFRegional:listWebACLs', 'WAFRegional:listALBForWebACL', 'ELBv2:describeLoadBalancers'],
    compliance: {
        hipaa: '.',
        pci: '.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.wafregional, function(region, rcb) {
                var protectedALB = [];
                var listWebACL = helpers.addSource(cache, source,
                    ['wafregional', 'listWebACLs', region]);

                if (!listWebACL) return rcb();

                if (listWebACL.err || !listWebACL.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for WAFRegional WebACL: ' + helpers.addError(listWebACL), region);
                    return rcb();
                }

                hasError = false;
                listWebACL.data.forEach(function(webacl) {
                    var listALB = helpers.addSource(cache, source, ['wafregional', 'listALBForWebACL', region, webacl.WebACLId]);
                    if (listALB.err || !listALB.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for associated ALB for WAFRegional WebACL: ' + helpers.addError(listALB), region, webacl.Name + '(' + webacl.WebACLId + ')');
                        hasError = true;
                    } else {
                        protectedALB = protectedALB.concat(listALB.data);
                    }
                });

                if (hasError) return rcb();

                var describeLoadBalancers = helpers.addSource(cache, source, ['elbv2', 'describeLoadBalancers', region]);

                if (!describeLoadBalancers) return rcb();

                if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for ALB: ' + helpers.addError(describeLoadBalancers), region);
                    return rcb();
                }

                if (!describeLoadBalancers.data.length) {
                    helpers.addResult(results, 0, 'No ALB present', region);
                    return rcb();
                }

                describeLoadBalancers.data.forEach(function(alb) {
                    if (alb.Scheme == 'internet-facing') {
                        if (protectedALB.includes(alb.LoadBalancerArn)) {
                            helpers.addResult(results, 0,
                                'The ALB have an associated WebACL',
                                region, alb.LoadBalancerArn);
                        } else {
                            helpers.addResult(results, 2,
                                'The ALB do not have an associated WebACL',
                                region, alb.LoadBalancerArn);
                        }
                    }
                });
                rcb();
            }, function() {
                callback(null, results, source);
            });
    }
};