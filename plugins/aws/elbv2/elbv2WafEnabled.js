var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 WAF Enabled',
    category: 'ELBv2',
    domain: 'Content Delivery',
    description: 'Ensure that all Application Load Balancers have WAF enabled.',
    more_info: 'Enabling WAF allows control over requests to the load balancer, allowing or denying traffic based off rules in the Web ACL',
    link: 'https://aws.amazon.com/blogs/aws/aws-web-application-firewall-waf-for-application-load-balancers/',
    recommended_action: '1. Enter the WAF service. 2. Enter Web ACLs and filter by the region the Application Load Balancer is in. 3. If no Web ACL is found, Create a new Web ACL in the region the ALB resides and in Resource type to associate with web ACL, select the Load Balancer. ',
    apis: ['ELBv2:describeLoadBalancers', 'WAFV2:listWebACLs', 'WAFRegional:listWebACLs', 'WAFV2:listResourcesForWebACL', 'WAFRegional:listResourcesForWebACL'],
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var resourcesToCheck = [];

        async.each(regions.wafv2, function(region, rcb){
            var listWebACLs = helpers.addSource(cache, source,
                ['wafv2', 'listWebACLs', region]);

            var listRegionalACLs = helpers.addSource(cache, source,
                ['wafregional', 'listWebACLs', region]);

            if (!listWebACLs || !listRegionalACLs) return rcb();

            if (listWebACLs.err || !listWebACLs.data) {
                helpers.addResult(results, 3,
                    'Unable to query for WAFv2: ' + helpers.addError(listWebACLs), region);
                return rcb();
            }
            if (listRegionalACLs.err || !listRegionalACLs.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Regional WAF: ' + helpers.addError(listRegionalACLs), region);
                return rcb();
            }

            var combinedACLS = listWebACLs.data.concat(listRegionalACLs.data);

            if (!combinedACLS.length) {
                return rcb();
            }

            combinedACLS.forEach(webACL => {
                if (webACL.WebACLId) {
                    let listResources = helpers.addSource(cache, source,
                        ['wafregional', 'listResourcesForWebACL', region, webACL.WebACLId]);

                    if (listResources && listResources.data && listResources.data.ResourceArns &&
                        listResources.data.ResourceArns.length) {
                        resourcesToCheck = resourcesToCheck.concat(listResources.data.ResourceArns);
                    }
                } else if (webACL.ARN) {
                    let listResources = helpers.addSource(cache, source,
                        ['wafv2', 'listResourcesForWebACL', region, webACL.ARN]);

                    if (listResources && listResources.data && listResources.data.ResourceArns &&
                        listResources.data.ResourceArns.length) {
                        resourcesToCheck = resourcesToCheck.concat(listResources.data.ResourceArns);
                    }
                }
            });
            rcb();
        }, function(){
            async.each(regions.elbv2, function(loc, lcb){
                var loadBalancers = helpers.addSource(cache, source,
                    ['elbv2', 'describeLoadBalancers', loc]);

                if (!loadBalancers) return lcb();

                if (loadBalancers.err || !loadBalancers.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Load Balancers: ' + helpers.addError(loadBalancers), loc);
                    return lcb();
                }

                if (!loadBalancers.data.length) {
                    helpers.addResult(results, 0, 'No Load Balancers found', loc);
                    return lcb();
                }

                loadBalancers.data.forEach(loadBalancer => {
                    if (loadBalancer.LoadBalancerArn && (resourcesToCheck.indexOf(loadBalancer.LoadBalancerArn) > -1)) {
                        resourcesToCheck.splice(resourcesToCheck.indexOf(loadBalancer.LoadBalancerArn), 1);
                        helpers.addResult(results, 0, 'The Application Load Balancer has WAF enabled', loc, loadBalancer.LoadBalancerArn);
                    } else {
                        helpers.addResult(results, 2, 'The Application Load Balancer does not have WAF enabled', loc, loadBalancer.LoadBalancerArn);
                    }
                });

                lcb();
            }, function() {
                callback(null, results, source);
            });
        });
    }
};
