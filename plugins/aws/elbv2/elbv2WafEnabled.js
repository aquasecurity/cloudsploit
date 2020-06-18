var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 WAF Enabled',
    category: 'ELBv2',
    description: 'Ensure that all Application Load Balancers have WAF enabled.',
    more_info: 'Enabling WAF allows control over requests to the load balancer, allowing or denying traffic based off rules in the Web ACL',
    link: 'https://aws.amazon.com/blogs/aws/aws-web-application-firewall-waf-for-application-load-balancers/',
    recommended_action: '1. Enter the WAF service. 2. Enter Web ACLs and filter by the region the Application Load Balancer is in. 3. If no Web ACL is found, Create a new Web ACL in the region the ALB resides and in Resource type to associate with web ACL, select the Load Balancer. ',
    apis: ['WAFRegional:listWebACLs','WAFRegional:listResourcesForWebACL','ELBv2:describeLoadBalancers'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var myResourceArns = [];

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
                var loadBalancerARN = loadBalancer.LoadBalancerArn;
                myResourceArns.push(loadBalancerARN);
            });

            lcb();
        }, function(){
            async.each(regions.wafregional, function(region, rcb){
                var listWebACLs = helpers.addSource(cache, source,
                    ['wafregional', 'listWebACLs', region]);

                if (!listWebACLs) return rcb();

                if (listWebACLs.err || !listWebACLs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for WAFs: ' + helpers.addError(listWebACLs), region);
                    return rcb();
                }

                if (!listWebACLs.data.length) {
                    helpers.addResult(results, 0, 'No WAFs found', region);
                    return rcb();
                }

                listWebACLs.data.forEach(webACL => {

                    var webACLId = webACL.WebACLId;

                    var listResources = helpers.addSource(cache, source,
                        ['wafregional', 'listResourcesForWebACL', region, webACLId]);

                    if (!listResources || listResources.err || !listResources.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for WAf Resources: ' + helpers.addError(listResources), region, webACLId);
                        return;
                    }

                    if (listResources.data.ResourceArns) {
                        listResources.data.ResourceArns.forEach(resourceARN => {
                            var resourceType = resourceARN.split(':')[2];
                            if (resourceType == 'elasticloadbalancing') {
                                if (myResourceArns.indexOf(resourceARN) > -1) {
                                    myResourceArns.splice(myResourceArns.indexOf(resourceARN), 1);
                                }
                            }
                        });
                    }
                });

                rcb();
            }, function() {
                if (myResourceArns.length) {
                    var myResourceArnStr = myResourceArns.join(', ');

                    helpers.addResult(results, 2,
                        `The following Application Load Balancers do not have WAF Enabled: ${myResourceArnStr}`);
                } else {
                    helpers.addResult(results, 0, 'All Application Load Balancers have WAF enabled');
                }
                callback(null, results, source);
            });
        });
    }
};
