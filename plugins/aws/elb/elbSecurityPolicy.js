var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB Security Policy',
    category: 'ELB',
    description: 'Ensures that AWS ELBs are using the latest predefined security policies.',
    more_info: 'AWS ELBs should use the latest predefined security policies to secure the connection between client and ELB.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html',
    recommended_action: 'Update ELB reference security policy to latest predefined security policy to secure the connection between client and ELB',
    apis: ['ELB:describeLoadBalancers', 'ELB:describeLoadBalancerPolicies', 'STS:getCallerIdentity'],
    settings: {
        latest_security_policies: {
            name: 'ELB Latest Predefined Security Policy Versions',
            description: 'A comma-delimited list of security policies that indicates the latest predefined security policy versions',
            regex: '[a-zA-Z0-9-,]',
            default: 'ELBSecurityPolicy-2016-08,ELBSecurityPolicy-TLS-1-2-2017-01,ELBSecurityPolicy-TLS-1-1-2017-01'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        
        var latest_security_policies = settings.latest_security_policies || this.settings.latest_security_policies.default;
        latest_security_policies = latest_security_policies.split(',');

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elb', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    `Unable to query for load balancers: ${helpers.addError(describeLoadBalancers)}`,
                    region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(lb, cb){
                if (!lb.DNSName) return cb();

                var resource = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;
                var describeLoadBalancerPolicies = helpers.addSource(cache, source,
                    ['elb', 'describeLoadBalancerPolicies', region, lb.DNSName]);
                
                if (!describeLoadBalancerPolicies ||
                    describeLoadBalancerPolicies.err ||
                    !describeLoadBalancerPolicies.data ||
                    !describeLoadBalancerPolicies.data.PolicyDescriptions) {
                    helpers.addResult(results, 3,
                        `Unable to query load balancer policies for ELB "${lb.LoadBalancerName}": ${helpers.addError(describeLoadBalancerPolicies)}`,
                        region, resource);
                    return cb();
                }

                var insecurePolicies = false;
                var securityPolicyFound = false;
                describeLoadBalancerPolicies.data.PolicyDescriptions.forEach(function(policyDesc) {
                    if(policyDesc && policyDesc.PolicyAttributeDescriptions){
                        for (var i in policyDesc.PolicyAttributeDescriptions) {
                            var policyAttrDesc = policyDesc.PolicyAttributeDescriptions[i];
                            if (policyAttrDesc.AttributeName === 'Reference-Security-Policy') {
                                securityPolicyFound = true;
                                if(latest_security_policies.indexOf(policyAttrDesc.AttributeValue) === -1) {
                                    insecurePolicies = true;
                                }
                                break;
                            }
                        }
                    }
                });
                
                if(securityPolicyFound){
                    if (!insecurePolicies) {
                        helpers.addResult(results, 0,
                            `ELB  "${lb.LoadBalancerName}" is using latest predefined policies`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `ELB "${lb.LoadBalancerName}" is not using latest predefined policies`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        `ELB "${lb.LoadBalancerName}" is not using any reference security policy`,
                        region,resource);
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