var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App-Tier ELB Security Policy',
    category: 'ELB',
    description: 'Ensures that AWS App-Tier ELBs are using the latest predefined security policies.',
    more_info: 'AWS  App-Tier ELBs should use the latest predefined security policies to secure the connection between client and ELB.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html',
    recommended_action: 'Update App-Tier ELB reference security policy to latest predefined security policy to secure the connection between client and ELB',
    apis: ['ELB:describeLoadBalancers', 'ELB:describeLoadBalancerPolicies', 'ELB:describeTags', 'STS:getCallerIdentity'],
    settings: {
        app_tier_tag_key: {
            name: 'Auto Scaling App-Tier Tag Key',
            description: 'App-Tier tag key used by Auto Scaling groups to indicate App-Tier groups',
            regex: '[a-zA-Z0-9-,]',                                                                  //TODO using _ in default
            default: 'app_tier'
        },
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

        var app_tier_tag_key = settings.app_tier_tag_key || this.settings.app_tier_tag_key.default;
        var latest_security_policies = settings.latest_security_policies || this.settings.latest_security_policies.default;

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

            var appTierElbFound = false;
            async.each(describeLoadBalancers.data, function(lb, cb){
                var describeTags = helpers.addSource(cache, source,
                    ['elb', 'describeTags', region, lb.LoadBalancerName]);

                if (!describeTags ||
                    describeTags.err ||
                    !describeTags.data ||
                    !describeTags.data.TagDescriptions) {
                    helpers.addResult(results, 3,
                        `Unable to query load balancer tags for ELB "${lb.LoadBalancerName}": ${helpers.addError(describeLoadBalancerPolicies)}`,
                        region, resource);
                    return cb();
                }
                
                var appTierTag = false;
                describeTags.data.TagDescriptions.forEach(function(Tags) {
                    if(Tags && Tags.Tags) {
                        Tags.Tags.forEach(function(td) {                           //TODO use for loop and break
                            if(td.Key === app_tier_tag_key) {
                                appTierTag = true;
                                appTierElbFound = true;
                            }
                        });
                    }
                });

                if (appTierTag) {
                    var resource = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;

                    var describeLoadBalancerPolicies = helpers.addSource(cache, source,
                        ['elb', 'describeLoadBalancerPolicies', region, lb.DNSName]);                //TODO can't use elb name?

                    if (!describeLoadBalancerPolicies ||
                        describeLoadBalancerPolicies.err ||
                        !describeLoadBalancerPolicies.data ||
                        !describeLoadBalancerPolicies.data.PolicyDescriptions) {
                        helpers.addResult(results, 3,
                            `Unable to query policies for ELB "${lb.LoadBalancerName}": ${helpers.addError(describeLoadBalancerPolicies)}`,
                            region, resource);
                        return cb();
                    }

                    var insecurePolicies = false;
                    var securityPolicyFound = false;
                    describeLoadBalancerPolicies.data.PolicyDescriptions.forEach(function(policyDesc) {
                        if(policyDesc && policyDesc.PolicyAttributeDescriptions) {                   //No need to check policyDesc
                            for (var i in policyDesc.PolicyAttributeDescriptions) {
                                var policyAttrDesc = policyDesc.PolicyAttributeDescriptions[i];
                                if (policyAttrDesc.AttributeName === 'Reference-Security-Policy') {              //if policyAttrDesc && ...
                                    securityPolicyFound = true;
                                    if(latest_security_policies.indexOf(policyAttrDesc.AttributeValue) === -1) {
                                        insecurePolicies = true;
                                    }
                                    break;
                                }
                            }
                        }
                    });

                    if(securityPolicyFound) {
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
                            region, resource);
                    }
                }
                cb();
            }, function(){
                rcb();
            });

            if (!appTierElbFound) {
                helpers.addResult(results, 0,
                    'No App-Tier ELB found', region);
            }
        }, function(){
            callback(null, results, source);
        });
        

    }
};