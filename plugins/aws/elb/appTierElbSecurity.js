var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App-Tier ELB Security Policy',
    category: 'ELB',
    description: 'Ensures that AWS App-Tier ELBs are using the latest predefined security policies.',
    more_info: 'AWS App-Tier ELBs should use the latest predefined security policies to secure the connection between client and ELB.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html',
    recommended_action: 'Update App-Tier ELB reference security policy to latest predefined security policy to secure the connection between client and ELB',
    apis: ['ELB:describeLoadBalancers', 'ELB:describeLoadBalancerPolicies', 'ELB:describeTags', 'STS:getCallerIdentity'],
    settings: {
        elb_app_tier_tag_key: {
            name: 'App-Tier Tag Key',
            description: 'App-Tier tag key used by ELBs to indicate App-Tier groups',
            regex: '^.*$',
            default: ''
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

        var config = {
            elb_app_tier_tag_key : settings.elb_app_tier_tag_key || this.settings.elb_app_tier_tag_key.default,
            latest_security_policies : settings.latest_security_policies || this.settings.latest_security_policies.default
        };

        if (!config.elb_app_tier_tag_key.length) return callback(null, results, source);

        config.latest_security_policies = config.latest_security_policies.split(',');

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
                    if (Tags && Tags.Tags) {
                        for (var i in Tags.Tags){
                            var td = Tags.Tags[i];
                            if (td.Key && td.Key === config.elb_app_tier_tag_key) {
                                appTierTag = true;
                                appTierElbFound = true;
                                break;
                            }
                        }
                    }
                });

                if (appTierTag) {
                    if (!lb.LoadBalancerName || !lb.DNSName) return cb();

                    var resource = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;

                    var describeLoadBalancerPolicies = helpers.addSource(cache, source,
                        ['elb', 'describeLoadBalancerPolicies', region, lb.DNSName]);

                    if (!describeLoadBalancerPolicies ||
                        (!describeLoadBalancerPolicies.err && !describeLoadBalancerPolicies.data)) return cb();

                    if (describeLoadBalancerPolicies.err ||
                        !describeLoadBalancerPolicies.data) {
                        helpers.addResult(results, 3,
                            `Unable to query policies for ELB "${lb.LoadBalancerName}": ${helpers.addError(describeLoadBalancerPolicies)}`,
                            region, resource);
                        return cb();
                    }

                    var insecurePolicy = false;
                    var securityPolicyFound = false;
                    describeLoadBalancerPolicies.data.PolicyDescriptions.forEach(function(policyDesc) {
                        if (policyDesc.PolicyAttributeDescriptions) {
                            for (var policyAttrDesc of policyDesc.PolicyAttributeDescriptions) {
                                if (policyAttrDesc.AttributeName && policyAttrDesc.AttributeName === 'Reference-Security-Policy') {
                                    securityPolicyFound = true;
                                    if (!config.latest_security_policies.includes(policyAttrDesc.AttributeValue)) {
                                        insecurePolicy = true;
                                        break;
                                    }
                                }
                            }
                        }
                    });

                    if (securityPolicyFound) {
                        if (!insecurePolicy) {
                            helpers.addResult(results, 0,
                                `ELB  "${lb.LoadBalancerName}" is using latest predefined security policy`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `ELB "${lb.LoadBalancerName}" is not using latest predefined security policy`,
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
                if (!appTierElbFound) {
                    helpers.addResult(results, 0,
                        'No App-Tier ELB found', region);
                }
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
