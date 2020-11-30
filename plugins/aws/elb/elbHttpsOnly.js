var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB HTTPS Only',
    category: 'ELB',
    description: 'Ensures ELBs are configured to only accept' + 
                 ' connections on HTTPS ports.',
    more_info: 'For maximum security, ELBs can be configured to only'+
                ' accept HTTPS connections. Standard HTTP connections '+
                ' will be blocked. This should only be done if the '+
                ' client application is configured to query HTTPS '+
                ' directly and not rely on a redirect from HTTP.',
    link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html',
    recommended_action: 'Remove non-HTTPS listeners from load balancer.',
    apis: ['ELB:describeLoadBalancers', 'STS:getCallerIdentity'],
    remediation_description: 'All HTTP Listeners will be deleted',
    remediation_min_version: '202011062139',
    apis_remediate: ['ELB:describeLoadBalancers'],
    actions: {remediate: ['ELB:deleteLoadBalancerListeners'], rollback: ['ELB:createLoadBalancerListeners']},
    permissions: {remediate: ['elasticloadbalancing:DeleteLoadBalancerListeners'], rollback: ['elasticloadbalancing:CreateLoadBalancerListeners']},
    realtime_triggers: ['elasticloadbalancing:CreateLoadBalancerListeners','elasticloadbalancing:CreateLoadBalancer'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elb', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    `Unable to query for load balancers: ${helpers.addError(describeLoadBalancers)}`, region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(lb, cb){
                // arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name
                var elbArn = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;

                if(!lb.ListenerDescriptions.length) {
                    helpers.addResult(results, 0,
                        `ELB "${lb.LoadBalancerName}" is not using any listeners`,
                        region, elbArn);
                    return cb();
                }

                // loop through listeners
                var non_https_listeners = [];
                lb.ListenerDescriptions.forEach(function(listener){
                    // if it is not https add errors to results
                    if (listener.Listener.Protocol !== 'HTTPS' && listener.Listener.Protocol !== 'SSL'){
                        non_https_listeners.push(
                            `${listener.Listener.Protocol}/${listener.Listener.LoadBalancerPort}`
                        );
                    }
                });

                if (non_https_listeners.length) {
                    helpers.addResult(
                        results, 2,
                        `Elb "${lb.LoadBalancerName}" is using these listeners ${non_https_listeners.join(', ')} without HTTPS protocol`,
                        region, elbArn);
                } else {
                    helpers.addResult(results, 0,
                        `ELB "${lb.LoadBalancerName}" is using listeners with HTTPS protocol only`,
                        region, elbArn);
                }
                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'elbHttpsOnly';
        var elbName;

        if (resource && resource.length) {
            elbName = resource.split('/')[1];
            config.region = resource.split(':')[3];
        } else {
            return callback('No resource to remediate');
        }
        var describeLoadBalancers;
        if (cache['elb'] &&
            cache['elb']['describeLoadBalancers'] &&
            cache['elb']['describeLoadBalancers'][config.region] &&
            cache['elb']['describeLoadBalancers'][config.region].data) {
            describeLoadBalancers = cache['elb']['describeLoadBalancers'][config.region].data;
        } else {
            return callback('Unable to query for ELB');
        }

        var failingLoadBalancer = describeLoadBalancers.find(loadBalancer => {
            if (loadBalancer.LoadBalancerName === elbName) {
                return loadBalancer;
            }
        });

        var failingIps = [];
        if (failingLoadBalancer && failingLoadBalancer.ListenerDescriptions && failingLoadBalancer.ListenerDescriptions.length) {
            failingLoadBalancer.ListenerDescriptions.forEach(listener => {
                if (listener.Listener.Protocol === 'HTTP') {
                    failingIps.push(listener.Listener.LoadBalancerPort);
                }
            });
        } else {
            return callback(`No listeners found for ELB: ${resource}`);
        }

        if (!failingIps.length) {
            return callback('No failing listeners found');
        }

        var params = {
            'LoadBalancerName': elbName,
            'LoadBalancerPorts': failingIps
        };


        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Listener': 'Deleted',
            'LoadBalancerName': elbName,
            'LoadBalancerPorts': failingIps
        };

        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'LISTENERS_DELETED',
                'LoadBalancerName': elbName,
                'LoadBalancerPorts': failingIps
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
