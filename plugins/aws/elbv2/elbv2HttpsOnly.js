var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 HTTPS Only',
    category: 'ELBv2',
    description: 'Ensures ELBs are configured to only accept' +
        ' connections on HTTPS ports.',
    more_info: 'For maximum security, ELBs can be configured to only'+
        ' accept HTTPS connections. Standard HTTP connections '+
        ' will be blocked. This should only be done if the '+
        ' client application is configured to query HTTPS '+
        ' directly and not rely on a redirect from HTTP.',
    link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html',
    recommended_action: 'Remove non-HTTPS listeners from load balancer.',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeListeners'],
    remediation_description: 'All HTTP Listeners will be deleted',
    remediation_min_version: '202011062139',
    apis_remediate: ['ELBv2:describeLoadBalancers','ELBv2:describeListeners'],
    actions: {remediate: ['ELBv2:deleteListener'], rollback: ['ELBv2:createListener']},
    permissions: {remediate: ['elasticloadbalancing:DeleteListener'], rollback: ['elasticloadbalancing:CreateListener']},
    realtime_triggers: ['elasticloadbalancing:CreateListener','elasticloadbalancing:CreateLoadBalancer'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

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
                var describeListeners = helpers.addSource(cache, source,
                    ['elbv2', 'describeListeners', region, lb.DNSName]);

                // loop through listeners
                var non_https_listener = [];
                var noListeners = true;
                var elbArn = lb.LoadBalancerArn;
                if (describeListeners.data && describeListeners.data.Listeners && describeListeners.data.Listeners.length) {
                    noListeners = false;
                    describeListeners.data.Listeners.forEach(function(listener){
                        // if it is not https add errors to results
                        if (listener.Protocol && listener.Port && (listener.Protocol !== 'HTTPS' && listener.Protocol !== 'SSL')) {
                            non_https_listener.push(
                                listener.Protocol + ' / ' +
                                listener.Port
                            );
                        }

                    });
                }
                if (non_https_listener && non_https_listener.length){
                    var msg = 'The following listeners are not using HTTPS-only: ';
                    helpers.addResult(results, 2,
                        msg + non_https_listener.join(', '), region, elbArn);
                }else if (non_https_listener && !non_https_listener.length) {
                    helpers.addResult(results, 0, 'All listeners are HTTPS-only', region, elbArn);
                } else if (noListeners) {
                    helpers.addResult(results, 0, 'No listeners found', region, elbArn);
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
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;
        var pluginName = 'elbv2HttpsOnly';
        var actions = [];
        var errors = [];

        if (resource && resource.length) {
            config.region = resource.split(':')[3];
        } else {
            return callback('No resource to remediate');
        }
        var describeLoadBalancers;

        if (cache['elbv2'] &&
            cache['elbv2']['describeLoadBalancers'] &&
            cache['elbv2']['describeLoadBalancers'][config.region] &&
            cache['elbv2']['describeLoadBalancers'][config.region].data &&
            cache['elbv2']['describeLoadBalancers'][config.region].data.length) {
            describeLoadBalancers = cache['elbv2']['describeLoadBalancers'][config.region].data;
        } else {
            return callback('Unable to query for load balancers');
        }

        resource = resource.replace('listener', 'loadbalancer');
        resource = resource.split('/');
        resource.pop();
        resource = resource.join('/');

        var failingLoadBalancer = describeLoadBalancers.find(loadBalancer => {
            return loadBalancer.LoadBalancerArn === resource;
        });

        if (!failingLoadBalancer || !failingLoadBalancer.DNSName) {
            return callback('Unable to query for ELBv2 Listeners');
        }
        var failingDNSName = failingLoadBalancer.DNSName;
        var describeListeners;

        if (cache['elbv2'] &&
            cache['elbv2']['describeListeners'] &&
            cache['elbv2']['describeListeners'][config.region] &&
            cache['elbv2']['describeListeners'][config.region][failingDNSName] &&
            cache['elbv2']['describeListeners'][config.region][failingDNSName].data &&
            cache['elbv2']['describeListeners'][config.region][failingDNSName].data.Listeners) {
            describeListeners = cache['elbv2']['describeListeners'][config.region][failingDNSName].data.Listeners;
        } else {
            return callback('Unable to query for ELBv2 Listeners');
        }

        var failingListeners = describeListeners.filter(listener => {
            if (listener.Protocol === 'HTTP') {
                return listener;
            }
        });
        if (!failingListeners || !failingListeners.length) {
            return callback('No failing listeners found');
        }

        async.each(failingListeners, function(failingListener, cb) {
            var params = {
                'ListenerArn': failingListener.ListenerArn
            };

            helpers.remediatePlugin(config, putCall[0], params, function(error, action) {
                if (error && (error.length || Object.keys(error).length)) {
                    errors.push(error);
                } else if (action && (action.length || Object.keys(action).length)){
                    actions.push(action);
                }

                cb();
            });
        }, function() {
            if (errors && errors.length) {
                remediation_file['post_remediate']['actions'][pluginName]['error'] = errors.join(', ');
                settings.remediation_file = remediation_file;
                return callback(errors, null);
            } else {
                remediation_file['post_remediate']['actions'][pluginName][resource] = actions;
                settings.remediation_file = remediation_file;
                return callback(null, actions);
            }
        });
    }
};
