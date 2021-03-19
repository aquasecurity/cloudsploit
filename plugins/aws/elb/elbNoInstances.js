var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB No Instances',
    category: 'ELB',
    description: 'Detects ELBs that have no backend instances attached',
    more_info: 'All ELBs should have backend server resources. ' +
               'Those without any are consuming costs without providing ' +
               'any functionality. Additionally, old ELBs with no instances ' +
               'present a security concern if new instances are accidentally attached.',
    link: 'http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-backend-instances.html',
    recommended_action: 'Delete old ELBs that no longer have backend resources.',
    apis: ['ELB:describeLoadBalancers', 'STS:getCallerIdentity'],
    remediation_description: 'ELBs that have no instances attached will be deleted.',
    remediation_min_version: '202101071800',
    apis_remediate: ['ELB:describeLoadBalancers'],
    actions: {
        remediate: ['ELB:deleteLoadBalancer'],
        rollback: ['ELB:createLoadBalancer']
    },
    permissions: {
        remediate: ['elasticloadbalancing:DeleteLoadBalancer'],
        rollback: ['elasticloadbalancing:CreateLoadBalancer']
    },
    realtime_triggers: [],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

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
                // arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name
                var elbArn = 'arn:aws:elasticloadbalancing:' +
                              region + ':' + accountId + ':' +
                              'loadbalancer/' + lb.LoadBalancerName;

                if (lb.Instances.length) {
                    helpers.addResult(results, 0, 'ELB has ' + lb.Instances.length + ' backend instances', region, elbArn);
                } else {
                    helpers.addResult(results, 2, 'ELB does not have backend instances', region, elbArn);
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
        var pluginName = 'elbNoInstances';
        var lbNameArr = resource.split(':');
        var lbName = lbNameArr[5].substring(lbNameArr[5].lastIndexOf('/') + 1);

        config.region = lbNameArr[3];

        // create the params necessary for the remediation
        var params = {
            'LoadBalancerName': lbName
        };

        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Deletion': 'NOT_DELETED',
            'ELB': resource
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
                'Action': 'DELETED',
                'ELB': resource
            };

            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
