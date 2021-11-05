var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 No Instances',
    category: 'ELBv2',
    domain: 'Content Delivery',
    description: 'Detects ELBs that have no target groups attached',
    more_info: 'All ELBs should have backend server resources. ' +
        'Those without any are consuming costs without providing ' +
        'any functionality. Additionally, old ELBs with no target groups ' +
        'present a security concern if new target groups are accidentally attached.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html',
    recommended_action: 'Delete old ELBs that no longer have backend resources.',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeTargetGroups'],
    remediation_description: 'ELBs that have no target groups attached will be deleted.',
    remediation_min_version: '202101072000',
    apis_remediate: ['ELBv2:describeLoadBalancers'],
    actions: {
        remediate: ['ELBv2:deleteLoadBalancer'],
        rollback: ['ELBv2:createLoadBalancer']
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
                var describeTargetGroups = helpers.addSource(cache, source,
                    ['elbv2', 'describeTargetGroups', region, lb.DNSName]);

                var elbArn = lb.LoadBalancerArn;
                if (describeTargetGroups.data && describeTargetGroups.data.TargetGroups && describeTargetGroups.data.TargetGroups.length){
                    helpers.addResult(results, 0,
                        'ELB has ' + describeTargetGroups.data.TargetGroups.length + ' target groups', region, elbArn);
                } else {
                    helpers.addResult(results, 2, 'ELB does not have target groups ', region, elbArn);
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
        var pluginName = 'elbv2NoInstances';
        var lbNameArr = resource.split(':');

        config.region = lbNameArr[3];

        // create the params necessary for the remediation
        var params = {
            'LoadBalancerArn': resource
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
