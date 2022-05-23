var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFormation Stack Termination Protection Enabled',
    category: 'CloudFormation',
    domain: 'Application Integration',
    description: 'Ensures that AWS CloudFormation stacks have termination protection enabled.',
    more_info: 'AWS CloudFormation stacks should have termination protection enabled to avoid accidental stack deletion.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-protect-stacks.html',
    recommended_action: 'Enable termination protection for CloudFormation stack',
    apis: ['CloudFormation:listStacks', 'CloudFormation:describeStacks'],
    remediation_description: 'Stack termination protection will be enabled for affected stacks.',
    remediation_min_version: '202205161341',
    apis_remediate: ['CloudFormation:listStacks', 'CloudFormation:describeStacks'],
    actions: {
        remediate: ['CloudFormation:updateTerminationProtection'],
        rollback: ['CloudFormation:updateTerminationProtection']
    },
    permissions: {
        remediate: ['cloudformation:UpdateTerminationProtection'],
        rollback: ['cloudformation:UpdateTerminationProtection']
    },
    realtime_triggers: ['cloudformation:UpdateTerminationProtection', 'cloudformation:CreateStack'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.cloudformation, function(region, rcb){
            var listStacks = helpers.addSource(cache, source,
                ['cloudformation', 'listStacks', region]);

            if (!listStacks) return rcb();

            if (listStacks.err || !listStacks.data) {
                helpers.addResult(results, 3, `Unable to query for CloudFormation stacks: ${helpers.addError(listStacks)}`, region);
                return rcb();
            }

            if (!listStacks.data.length) {
                helpers.addResult(results, 0, 'No CloudFormation stacks found', region);
                return rcb();
            }

            async.each(listStacks.data, function(stack, cb){
                if (!stack.StackId || !stack.StackName) return cb();

                var describeStacks = helpers.addSource(cache, source,
                    ['cloudformation', 'describeStacks', region, stack.StackName]);

                if (!describeStacks || describeStacks.err || !describeStacks.data ||
                    !describeStacks.data.Stacks || !describeStacks.data.Stacks.length) {
                    helpers.addResult(results, 3, `Unable to query for CloudFormation stack detils: ${helpers.addError(describeStacks)}`,
                        region, stack.StackId);
                    return cb();
                }

                for (var stackDetails of describeStacks.data.Stacks) {
                    if (!stackDetails.StackId) continue;

                    var resource = stackDetails.StackId;
                    if (stackDetails.EnableTerminationProtection) {
                        helpers.addResult(results, 0,
                            `CloudFormation stack "${stackDetails.StackName}" has termination protection enabled`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `CloudFormation stack "${stackDetails.StackName}" does not have termination protection enabled`,
                            region, resource);
                    }
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
        var pluginName = 'stackTerminationProtection';
        var stackNameArr = resource.split(':');
        var stacks = stackNameArr[stackNameArr.length - 1];
        var stackName = stacks.split('/');
        stackName = stackName[1];

        var stackLocation = stackNameArr[3];

        // add the location of the cloudformation stack to the config
        config.region = stackLocation;
        var params = {};

        // create the params necessary for the remediation
        
        params = { 
            EnableTerminationProtection: true,
            StackName: stackName  
        };

        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'TerminationProtection': 'Disabled',
            'StackName': stackName
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
                'TerminationProtection': 'Enabled',
                'StackName': stackName
            };
            
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
