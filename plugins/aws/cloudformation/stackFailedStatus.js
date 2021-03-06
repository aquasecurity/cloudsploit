var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFormation Stack Failed Status',
    category: 'CloudFormation',
    description: 'Ensures that AWS CloudFormation stacks are not in Failed mode for more than the maximum failure limit hours.',
    more_info: 'AWS CloudFormation stacks should not be in failed mode to avoid application downtime.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-view-stack-data-resources.html',
    recommended_action: 'Remove or redeploy the CloudFormation failed stack.',
    apis: ['CloudFormation:listStacks', 'CloudFormation:describeStackEvents'],
    settings: {
        stack_failed_state_hours_limit: {
            name: 'CloudFormation Stack Failed State Limit',
            description: 'A value to be used as a maximum limit in hours in which a CloudFormation stack can stay in failed state',
            regex: '^[0-9]{1,4}$',
            default: 0
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var stack_failed_state_hours_limit = ('stack_failed_state_hours_limit' in settings) ? parseInt(settings.stack_failed_state_hours_limit) : this.settings.stack_failed_state_hours_limit.default;

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

            async.each(listStacks.data, function(stack, cb) {
                if (!stack.StackId || !stack.StackName) return cb();
                var resource = stack.StackId;

                if (stack.StackStatus && (
                    stack.StackStatus.toUpperCase() === 'CREATE_FAILED' || 
                    stack.StackStatus.toUpperCase() === 'DELETE_FAILED' || 
                    stack.StackStatus.toUpperCase() === 'ROLLBACK_FAILED' || 
                    stack.StackStatus.toUpperCase() === 'UPDATE_ROLLBACK_FAILED')) {
                    var describeStackEvents = helpers.addSource(cache, source,
                        ['cloudformation', 'describeStackEvents', region, stack.StackName]);

                    if (!describeStackEvents || describeStackEvents.err || !describeStackEvents.data) {
                        helpers.addResult(results, 3, `Unable to query for CloudFormation stack events: ${helpers.addError(describeStackEvents)}`, region);
                        return cb();
                    }

                    if (!describeStackEvents.data.StackEvents ||
                        !describeStackEvents.data.StackEvents.length) {
                        helpers.addResult(results, 0, 'No CloudFormation stack events found', region);
                        return cb();
                    }

                    var latestEvent = describeStackEvents.data.StackEvents[0];
                    var now = new Date();
                    var then = new Date(latestEvent.Timestamp);
                    var difference = helpers.hoursBetween(then, now);

                    if (difference > stack_failed_state_hours_limit) {
                        helpers.addResult(results, 2,
                            `CloudFormation stack "${stack.StackName}" is in failed state for ${difference} hours of ${stack_failed_state_hours_limit} limit`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            `CloudFormation stack "${stack.StackName}" is in failed state for ${difference} hours of ${stack_failed_state_hours_limit} limit`,
                            region, resource);
                    }

                } else {
                    helpers.addResult(results, 0,
                        `CloudFormation stack "${stack.StackName}" is not in failed state`,
                        region, resource);
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
