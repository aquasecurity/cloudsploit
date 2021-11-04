var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFormation Stack SNS Notifications',
    category: 'CloudFormation',
    domain: 'Application Integration',
    description: 'Ensures that AWS CloudFormation stacks have SNS topic associated.',
    more_info: 'AWS CloudFormation stacks should have SNS topic associated to ensure stack events monitoring.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-view-stack-data-resources.html',
    recommended_action: 'Associate an Amazon SNS topic to all CloudFormation stacks',
    apis: ['CloudFormation:listStacks', 'CloudFormation:describeStacks'],

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
                    helpers.addResult(results, 3, `Unable to query for CloudFormation stack details: ${helpers.addError(describeStacks)}`,
                        region, stack.StackId);
                    return cb();
                }

                for (var stackDetails of describeStacks.data.Stacks) {
                    var resource = stackDetails.StackId;

                    if (stackDetails.NotificationARNs && stackDetails.NotificationARNs.length) {
                        helpers.addResult(results, 0,
                            `CloudFormation stack "${stackDetails.StackName}" has SNS topic associated`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `CloudFormation stack "${stackDetails.StackName}" does not have SNS topic associated`,
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
    }
};
