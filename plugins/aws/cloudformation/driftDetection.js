var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFormation Drift Detection',
    category: 'CloudFormation',
    description: 'Ensures that AWS CloudFormation stacks are not in a drifted state.',
    more_info: 'AWS CloudFormation stack should not be in drifted state to ensure that stack template is aligned with the resources.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-resolve-drift.html',
    recommended_action: 'Resolve CloudFormation stack drift by importing drifted resource back to the stack.',
    apis: ['CloudFormation:listStacks'],

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

            for (var stack of listStacks.data) {
                if (!stack.StackId) return;
                var resource = stack.StackId;

                if (stack.DriftInformation && stack.DriftInformation.StackDriftStatus &&
                    stack.DriftInformation.StackDriftStatus.toUpperCase() === 'DRIFTED') {
                    helpers.addResult(results, 2,
                        `CloudFormation stack "${stack.StackName}" is in drifted state`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        `CloudFormation stack "${stack.StackName}" is not in drifted state`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
