var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFormation Deletion Policy In Use',
    category: 'CloudFormation',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that deletion policy is used for Amazon CloudFormation stacks.',
    more_info: 'CloudFormation deletes the resource and all its content during stack deletion. With the DeletionPolicy attribute you can preserve, backup a resource when its stack is deleted. A DeletionPolicy attribute can be applied to each cloudformation stack.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-deletionpolicy.html',
    recommended_action: 'Enable deletion policy attribute in the AWS Cloudformation stack.',
    apis: ['CloudFormation:listStacks', 'CloudFormation:getTemplate'],
    realtime_triggers: ['cloudformation:CreateStack','cloudformation:UpdateStack','cloudformation:DeleteStack'],
    
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
                
                var resource = stack.StackName;
                var templates = helpers.addSource(cache, source,
                    ['cloudformation', 'getTemplate', region, resource]);
                
                if (!templates || templates.err || !templates.data) {
                    helpers.addResult(results, 3, `Unable to query CloudFormation stack template: ${helpers.addError(templates)}`, region, resource);
                    return rcb();
                }

                if (templates && templates.data && templates.data.TemplateBody) {
                    var deletionPolicy = templates.data.TemplateBody.includes('DeletionPolicy');
                    
                    if (deletionPolicy) {
                        helpers.addResult(results, 0,
                            'Deletion Policy is used for CloudFormation stack ',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2, 'Deletion Policy is not used for CloudFormation stack ',
                            region, resource);
                    }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
