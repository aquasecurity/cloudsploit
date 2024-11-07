var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFormation Deletion Policy In Use',
    category: 'CloudFormation',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that deletion policy is used for Amazon CloudFormation stacks.',
    more_info: 'DeletionPolicy attribute allows to preserve and backup a resource when its stack is deleted. By default, AWS CloudFormation deletes the resource and all its content if a resource has no DeletionPolicy attribute in a template.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-deletionpolicy.html',
    recommended_action: 'Add DeletionPolicy attribute in the AWS Cloudformation stack template.',
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
                if (!stack.StackId || !stack.StackName) continue;
                
                var resource = stack.StackId;
                var template = helpers.addSource(cache, source,
                    ['cloudformation', 'getTemplate', region, stack.StackName]);
                
                if (!template || template.err || !template.data) {
                    helpers.addResult(results, 3, `Unable to query CloudFormation stack template: ${helpers.addError(template)}`, region, resource);
                    continue;
                }

                if (template.data.TemplateBody) {
                    // eslint-disable-next-line no-useless-escape
                    var deletionPolicy = template.data.TemplateBody.includes('DeletionPolicy\":\"Retain');
                    
                    if (deletionPolicy) {
                        helpers.addResult(results, 0,
                            'Deletion Policy is used for CloudFormation stack',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2, 'Deletion Policy is not used for CloudFormation stack',
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

