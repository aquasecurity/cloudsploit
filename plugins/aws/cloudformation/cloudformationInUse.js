var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS CloudFormation In Use',
    category: 'CloudFormation',
    domain: 'Application Integration',
    description: 'Ensure that Amazon CloudFormation is in use within your AWS account of selected region to automate your infrastructure management and deployment.',
    more_info: 'AWS CloudFormation is a service that helps you model and set up your AWS resources so that you can spend less time managing those resources and more time focusing on your applications that run in AWS.'+
        'A stack is a collection of AWS resources that you can manage as a single unit. In other words, you can create, update, or delete a collection of resources by creating, updating, or deleting stacks.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html',
    recommended_action: 'Check if CloudFormation is in use or not by observing the stacks',
    apis: ['CloudFormation:describeStacks'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
       
        async.each(regions.cloudformation, function(region, rcb){
            var describeStacks = helpers.addSource(cache, source,
                ['cloudformation', 'describeStacks', region]);

            if (!describeStacks) return rcb();

            if (describeStacks.err || !describeStacks.data) {
                helpers.addResult(results, 3,
                    `Unable to query cloudformation stacks: ${helpers.addError(describeStacks)}`, region);
                return rcb();
            }

            if (!describeStacks.data.length) {
                helpers.addResult(results, 2,
                    'the Amazon CloudFormation service is not currently in use within the selected AWS region.',
                    region); 
            }else {
                helpers.addResult(results, 0,
                    'the Amazon CloudFormation service is currently in use within the selected AWS region.',
                    region);  
            }
        
            
           
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
