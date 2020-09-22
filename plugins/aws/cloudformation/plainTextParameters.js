var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFormation Plaintext Parameters',
    category: 'CloudFormation',
    description: 'Ensures CloudFormation parameters that reference sensitive values are configured to use NoEcho.',
    more_info: 'CloudFormation supports the NoEcho property for sensitive values, which should be used to ensure secrets are not exposed in the CloudFormation UI and APIs.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html',
    recommended_action: 'Update the sensitive parameters to use the NoEcho property.',
    apis: ['CloudFormation:describeStacks'],
    settings: {
        plain_text_parameters: {
            name: 'CloudFormation Plaintext Parameters',
            description: 'A comma-delimited list of parameter strings that indicate a sensitive value',
            regex: '[a-zA-Z0-9,]',
            default: 'secret,password,privatekey'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var secretWords = this.settings.plain_text_parameters.default;
        secretWords = secretWords.split(',');
        async.each(regions.cloudformation, function(region, rcb){

            var describeStacks = helpers.addSource(cache, source,
                ['cloudformation', 'describeStacks', region]);
            if (!describeStacks) return rcb();

            if (describeStacks.err || !describeStacks.data) {
                helpers.addResult(results, 3,
                    'Unable to describe stacks: ' + helpers.addError(describeStacks), region);
                return rcb();
            }

            if (!describeStacks.data.length) {
                helpers.addResult(results, 0, 'No CloudFormation stacks found', region);
                return rcb();
            }
            
            for (var s in describeStacks.data){
                // arn:aws:cloudformation:region:account-id:stack/stack-name/stack-id
                var stack = describeStacks.data[s];
                var resource = stack.StackId;
                let foundStrings = [];

                if(!stack.Parameters || !stack.Parameters.length) {
                    helpers.addResult(results, 0,
                        'Template does not contain any parameters', region, resource);
                    continue;
                }

                stack.Parameters.forEach(function(parameter){
                    if(parameter.ParameterKey && secretWords.includes(parameter.ParameterKey.toLowerCase()) && !parameter.ParameterValue.match('^[*]+$')) {
                        foundStrings.push(parameter.ParameterKey);
                    }
                });

                if(foundStrings && foundStrings.length) {
                    helpers.addResult(results, 2,
                        'Template contains the following potentially-sensitive parameters: ' + foundStrings, region, resource);
                }
                else {
                    helpers.addResult(results, 0,
                        'Template does not contain any potentially-sensitive parameters', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
