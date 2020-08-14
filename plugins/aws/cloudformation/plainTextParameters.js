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

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        secretWords = settings.plainTextParameters.secretWords;

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
                helpers.addResult(results, 0, 'No stack description found', region);
                return rcb();
            }
            
            var parameterFound;
            describeStacks.data.forEach(function(stack){
                parameterFound = false;

                if(!stack.Parameters.length) {
                    helpers.addResult(results, 0,
                        'The template did not contain any potentially-sensitive parameters', region);
                    return;
                }

                stack.Parameters.forEach(function(parameter){
                    if(secretWords.includes(parameter.ParameterKey.toLowerCase()) && !parameterFound) {
                        parameterFound = true;
                        helpers.addResult(results, 1,
                            'The template contained one of the following potentially-sensitive parameters: secret, key, password', region);
                        return;
                    }
                });
                
                if(!parameterFound) {
                    helpers.addResult(results, 0,
                    'The template did not contain any potentially-sensitive parameters', region);
                }

            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
