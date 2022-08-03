var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFormation Plaintext Parameters',
    category: 'CloudFormation',
    domain: 'Application Integration',
    description: 'Ensures CloudFormation parameters that reference sensitive values are configured to use NoEcho.',
    more_info: 'CloudFormation supports the NoEcho property for sensitive values, which should be used to ensure secrets are not exposed in the CloudFormation UI and APIs.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html',
    recommended_action: 'Update the sensitive parameters to use the NoEcho property.',
    apis: ['CloudFormation:listStacks', 'CloudFormation:describeStacks'],
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
        async.each(regions.cloudformation, function(region, rcb) {
            var listStacks = helpers.addSource(cache, source,
                ['cloudformation', 'listStacks', region]);

            if (!listStacks) return rcb();

            if (listStacks.err || !listStacks.data) {
                helpers.addResult(results, 3, `Unable to query for  CloudFormation stacks: ${helpers.addError(listStacks)}`, region);
                return rcb();
            }

            if (!listStacks.data.length) {
                helpers.addResult(results, 0, 'No CloudFormation stacks found', region);
                return rcb();
            }

            async.each(listStacks.data, function(stack, cb) {
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
                    var resource = stackDetails.StackId;
                    let foundStrings = [];

                    if (!stackDetails.Parameters || !stackDetails.Parameters.length) {
                        helpers.addResult(results, 0,
                            'Template does not contain any parameters', region, resource);
                        continue;
                    }

                    for (var parameter of stackDetails.Parameters) {
                        if (parameter.ParameterKey && secretWords.includes(parameter.ParameterKey.toLowerCase()) && !parameter.ParameterValue.match('^[*]+$')) {
                            foundStrings.push(parameter.ParameterKey);
                        }
                    }

                    if (foundStrings && foundStrings.length) {
                        helpers.addResult(results, 2,
                            `Template contains these potentially-sensitive parameters: ${foundStrings.join(', ')}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'Template does not contain any potentially-sensitive parameters',
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
