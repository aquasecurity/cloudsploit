var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFormation Plaintext Parameters',
    category: 'CloudFormation',
    description: 'Ensures CloudFormation parameters that reference sensitive values are configured to use NoEcho.',
    more_info: 'CloudFormation supports the NoEcho property for sensitive values, which should be used to ensure secrets are not exposed in the CloudFormation UI and APIs.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html',
    recommended_action: 'Update the sensitive parameters to use the NoEcho property.',
    apis: ['CloudFormation:describeStacks'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
                'CloudFront HTTPS redirection should be used to ensure site visitors ' +
                'are always connecting over a secure channel.'
    },
    // settings : { secretWords : ["password", "privatekey", "secret"] },

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var describeStacks = helpers.addSource(cache, source,
            ['cloudformation', 'describeStacks', region]);

        console.log(describeStacks);
        console.log("results received");
        // if (!describeStacks) return callback(null, results, source);

        // if (describeStacks.err || !describeStacks.data) {
        //     helpers.addResult(results, 3,
        //         'Unable to describe stacks: ' + helpers.addError(describeStacks));
        //     return callback(null, results, source);
        // }

        // if (!describeStacks.data.length) {
        //     helpers.addResult(results, 0, 'No stacks descriptions found');
        //     return callback(null, results, source);
        // }
        // console.log(describeStacks.data);
        // loop through stacks for every template retrieval
        // describeStacks.data.forEach(function(Distribution){
        //     var stackTemplate = helpers.addSource(cache, source,
        //         ['cloudformation', 'getTemplate', region]);
    
        //     if (!describeStacks) return callback(null, results, source);
    
        //     if (describeStacks.err || !describeStacks.data) {
        //         helpers.addResult(results, 3,
        //             'Unable to describe stacks: ' + helpers.addError(describeStacks));
        //         return callback(null, results, source);
        //     }

        //     if (Distribution.DefaultCacheBehavior.ViewerProtocolPolicy == 'redirect-to-https') {
        //         helpers.addResult(results, 0, 'CloudFront distribution ' + 
        //             'is configured to redirect non-HTTPS traffic to HTTPS', 'global', Distribution.ARN);
        //     } else if (Distribution.DefaultCacheBehavior.ViewerProtocolPolicy == 'https-only') {
        //         helpers.addResult(results, 0, 'The CloudFront ' + 
        //             'distribution is set to use HTTPS only.', 'global', Distribution.ARN);
        //     } else {
        //         helpers.addResult(results, 2, 'CloudFront distribution ' + 
        //             'is not configured to use HTTPS', 'global', Distribution.ARN);
        //     }
        // });

        callback(null, results, source);
    }
};