var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront Custom Origin HTTPS Only',
    category: 'CloudFront',
    domain: 'Content Delivery',
    description: 'Ensures CloudFront Distribution Custom Origin is HTTPS Only.',
    more_info: 'When you create a distribution, you specify the origin where CloudFront sends requests for the files. You can use several different kinds of origins with CloudFront.',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html',
    recommended_action: 'Modify CloudFront distribution and update the Origin Protocol Policy setting to HTTPS Only.',
    apis: ['CloudFront:listDistributions'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
       
        var region = helpers.defaultRegion(settings);

        var listDistributions = helpers.addSource(cache, source,
            ['cloudfront', 'listDistributions', region]);

        if (!listDistributions) return callback(null, results, source);

        if (listDistributions.err || !listDistributions.data) {
            helpers.addResult(results, 3,
                'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions));
            return callback(null, results, source);
        }

        if (!listDistributions.data.length) {
            helpers.addResult(results, 0, 'No CloudFront distributions found');
            return callback(null, results, source);
        }
 
        for (let distribution of listDistributions.data){
            if (!distribution.ARN) continue;

            if (!distribution.Origins || !distribution.Origins.Items || !distribution.Origins.Items.length){
                helpers.addResult(results, 0, 'CloudFront distribution has no origins', 'global', distribution.ARN);
            } else {
                let items = distribution.Origins.Items;
                let isCorrectPolicy = true;
                for (let origin of items){
                    if (!origin.CustomOriginConfig || !origin.CustomOriginConfig.OriginProtocolPolicy) continue;

                    let originProtocolPolicy = origin.CustomOriginConfig.OriginProtocolPolicy.toLowerCase();
                    
                    if (originProtocolPolicy == 'http-only' || originProtocolPolicy == 'match-viewer'){
                        isCorrectPolicy = false;
                        break;
                    }
                }
                if (!isCorrectPolicy){
                    helpers.addResult(results, 2, 'CloudFront distribution custom origin is not configured to use HTTPS only', 'global', distribution.ARN);
                } else {
                    helpers.addResult(results, 0, 'CloudFront distribution custom origin is configured to use HTTPS only', 'global', distribution.ARN);
                }
            }
        }
        callback(null, results, source);
    }
};