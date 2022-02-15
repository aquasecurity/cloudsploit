var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront Enabled',
    category: 'CloudFront',
    domain: 'Content Delivery',
    description: 'Ensure that AWS CloudFront service is used within your AWS account.',
    more_info: 'Amazon CloudFront is a web service that speeds up distribution of your static and dynamic web content, such as .html, .css, .js, and image files, to your users. CloudFront delivers your content through a worldwide network of data centers called edge locations.',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html',
    recommended_action: 'Check if CloudFront is in use or not by observing the data received.',
    apis: ['EventBridge:listRules'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var listRules = helpers.addSource(cache, source,
            ['eventbridge', 'listRules', region]);

        if (!listRules) return callback(null, results, source);

        if (listRules.err || !listRules.data) {
            helpers.addResult(results, 3,
                'Unable to list CloudWatch events rules: ' + helpers.addError(listRules), region);
            return callback(null, results, source);
        }

        if (listRules.data.length) {
            helpers.addResult(results, 0, 
                'AWS CloudWatch events are currently in use', 
                region);
        } else {
            helpers.addResult(results, 2,
                'AWS CloudWatch events are not currently in use', 
                region);
        }

        return callback(null, results, source);
    }
};