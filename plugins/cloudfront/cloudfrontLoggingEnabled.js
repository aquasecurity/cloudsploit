var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
    title: 'CloudFront Logging Enabled',
    category: 'CloudFront',
    description: 'Ensures CloudFront distributions have request logging enabled.',
    more_info: 'Logging requests to CloudFront ' +
               'distributions is a helpful way of detecting and ' + 
               'investigating potential attacks, malicious activity, ' + 
               'or misuse of backend resources. Logs can be sent to S3 ' + 
               'and processed for further analysis.',
    link: 'http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html',
    recommended_action: 'Enable CloudFront request logging.',
    apis: ['CloudFront:listDistributions', 'CloudFront:getDistribution'],

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};

        var listDistributions = helpers.addSource(cache, source,
            ['cloudfront', 'listDistributions', 'us-east-1']);

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
        // loop through Instances for every reservation
        listDistributions.data.forEach(function(Distribution){
            var getDistribution = helpers.addSource(cache, source,
                    ['cloudfront', 'getDistribution', 'us-east-1', Distribution.Id]);

            if (getDistribution.data &&
                getDistribution.data.Distribution &&
                getDistribution.data.Distribution.DistributionConfig &&
                getDistribution.data.Distribution.DistributionConfig.Logging){
                logging = getDistribution.data.Distribution.DistributionConfig.Logging;
                if (logging.Enabled){
                    helpers.addResult(results, 0,
                            'Request logging is enabled', Distribution.ARN);
                } else {
                    helpers.addResult(results, 2,
                        'Request logging is not enabled', Distribution.ARN);
                }
            }
        });

        return callback(null, results, source);
    }
};