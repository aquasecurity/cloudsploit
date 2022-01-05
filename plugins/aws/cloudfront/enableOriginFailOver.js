var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFront Enable Origin Failover',
    category: 'CloudFront',
    domain: 'Content Delivery',
    description: 'Ensure that Origin Failover feature is enabled for your CloudFront distributions in order to improve the availability of the content delivered to your end users.',
    more_info: ' With Origin Failover capability, you can setup two origins for your CloudFront web distributions primary and secondary. In the event of primary origin failure, ' +
               'your content is automatically served from the secondary origin, maintaining the distribution high reliability. ',
    link: 'https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_OriginGroupFailoverCriteria.html',
    recommended_action: 'Ensures that When you create or update a distribution, you can specify the origin group instead of a single origin, and CloudFront will failover from the primary origin to the second origin under the failover conditions that you have chosen.',
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
                'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions), region);
            return callback(null, results, source);
        }

        if (!listDistributions.data.length) {
            helpers.addResult(results, 0, 'No CloudFront distributions found', region);
            return callback(null, results, source);
        }

        // loop through Instances for every reservation
        listDistributions.data.forEach(distribution => {
            if (!distribution.OriginGroups || !distribution.OriginGroups.Quantity) {
                helpers.addResult(results, 2,
                    'origin failover is not enabled within CloudFront distribution.', 'global', distribution.ARN);
            } else {
                helpers.addResult(results, 0,
                    'origin failover is enabled within CloudFront distribution.', 'global', distribution.ARN);
            }
        });

        return callback(null, results, source);
    }
};