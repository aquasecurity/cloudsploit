var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Bucket Lifecycle Configuration',
    category: 'OSS',
    description: 'Ensures that OSS buckets have lifecycle configuration enabled to automatically transition bucket objects.',
    more_info: 'Enabling lifecycle policies for OSS buckets enables the transition to .',
    recommended_action: 'Modify OSS buckets to enable logging.',
    link: 'https://www.alibabacloud.com/help/doc-detail/31900.htm',
    apis: ['OSS:listBuckets', 'OSS:getBucketInfo', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', region, 'data']);

        var listBuckets = helpers.addSource(cache, source, ['oss', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);
        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, `Unable to query for OSS buckets: ${helpers.addError(listBuckets)}`, region);
            return callback(null, results, source);
        }