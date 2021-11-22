var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'ActionTrail Bucket Private',
    category: 'ActionTrail',
    domain: 'Compliance',
    description: 'Ensure that OSS buckets which are acting as ActionTrail trails destinations, should not be publicly accessible.',
    more_info: 'When you allow public-access on an OSS bucket, all Internet users can access the objects in the bucket ' +
        'and write data to the bucket. This may cause unexpected access to the data in your bucket, and cause an increase in your fees. ' +
        'If a user uploads prohibited data or information, it may affect your legitimate interests and rights.',
    link: 'https://help.aliyun.com/document_detail/31954.html',
    recommended_action: 'Modify bucket ACL to restrict access to be private.',
    apis: ['ActionTrail:DescribeTrails', 'OSS:listBuckets', 'OSS:getBucketInfo', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);
        var listBuckets = helpers.addSource(cache, source, ['oss', 'listBuckets', defaultRegion]);
        
        if (!listBuckets || listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, `Unable to query for OSS buckets: ${helpers.addError(listBuckets)}`, defaultRegion);
            return callback(null, results, source);
        }

        async.each(regions.actiontrail, function(region, rcb) {
            var describeTrails = helpers.addSource(cache, source, ['actiontrail', 'DescribeTrails', region]);

            if (!describeTrails) return rcb();

            if (describeTrails.err || !describeTrails.data) {
                helpers.addResult(results, 3, 'Unable to query ActionTrail trails: ' + helpers.addError(describeTrails), region);
                return rcb();
            }

            if (!describeTrails.data.length) {
                helpers.addResult(results, 0, 'No ActionTrail trail found', region);
                return rcb();
            }

            var osstrailFound = false;
            for (let trail of describeTrails.data) {
                if (!trail.OssBucketName) continue;

                osstrailFound = true;

                var getBucketInfo = helpers.addSource(cache, source,
                    ['oss', 'getBucketInfo', region, trail.OssBucketName]);
                var bucketLocation = (getBucketInfo && getBucketInfo.data && getBucketInfo.data.Location) ?
                    getBucketInfo.data.Location : region;
                bucketLocation = bucketLocation.replace('oss-', '');
    
                var resource = helpers.createArn('oss', accountId, 'bucket', trail.OssBucketName, bucketLocation);
    
                if (!getBucketInfo || getBucketInfo.err || !getBucketInfo.data) {
                    helpers.addResult(results, 3,
                        `Unable to query OSS bucket info: ${helpers.addError(getBucketInfo)}`, bucketLocation, resource);
                    continue;
                }

                if (getBucketInfo.data.AccessControlList &&
                    getBucketInfo.data.AccessControlList.Grant &&
                    getBucketInfo.data.AccessControlList.Grant == 'private') {
                    helpers.addResult(results, 0,
                        `ActionTrail trail Bucket ACL allows ${getBucketInfo.data.AccessControlList.Grant} access`,
                        bucketLocation, resource);
                } else {
                    helpers.addResult(results, 2,
                        `ActionTrail trail Bucket ACL allows ${getBucketInfo.data.AccessControlList.Grant} access`,
                        bucketLocation, resource);
                }
            }

            if (!osstrailFound) {
                helpers.addResult(results, 0, 'No ActionTrail trail with OSS bucket destination found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
