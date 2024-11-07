var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Bucket Write Logs Enabled',
    category: 'Object Store',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures write level Object Storage logging is enabled for all buckets.',
    more_info: 'Enabling write level logging for object store buckets will provide you more visibility into changes to objects in your buckets.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Object/Tasks/managingbuckets.htm',
    recommended_action: 'Enable write level logging for each object store.',
    apis: ['namespace:get', 'bucket:list', 'logGroup:list', 'log:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.bucket, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var buckets = helpers.addSource(cache, source,
                    ['bucket', 'list', region]);

                if (!buckets) return rcb();

                if (buckets.err || !buckets.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for object store buckets: ' + helpers.addError(buckets), region);
                    return rcb();
                } 

                if (!buckets.data.length) {
                    helpers.addResult(results, 0, 'No object store buckets to check', region);
                    return rcb();
                }

                var logs = helpers.addSource(cache, source,
                    ['log', 'list', region]);
                
                buckets.data.forEach(bucket  => {                    
                    let bucketLog = null;

                    if (logs && !logs.err && logs.data && logs.data.length) {
                        bucketLog = logs.data.find(log => log.isEnabled && log.configuration 
                            && Object.keys(log.configuration).length && log.configuration.source 
                            && Object.keys(log.configuration.source).length && log.configuration.source.service === 'objectstorage'
                            && log.configuration.source.category === 'write' 
                            && log.configuration.source.resource === bucket.name);
                    }

                    if (bucketLog) {
                        helpers.addResult(results, 0, 'The bucket has write level logging enabled', region, bucket.id);
                    } else {
                        helpers.addResult(results, 2, 'The bucket does not have write level logging enabled', region, bucket.id);
                    }
                });
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};