var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Bucket Public Access Type',
    category: 'Object Store',
    description: 'Ensures object store buckets do not allow global write, delete, or read permissions',
    more_info: 'Object store buckets can be configured to allow anyone, regardless of whether they are an Oracle cloud user or not, to write objects to a bucket or delete objects. This option should not be configured unless there is a strong business requirement.',
    recommended_action: 'Disable global all users policies on all object store buckets and ensure the bucket is configured with the least privileges.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Object/Tasks/managingbuckets.htm',
    apis: ['namespace:get','bucket:list', 'bucket:get'],
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
            'a legitimate business need. If PCI-restricted data is stored in Object Store, ' +
            'those buckets should not enable global user access.',
        hipaa: 'HIPAA requires that all patient information is kept private and can only be accessed ' +
            'by administrators.'
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.bucket, function (region, rcb) {

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var getBucket = helpers.addSource(cache, source,
                    ['bucket', 'get', region]);

                if (!getBucket) return rcb();

                if (getBucket.err || !getBucket.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for object store bucket details: ' + helpers.addError(getBucket), region);
                } else if (!getBucket.data.length) {
                    helpers.addResult(results, 0, 'No object store bucket details to check', region);
                } else {

                    getBucket.data.forEach(function (bucket) {
                        if (bucket.publicAccessType &&
                            bucket.publicAccessType === "NoPublicAccess") {
                            helpers.addResult(results, 0,
                                `Object store bucket (${bucket.name}) does not allow public access.`, region, bucket.id);
                        } else {
                            helpers.addResult(results, 2,
                                `Object store bucket (${bucket.name}) allows  ` + (bucket.publicAccessType ? bucket.publicAccessType : ''), region, bucket.id);
                        }
                    });
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};