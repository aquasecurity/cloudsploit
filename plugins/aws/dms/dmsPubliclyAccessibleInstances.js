var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DMS Publicly Accessible Instances',
    category: 'DMS',
    domain: 'Application Integration',
    description: 'Ensure that Amazon Database Migration Service (DMS) instances are not publicly accessible.',
    more_info: 'An AWS DMS replication instance can have one public IP address and one private IP address. If you uncheck (disable) the box for Publicly accessible, then the replication instance has only a private IP address. that prevents from exposure of data to other users',
    recommended_action: 'Ensure that DMS replication instances have only private IP address and not public IP address',
    link: 'https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.PublicPrivate.html',
    apis: ['DMS:describeReplicationInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.dms, function(region, rcb){
            var describeReplicationInstances = helpers.addSource(cache, source,
                ['dms', 'describeReplicationInstances', region]);

            if (!describeReplicationInstances) return rcb();

            if (describeReplicationInstances.err || !describeReplicationInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to list DMS replication instances: ${helpers.addError(describeReplicationInstances)}`, region);
                return rcb();
            }

            if (!describeReplicationInstances.data.length) {
                helpers.addResult(results, 0,
                    'No DMS replication instances found', region);
                return rcb();
            }

            for (let instance of describeReplicationInstances.data) {
                if (!instance.ReplicationInstanceArn) continue;

                let resource = instance.ReplicationInstanceArn;

                if (!instance.PubliclyAccessible) {
                    helpers.addResult(results, 0,
                        'DMS replication instance is not publicly accessible.',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'DMS replication instance is publicly accessible.',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
