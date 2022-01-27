var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DMS Multi-AZ Feature Enabled',
    category: 'DMS',
    domain: 'Application Integration',
    description: 'Ensure that your Amazon Database Migration Service (DMS) replication instances are using Multi-AZ deployment configurations.',
    more_info: 'AWS Database Migration Service (AWS DMS) helps you migrate databases to AWS quickly and securely. In a Multi-AZ deployment, AWS DMS automatically provisions and maintains a synchronous standby replica of the replication instance in a different Availability Zone.',
    recommended_action: 'Enable Multi-AZ deployment feature in order to get high availability and failover support',
    link: 'https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html',
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

                if (instance.MultiAZ) {
                    helpers.addResult(results, 0,
                        'DMS replication instance has Multi-AZ feature enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'DMS replication instance does not have Multi-AZ feature enabled',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};