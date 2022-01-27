var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DMS Auto Minor Version Upgrade',
    category: 'DMS',
    domain: 'Application Integration',
    description: 'Ensure that your Amazon Database Migration Service (DMS) replication instances have the Auto Minor Version Upgrade feature enabled',
    more_info: 'AWS Database Migration Service (AWS DMS) helps you migrate databases to AWS quickly and securely. The DMS service releases engine version upgrades regularly to introduce new software features, bug fixes, security patches and performance improvements.',
    recommended_action: 'Enable Auto Minor Version Upgrade feature in order to automatically receive minor engine upgrades for improved performance and security',
    link: 'https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.Modifying.html',
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

                if (instance.AutoMinorVersionUpgrade) {
                    helpers.addResult(results, 0,
                        'Replication instance has auto minor version upgrade enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Replication instance does not have auto minor version upgrade enabled',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};