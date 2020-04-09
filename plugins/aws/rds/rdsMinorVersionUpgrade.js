var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS / DocumentDB Minor Version Upgrade',
    category: 'RDS',
    description: 'Auto Minor Version Upgrade must be enabled on RDS and DocumentDB databases.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html#USER_UpgradeDBInstance.Upgrading.AutoMinorVersionUpgrades',
    recommended_action: 'Enable automatic minor version upgrades on RDS and DocumentDB databases',
    apis: ['RDS:describeDBInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var foundDBInstance = false;

        async.each(regions.rds, function(region, rcb) {
            var describeDBInstances = helpers.addSource(cache, source, ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) {
                return rcb();
            }

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3, `Unable to query for RDS/DocumentDB instances: ${helpers.addError(describeDBInstances)}`, region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                return rcb();
            }

            foundDBInstance = true;
            for (i in describeDBInstances.data) {
                var db = describeDBInstances.data[i];

                if (db.AutoMinorVersionUpgrade) {
                    helpers.addResult(results, 0, 'Auto Minor Version Upgrade is enabled', region, db.DBInstanceArn);
                } else {
                    helpers.addResult(results, 2, 'Auto Minor Version Upgrade is not enabled', region, db.DBInstanceArn);
                }
            }

            rcb();
        }, function() {
            if (!foundDBInstance) {
                helpers.addResult(results, 0, 'No RDS/DocumentDB instances found');
            }
            callback(null, results, source);
        });
    }
};
