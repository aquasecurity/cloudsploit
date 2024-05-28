var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Database Minor Version Upgrade',
    category: 'Neptune',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures Auto Minor version upgrade is enabled on Neptune database instances.',
    more_info: 'AWS Neptune database service releases engine version upgrades regularly to introduce software features, bug fixes, security patches and performance improvements. Enabling auto minor version upgrade feature ensures that minor engine upgrades are applied automatically to the instance during the maintenance window.',
    recommended_action: 'Modify Neptune database instance and enable automatic minor version upgrades feature.',
    link: 'https://docs.aws.amazon.com/neptune/latest/userguide/cluster-maintenance.html',
    apis: ['Neptune:describeDBInstances'],
    realtime_triggers: ['neptune:CreateDBInstance', 'neptune:DeleteDBInstance', 'neptune:ModifyDBInstance'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.neptune, function(region, rcb){
            var describeDBInstances = helpers.addSource(cache, source,
                ['neptune', 'describeDBInstances', region]);

            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to list Neptune database cluster instances: ${helpers.addError(describeDBInstances)}`, region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0,
                    'No Neptune database instances found', region);
                return rcb();
            }

            var noInstance = true;

            for (let instance of describeDBInstances.data) {
                if (!instance.DBInstanceArn || instance.Engine !== 'neptune') continue;

                noInstance = false;

                if (instance.AutoMinorVersionUpgrade) {
                    helpers.addResult(results, 0, 'Neptune database instance has auto minor version upgrade enabled', region, instance.DBInstanceArn);
                } else {
                    helpers.addResult(results, 2, 'Neptune database instance does not have auto minor version upgrade enabled', region, instance.DBInstanceArn);
                }
            }

            if (noInstance) {
                helpers.addResult(results, 0,
                    'No Neptune database instances found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};