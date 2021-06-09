var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'RDS SQL Audit Log Retention Period',
    category: 'RDS',
    description: 'Ensure that RDS DB instances SQL Audit Log retention period is configured to be greater than 180 days',
    more_info: 'RDS instances provides auditing feature that can be used to log all the events and activities which can be used later in case of any suspicions or security reasons.',
    link: 'https://partners-intl.aliyun.com/help/doc-detail/118678.htm',
    recommended_action: 'Modify RDS DB instances to set SQL Audit Log retention period to be greater than 180 days',
    apis: ['RDS:DescribeDBInstances', 'RDS:DescribeSQLCollectorRetention', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var defaultRegion = helpers.defaultRegion(settings);

        var unsupportedEngines = ['sqlserver 2012', 'sqlserver 2016', 'sqlserver 2017', 'mariadb tx'];
        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);

        console.log(JSON.stringify(cache, null, 2));

        async.each(regions.rds, function(region, rcb) {
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'DescribeDBInstances', region]);

            if (!describeDBInstances) {
                return rcb();
            }

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query RDS DB instances: ${helpers.addError(describeDBInstances)}`,
                    region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS DB instances found', region);
                return rcb();
            }

            async.each(describeDBInstances.data, function(instance, cb){
                if (!instance.DBInstanceId) return cb();

                var resource = helpers.createArn('rds', accountId, 'instance', instance.DBInstanceId, region);

                let instanceEngine = (instance.Engine && instance.EngineVersion) ? `${instance.Engine.toLowerCase()} ${instance.EngineVersion}` : '';

                if (unsupportedEngines.includes(instanceEngine)) {
                    helpers.addResult(results, 0,
                        `SQL auditing is not supported for ${instanceEngine} engine type`,
                        region, resource);
                    return cb();
                }

                var describeSqlAuditRetention = helpers.addSource(cache, source,
                    ['rds', 'DescribeSQLCollectorRetention', region, instance.DBInstanceId]);
                console.log('SQL Detail ', JSON.stringify(describeSqlAuditRetention, null, 2));

                if (!describeSqlAuditRetention || describeSqlAuditRetention.err || !describeSqlAuditRetention.data) {
                    helpers.addResult(results, 3,
                        `Unable to query DB sql audit log retention: ${helpers.addError(describeSqlAuditRetention)}`,
                        region, resource);
                    return cb();
                }

                const currentRetentionPeriod = parseInt(describeSqlAuditRetention.data.ConfigValue);

                if (currentRetentionPeriod >= 180) {
                    helpers.addResult(results, 0,
                        'RDS DB instance sql audit log retention is configured to be greater than 180 days',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'RDS DB instance sql audit log retention is configured to be less than 180 days',
                        region, resource);
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};