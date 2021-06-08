var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'RDS Log Connection Enabled',
    category: 'RDS',
    description: 'Ensure that log_connections parameter is set to ON for RDS instances.',
    more_info: 'RDS instance provide the feature of logging details of an attempted or successful connection to the server. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.',
    link: '',
    recommended_action: 'Modify RDS DB instance log_connection parameter to ON',
    apis: ['RDS:DescribeDBInstances', 'RDS:DescribeParameters', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var defaultRegion = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);

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
                var describeParameters = helpers.addSource(cache, source,
                    ['rds', 'DescribeParameters', region, instance.DBInstanceId]);
                console.log(JSON.stringify(describeParameters, null, 2));

                if (!describeParameters || describeParameters.err || !describeParameters.data) {
                    helpers.addResult(results, 3,
                        `Unable to query DB parameters: ${helpers.addError(describeParameters)}`,
                        region, resource);
                    return cb();
                }

                if (describeParameters.data.RunningParameters &&
                    describeParameters.data.RunningParameters.DBInstanceParameter &&
                    describeParameters.data.RunningParameters.DBInstanceParameter.length) {
                    let parameters = describeParameters.data.RunningParameters.DBInstanceParameter;
                    let found = parameters.find(parameter => parameter.ParameterName == 'log_connections' && parameter.ParameterValue.toLowerCase() == 'on');

                    if (found) {
                        helpers.addResult(results, 0,
                            'RDS DB instance has log_connections parameter enabled',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'RDS DB instance does not have log_connections parameter enabled',
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'RDS DB instance does not have log_connections parameter enabled',
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