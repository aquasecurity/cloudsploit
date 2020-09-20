var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Transport Encryption Enabled',
    category: 'RDS',
    description: 'Ensures that RDS SQL Server instances have Transport Encryption enabled.',
    more_info: 'Parameter group associated with the RDS instance should have rds.force_ssl set to true to ensure transport encryption',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html',
    recommended_action: 'Update the parameter group associated with the RDS instance to have rds.force_ssl set to true',
    apis: ['RDS:describeDBInstances', 'RDS:describeDBParameters', 'RDS:describeDBParameterGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.rds, function(region, rcb) {
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) {
                return rcb();
            }

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query for RDS DB instances: ${helpers.addError(describeDBInstances)}`,
                    region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS DB instances found');
                return rcb();
            }

            async.each(describeDBInstances.data, function(db, cb){
                if (db.Engine === 'sqlserver-ex') {
                    var resource = db.DBInstanceArn;

                    if (!db.DBParameterGroups || !db.DBParameterGroups.length) {
                        helpers.addResult(results, 0,
                            `RDS DB instance "${db.DBName}" does not have any parameter groups associated`,
                            region, resource);
                    }

                    var dbParameterGroup = db.DBParameterGroups[0].DBParameterGroupName;

                    var parameters = helpers.addSource(cache, source,
                        ['rds', 'describeDBParameters', region, dbParameterGroup]);

                    if (!parameters || parameters.err || !parameters.data) {
                        helpers.addResult(results, 3,
                            `Unable to query for parameters: ${helpers.addError(parameters)}`,
                            region, resource);
                        return cb();
                    }

                    if (!parameters.data.Parameters || !parameters.data.Parameters.length) {
                        helpers.addResult(results, 2,
                            `No parameter found for group "${db.DBParameterGroupName}"`,
                            region, resource);
                        return cb();
                    }

                    var forceSslEnabled = false;
                    parameters.data.Parameters.forEach(function(param){
                        if (param.ParameterName === 'rds.force_ssl') {
                            if(param.ParameterValue === '0'){
                                forceSslEnabled = true;
                            }
                        }
                    });
                    
                    if (forceSslEnabled) {
                        helpers.addResult(results, 0,
                            `RDS DB instance "${db.DBInstanceIdentifier}" has transport encryption enabled`,
                            region, resource);
                    }
                    else {
                        helpers.addResult(results, 2,
                            `RDS DB instance "${db.DBInstanceIdentifier}" does not have transport encryption enabled`,
                            region, resource);
                    }
                }
                cb();
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};