const {
    CloudWatch
} = require('@aws-sdk/client-cloudwatch');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var cloudwatch = new CloudWatch(AWSConfig);
   
    async.eachLimit(collection.rds.describeDBInstances[AWSConfig.region].data, 10, function(instance, cb){        
        collection.cloudwatch.getRdsReadIOPSMetricStatistics[AWSConfig.region][instance.DBInstanceIdentifier] = {};
        var endTime = new Date();
        var startTime = new Date();
        startTime.setDate(startTime.getDate() - 7);
        var params = {
            'MetricName': 'ReadIOPS',
            'Namespace':'AWS/RDS',
            'StartTime': startTime,
            'EndTime': endTime,
            'Period': 86400,
            'Statistics': ['Sum'],
            'Dimensions' : [
                {
                    Name: 'DBInstanceIdentifier',
                    Value: instance.DBInstanceIdentifier
                }
            ]
        };

        helpers.makeCustomCollectorCall(cloudwatch, 'getMetricStatistics', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.cloudwatch.getRdsReadIOPSMetricStatistics[AWSConfig.region][instance.DBInstanceIdentifier].err = err;
            }
            if (data) collection.cloudwatch.getRdsReadIOPSMetricStatistics[AWSConfig.region][instance.DBInstanceIdentifier].data = data;
            cb();
        });
                
    }, function(){
        callback();
    });
};
