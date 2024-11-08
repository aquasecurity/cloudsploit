var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var cloudwatch = new AWS.CloudWatch(AWSConfig);
   
    async.eachLimit(collection.redshift.describeClusters[AWSConfig.region].data, 10, function(cluster, cb){        
        collection.cloudwatch.getredshiftMetricStatistics[AWSConfig.region][cluster.ClusterIdentifier] = {};
        var endTime = new Date();
        var startTime = new Date();
        startTime.setDate(startTime.getDate() - 7);
        var params = {
            'MetricName': 'CPUUtilization',
            'Namespace':'AWS/Redshift',
            'StartTime': startTime.toISOString(),
            'EndTime': endTime.toISOString(),
            'Period': 3600,
            'Statistics': ['Average'],
            'Dimensions' : [
                {
                    Name: 'ClusterIdentifier',
                    Value: cluster.ClusterIdentifier
                }
            ]
        };

        helpers.makeCustomCollectorCall(cloudwatch, 'getMetricStatistics', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.cloudwatch.getredshiftMetricStatistics[AWSConfig.region][cluster.ClusterIdentifier].err = err;
            }
            if (data) collection.cloudwatch.getredshiftMetricStatistics[AWSConfig.region][cluster.ClusterIdentifier].data = data;
            cb();
        });
                
    }, function(){
        callback();
    });
};
