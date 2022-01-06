var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var cloudwatch = new AWS.CloudWatch(AWSConfig);
   
    async.eachLimit(collection.elasticache.describeCacheClusters[AWSConfig.region].data, 10, function(cluster, cb){        
        collection.cloudwatch.getEcMetricStatistics[AWSConfig.region][cluster.CacheClusterId] = {};
        var endTime = new Date();
        var startTime = new Date();
        startTime.setDate(startTime.getDate() - 1);
        var params = {
            'MetricName': 'CPUUtilization',
            'Namespace':'AWS/ElastiCache',
            'StartTime': startTime.toISOString(),
            'EndTime': endTime.toISOString(),
            'Period': 3600,
            'Statistics': ['Average'],
            'Dimensions' : [
                {
                    Name: 'CacheClusterId',
                    Value: cluster.CacheClusterId
                }
            ]
        };

        helpers.makeCustomCollectorCall(cloudwatch, 'getMetricStatistics', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.cloudwatch.getEcMetricStatistics[AWSConfig.region][cluster.CacheClusterId].err = err;
            }
            collection.cloudwatch.getEcMetricStatistics[AWSConfig.region][cluster.CacheClusterId].data = data;
            cb();
        });
                
    }, function(){
        callback();
    });
};
