var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var cloudwatch = new AWS.CloudWatch(AWSConfig);
   
    async.eachLimit(collection.es.listDomainNames[AWSConfig.region].data, 10, function(domain, cb){        
        collection.cloudwatch.getEsMetricStatistics[AWSConfig.region][domain.DomainName] = {};
        var endTime = new Date();
        var startTime = new Date();
        startTime.setDate(startTime.getDate() - 1);
        var params = {
            'MetricName': 'ClusterStatus.Red',
            'Namespace':'AWS/ES',
            'StartTime': startTime.toISOString(),
            'EndTime': endTime.toISOString(),
            'Period': 3600,
            'Statistics': ['Maximum'],
            'Dimensions' : [
                {
                    Name: 'DomainName',
                    Value: domain.DomainName
                }
            ]
        };

        cloudwatch.getMetricStatistics(params, function(err, data) {
            if (err) {
                collection.cloudwatch.getEsMetricStatistics[AWSConfig.region][domain.DomainName].err = err;
            }
            collection.cloudwatch.getEsMetricStatistics[AWSConfig.region][domain.DomainName].data = data;
            cb();
        });
                
    }, function(){
        callback();
    });
};
