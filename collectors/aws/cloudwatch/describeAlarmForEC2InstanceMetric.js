var AWS = require('aws-sdk');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var cloudwatch = new AWS.CloudWatch(AWSConfig);

    var params = {
        MetricName: 'EC2InstanceEventCount',
        Namespace: 'CloudTrailMetrics'
    };

    helpers.makeCustomCollectorCall(cloudwatch, 'describeAlarmsForMetric', params, retries, null, null, null, function(err, data) {
        if (err) {
            collection.cloudwatch.describeAlarmForEC2InstanceMetric[AWSConfig.region].err = err;
        } else {
            collection.cloudwatch.describeAlarmForEC2InstanceMetric[AWSConfig.region].data = data.MetricAlarms || data;
        }
        callback();
    });  
};