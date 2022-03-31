var AWS = require('aws-sdk');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var cloudwatch = new AWS.CloudWatch(AWSConfig);

    var params = {
        MetricName: 'OrganizationsEvents',
        Namespace: 'CloudTrailMetrics'
    };

    helpers.makeCustomCollectorCall(cloudwatch, 'describeAlarmsForMetric', params, retries, null, null, null, function(err, data) {
        if (err) {
            collection.cloudwatch.describeAlarmForOrgEventsMetric[AWSConfig.region].err = err;
        } else {
            collection.cloudwatch.describeAlarmForOrgEventsMetric[AWSConfig.region].data = data.MetricAlarms || data;
        }
        callback();
    });  
};