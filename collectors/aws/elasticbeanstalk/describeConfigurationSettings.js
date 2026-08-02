const {
    ElasticBeanstalk
} = require('@aws-sdk/client-elastic-beanstalk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var elasticbeanstalk = new ElasticBeanstalk(AWSConfig);

    async.eachLimit(collection.elasticbeanstalk.describeEnvironments[AWSConfig.region].data, 15, function(environment, cb) {
        var params = {
            ApplicationName: environment.ApplicationName,
            EnvironmentName: environment.EnvironmentName
        };

        helpers.makeCustomCollectorCall(elasticbeanstalk, 'describeConfigurationSettings', params, retries, null, null, null, function(err, data) {
            collection.elasticbeanstalk.describeConfigurationSettings[AWSConfig.region][environment.EnvironmentArn] = {};
            if (err || !data) {
                collection.elasticbeanstalk.describeConfigurationSettings[AWSConfig.region][environment.EnvironmentArn].err = err;
            } else {
                collection.elasticbeanstalk.describeConfigurationSettings[AWSConfig.region][environment.EnvironmentArn].data = data;
            }
            cb();
        });
    }, function() {
        callback();
    });
};
