var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var emr = new AWS.EMR(AWSConfig);

    async.eachLimit(collection.emr.listClusters[AWSConfig.region].data, 15, function(cluster, cb){
        if (!collection.emr.describeCluster ||
            !collection.emr.describeCluster[AWSConfig.region] ||
            !collection.emr.describeCluster[AWSConfig.region][cluster.Id] ||
            !collection.emr.describeCluster[AWSConfig.region][cluster.Id].data ||
            !collection.emr.describeCluster[AWSConfig.region][cluster.Id].data.Cluster ||
            !collection.emr.describeCluster[AWSConfig.region][cluster.Id].data.Cluster.SecurityConfiguration) {
            return cb();
        }
            
        var securityConfigurationName = collection.emr.describeCluster[AWSConfig.region][cluster.Id].data.Cluster.SecurityConfiguration;

        collection.emr.describeSecurityConfiguration[AWSConfig.region][securityConfigurationName] = {};
        var params = {
            'Name': securityConfigurationName
        };

        helpers.makeCustomCollectorCall(emr, 'describeSecurityConfiguration', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.emr.describeSecurityConfiguration[AWSConfig.region][securityConfigurationName].err = err;
            }
            collection.emr.describeSecurityConfiguration[AWSConfig.region][securityConfigurationName].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
