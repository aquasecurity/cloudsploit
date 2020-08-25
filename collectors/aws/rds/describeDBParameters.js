var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var rds = new AWS.RDS(AWSConfig);

    async.eachLimit(collection.rds.describeDBParameterGroups[AWSConfig.region].data, 15, function(parameterGroupName, cb){
        collection.rds.describeDBParameters[AWSConfig.region][parameterGroupName.DBParameterGroupName] = {};
        collection.rds.describeDBParameters[AWSConfig.region][parameterGroupName.DBParameterGroupName].data = {}
        collection.rds.describeDBParameters[AWSConfig.region][parameterGroupName.DBParameterGroupName].data.Parameters = []

        var params = {
            DBParameterGroupName: parameterGroupName.DBParameterGroupName
        };

        rds.describeDBParameters(params).eachPage(function(err, data) {
            if (!data){
                cb();
            } else {
                collection.rds.describeDBParameters[AWSConfig.region][parameterGroupName.DBParameterGroupName].data.Parameters =
                    collection.rds.describeDBParameters[AWSConfig.region][parameterGroupName.DBParameterGroupName].data.Parameters.concat(data.Parameters);
            }
            if (err) {
                collection.rds.describeDBParameters[AWSConfig.region][parameterGroupName.DBParameterGroupName].err = err;
            }
        });
    }, function(){
        callback();
    });
};