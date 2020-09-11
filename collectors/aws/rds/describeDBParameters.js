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
            if (err) {
                collection.rds.describeDBParameters[AWSConfig.region][parameterGroupName.DBParameterGroupName].err = err;
                collection.rds.describeDBParameters[AWSConfig.region][parameterGroupName.DBParameterGroupName].data = null;
            } else if (!data) {
                cb(); // once eachPage is done iterating, data will be null, so then we call the callback once.
            } else {
                collection.rds.describeDBParameters[AWSConfig.region][parameterGroupName.DBParameterGroupName].data.Parameters =
                    collection.rds.describeDBParameters[AWSConfig.region][parameterGroupName.DBParameterGroupName].data.Parameters.concat(data.Parameters);
            }
        });
    }, function(){
        callback();
    });
};
