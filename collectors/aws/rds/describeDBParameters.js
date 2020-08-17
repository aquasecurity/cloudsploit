var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var rds = new AWS.RDS(AWSConfig);
    async.eachLimit(collection.rds.describeDBParameterGroups[AWSConfig.region].data, 15, function(group, cb){
        collection.rds.describeDBParameters[AWSConfig.region][group.DBParameterGroupName] = {};

        var params = {
            DBParameterGroupName: group.DBParameterGroupName
        };

        rds.describeDBParameters(params, function(err, data) {
            if (err) {
                collection.rds.describeDBParameters[AWSConfig.region][group].err = err;
            }
            collection.rds.describeDBParameters[AWSConfig.region][group.DBParameterGroupName].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};