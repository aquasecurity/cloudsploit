var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var rds = new AWS.RDS(AWSConfig);
    

	async.eachLimit(collection.rds.describeDBInstances[AWSConfig.region].data, 15, function(group, cb){
        var groupName = group.OptionGroupMemberships[0].OptionGroupName;
        collection.rds.describeOptionGroups[AWSConfig.region][groupName] = {};
        
        var params = {
            OptionGroupName: groupName
        };
        
        rds.describeOptionGroups(params, function(err, data) {
            if (err) {
                collection.rds.describeOptionGroups[AWSConfig.region][groupName].err = err;
            }
            collection.rds.describeOptionGroups[AWSConfig.region][groupName].data = data
            cb();
        });
    }, function(){
        callback();
    });
};