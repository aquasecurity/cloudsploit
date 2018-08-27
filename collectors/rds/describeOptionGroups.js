var AWS = require('aws-sdk');
var async = require('async');
const _ = require("lodash");

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
            
            let encrypted = _.find(data.OptionGroupsList[0].Options, { "OptionName": "TDE" });
            collection.rds.describeOptionGroups[AWSConfig.region][groupName].data = !encrypted ? false : true;
            cb();
        });
    }, function(){
        callback();
    });
};