var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var codebuild = new AWS.CodeBuild(AWSConfig);

    async.eachLimit(collection.codebuild.listProjects[AWSConfig.region].data, 15, function(project, cb){
        collection.codebuild.batchGetProjects[AWSConfig.region][project] = {};

        var params = {
            names: [project],
        };

        helpers.makeCustomCollectorCall(codebuild, 'batchGetProjects', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.codebuild.batchGetProjects[AWSConfig.region][project].err = err;
            }
            collection.codebuild.batchGetProjects[AWSConfig.region][project].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};