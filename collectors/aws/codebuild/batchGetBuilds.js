var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

// batchGetBuilds accepts at most 100 build ids per request
var MAX_IDS_PER_CALL = 100;

module.exports = function(AWSConfig, collection, retries, settings, scanAWSConfig, callback) {
    var codebuild = new AWS.CodeBuild(AWSConfig);

    // listBuilds returns bare id strings, so chunk them rather than calling per build
    var ids = collection.codebuild.listBuilds[AWSConfig.region].data;
    var chunks = [];
    for (var i = 0; i < ids.length; i += MAX_IDS_PER_CALL) {
        chunks.push(ids.slice(i, i + MAX_IDS_PER_CALL));
    }

    collection.codebuild.batchGetBuilds[AWSConfig.region].data = [];

    async.eachLimit(chunks, 5, function(chunk, cb){
        var params = {
            ids: chunk
        };

        helpers.makeCustomCollectorCall(codebuild, 'batchGetBuilds', params, retries, null, null, null, settings, scanAWSConfig, AWSConfig, function(err, data) {
            if (err) {
                collection.codebuild.batchGetBuilds[AWSConfig.region].err = err;
            } else if (data && data.builds && data.builds.length) {
                collection.codebuild.batchGetBuilds[AWSConfig.region].data =
                    collection.codebuild.batchGetBuilds[AWSConfig.region].data.concat(data.builds);
            }
            cb();
        });
    }, function(){
        callback();
    });
};
