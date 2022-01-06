var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var lookoutvision = new AWS.LookoutVision(AWSConfig);

    if (!collection.lookoutvision ||
        !collection.lookoutvision.listProjects ||
        !collection.lookoutvision.listProjects[AWSConfig.region] ||
        !collection.lookoutvision.listProjects[AWSConfig.region].data) return callback();

    async.eachLimit(collection.lookoutvision.listProjects[AWSConfig.region].data, 5, function(project, cb){
        
        if (!project.ProjectName || !collection.lookoutvision ||
            !collection.lookoutvision.listModels ||
            !collection.lookoutvision.listModels[AWSConfig.region] ||
            !collection.lookoutvision.listModels[AWSConfig.region][project.ProjectName] ||
            !collection.lookoutvision.listModels[AWSConfig.region][project.ProjectName].data ||
            !collection.lookoutvision.listModels[AWSConfig.region][project.ProjectName].data.Models ||
            !collection.lookoutvision.listModels[AWSConfig.region][project.ProjectName].data.Models.length) {
            return cb();
        }

        async.eachLimit(collection.lookoutvision.listModels[AWSConfig.region][project.ProjectName].data.Models, 3, function(model, pCb){
            collection.lookoutvision.describeModel[AWSConfig.region][model.ModelArn] = {};

            // Make the describe Models call
            helpers.makeCustomCollectorCall(lookoutvision, 'describeModel', {ModelVersion: model.ModelVersion,ProjectName: project.ProjectName}, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.lookoutvision.describeModel[AWSConfig.region][model.ModelArn].err = err;
                }

                collection.lookoutvision.describeModel[AWSConfig.region][model.ModelArn].data = data;
                pCb();
            });
        }, function() {
            cb();
        });
    }, function(){
        callback();
    });
};