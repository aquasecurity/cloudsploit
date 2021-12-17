var AWS = require('aws-sdk');
var async = require('async');

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
            collection.lookoutvision.describeModel[AWSConfig.region][model.ModelVersion] = {};

            // Make the describe Models call
            lookoutvision.describeModel({
                ModelVersion: model.ModelVersion,
                ProjectName: project.ProjectName
            }, function(err, data){
                if (err) {
                    collection.lookoutvision.describeModel[AWSConfig.region][model.ModelVersion].err = err;
                }

                collection.lookoutvision.describeModel[AWSConfig.region][model.ModelVersion].data = data;
                pCb();
            });
        }, function(){
            setTimeout(function(){
                cb();
            }, 100);
        });
    }, function(){
        callback();
    });
};