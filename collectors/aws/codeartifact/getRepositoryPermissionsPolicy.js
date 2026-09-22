var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, settings, scanAWSConfig, callback) {
    var codeartifact = new AWS.CodeArtifact(AWSConfig);

    // Needs both domain and repository, so the generic single-key postcall path cannot be used
    async.eachLimit(collection.codeartifact.listRepositories[AWSConfig.region].data, 10, function(repository, cb){
        collection.codeartifact.getRepositoryPermissionsPolicy[AWSConfig.region][repository.arn] = {};

        var params = {
            domain: repository.domainName,
            repository: repository.name
        };
        if (repository.domainOwner) params.domainOwner = repository.domainOwner;

        helpers.makeCustomCollectorCall(codeartifact, 'getRepositoryPermissionsPolicy', params, retries, null, null, null, settings, scanAWSConfig, AWSConfig, function(err, data) {
            if (err) {
                collection.codeartifact.getRepositoryPermissionsPolicy[AWSConfig.region][repository.arn].err = err;
            }
            if (data) collection.codeartifact.getRepositoryPermissionsPolicy[AWSConfig.region][repository.arn].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
