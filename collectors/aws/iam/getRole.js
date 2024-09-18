var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var iam = new AWS.IAM(AWSConfig);

    if (!collection.iam ||
        !collection.iam.listRoles ||
        !collection.iam.listRoles[AWSConfig.region] ||
        !collection.iam.listRoles[AWSConfig.region].data) return callback();

    async.eachLimit(collection.iam.listRoles[AWSConfig.region].data, 10, function(role, cb){
        if (!role.Arn ||
            !collection.iam.listRoles ||
            !collection.iam.listRoles[AWSConfig.region] ||
            !collection.iam.listRoles[AWSConfig.region].data) {

            return cb();
        }

        collection.iam.getRole[AWSConfig.region][role.RoleName] = {};

        helpers.makeCustomCollectorCall(iam, 'getRole', {RoleName: role.RoleName}, retries, null, null, null, function(err, data) {
            if (err) {
                collection.iam.getRole[AWSConfig.region][role.RoleName].err = err;
            }
            if (data) {
                delete data['ResponseMetadata'];

                data.Role.AssumeRolePolicyDocument = helpers.normalizePolicyDocument(data.Role.AssumeRolePolicyDocument);
                collection.iam.getRole[AWSConfig.region][role.RoleName].data = data;
            }

            cb();
        });
    }, function(){
        callback();
    });
};
