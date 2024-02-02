const {
    IAM
} = require('@aws-sdk/client-iam');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var iam = new IAM(AWSConfig);
    collection.iam.listRoles[AWSConfig.region] = {};
    var params = {};

    var paginating = false;
    var paginateCb = function(err, data) {
        if (err) {
            collection.iam.listRoles[AWSConfig.region].err = err;
        } else if (data) {
            data.Roles.map(role =>
                role['AssumeRolePolicyDocument'] = helpers.normalizePolicyDocument(role['AssumeRolePolicyDocument']));
            if (paginating && data.Roles && data.Roles.length &&
                collection.iam.listRoles[AWSConfig.region].data &&
                collection.iam.listRoles[AWSConfig.region].data.length) {
                collection.iam.listRoles[AWSConfig.region].data = collection.iam.listRoles[AWSConfig.region].data.concat(data.Roles);
            } else {
                collection.iam.listRoles[AWSConfig.region].data = data.Roles;
            }
            if (data.Marker && data.Marker.length) {
                paginating = true;
                return execute(data.Marker);
            }
        }


        callback();
    };

    function execute(marker) {
        var localParams = JSON.parse(JSON.stringify(params || {}));
        if (marker) localParams['Marker'] = marker;
        helpers.makeCustomCollectorCall(iam, 'listRoles', localParams, retries, null, null, null, paginateCb);
    }

    execute();
};
