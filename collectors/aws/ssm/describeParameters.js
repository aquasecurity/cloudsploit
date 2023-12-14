const {
    SSM
} = require('@aws-sdk/client-ssm');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ssm = new SSM(AWSConfig);
    collection.ssm.describeParameters[AWSConfig.region] = {};
    var params = {};

    var paginating = false;
    var paginateCb = function(err, data) {
        if (err) {
            collection.ssm.describeParameters[AWSConfig.region].err = err;
        } else if (data) {
            data.Parameters.map(param =>
                param['Name'] = param.Name.charAt(0) === '/' ? param.Name.slice(1) : param.Name);
            if (paginating && data.Parameters && data.Parameters.length &&
                collection.ssm.describeParameters[AWSConfig.region].data &&
                collection.ssm.describeParameters[AWSConfig.region].data.length) {
                collection.ssm.describeParameters[AWSConfig.region].data = collection.ssm.describeParameters[AWSConfig.region].data.concat(data.Parameters);
            } else {
                collection.ssm.describeParameters[AWSConfig.region].data = data.Parameters;
            }
            if (data.NextToken && data.NextToken.length) {
                paginating = true;
                return execute(data.NextToken);
            }
        }


        callback();
    };

    function execute(marker) {
        var localParams = JSON.parse(JSON.stringify(params || {}));
        if (marker) localParams['NextToken'] = marker;
        helpers.makeCustomCollectorCall(ssm, 'describeParameters', localParams, retries, null, null, null, paginateCb);
    }

    execute();
};
