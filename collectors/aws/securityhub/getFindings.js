var AWS = require('aws-sdk');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var securityhub = new AWS.SecurityHub(AWSConfig);
    collection.securityhub.getFindings[AWSConfig.region] = {};

    const params = {
        MaxResults: 100,
        Filters: {
            RecordState: [
                {
                    Comparison: 'EQUALS',
                    Value: 'ACTIVE'
                }
            ],
            WorkflowStatus: [
                {
                    Comparison: 'EQUALS',
                    Value: 'NEW'
                }
            ]
        }
    };

    var paginateCb = function(err, data) {
        if (err) {
            collection.securityhub.getFindings[AWSConfig.region].err = err;
        } else if (data && data.Findings && data.Findings.length) {
            collection.securityhub.getFindings[AWSConfig.region].data = [data.Findings]; // only returning the first finding
        }

        callback();
    };

    function execute() {
        helpers.makeCustomCollectorCall(securityhub, 'getFindings', params, retries, null, null, null, paginateCb);
    }
    execute();
};
