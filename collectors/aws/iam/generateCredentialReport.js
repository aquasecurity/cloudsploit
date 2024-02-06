const {
    IAM,GenerateCredentialReportCommand, GetCredentialReportCommand 
} = require('@aws-sdk/client-iam');
var async = require('async');

module.exports = function(AWSConfig, collection, retries, callback) {
    var iam = new IAM(AWSConfig);

    const generateCredentialReport = function(genCb) {
        iam.send(new GenerateCredentialReportCommand({}))
            .then((data) => {
                if (data && data.State) {
                    return genCb();
                }
                return genCb(data.State || 'Unable to generate credential report');
            })
            .catch((err) => {
                if (err.name === 'ReportInProgressException') {
                    return genCb();
                }
                return genCb(err);
            });
    };
    const getCredentialReport = function(pingCb) {
        const command = new GetCredentialReportCommand({});
        iam.send(command)
            .then((data) => {
                if (data && data.Content) {
                    return pingCb(null, data);
                }
                return pingCb('Waiting for credential report');
            })
            .catch((err) => pingCb(err));
    };

    async.retry({times: 10, interval: 5000}, generateCredentialReport, function(genErr){
        if (genErr) {
            collection.iam.generateCredentialReport[AWSConfig.region].err = genErr || 'Unable to download credential report';
            return callback();
        }

        async.retry({times: 10, interval: 5000}, getCredentialReport, function(reportErr, reportData){
            if (reportErr || !reportData || !reportData.Content) {
                collection.iam.generateCredentialReport[AWSConfig.region].err = reportErr || 'Unable to download credential report';
                return callback();
            }
            
            try {
                const csvContent = String.fromCharCode(...reportData.Content.toString('utf-8').split(',').map(Number));
                var csvRows = csvContent.split('\n');
            } catch (e) {
                collection.iam.generateCredentialReport[AWSConfig.region].err = 'Error converting credential CSV to string: ' + e;
                return callback();
            }

            if (!csvRows[0]) {
                collection.iam.generateCredentialReport[AWSConfig.region].err = 'Error reading credential CSV';
                return callback();
            }

            var headings = [];
            var entries = [];

            for (var r in csvRows) {
                var csvRow = csvRows[r];
                var csvFields = csvRow.split(',');
                
                // Create the header row
                if (r == 0) {
                    headings = csvRow.split(',');
                    continue;
                } else {
                    var entry = {};

                    for (var f in csvFields) {
                        var field = csvFields[f];

                        if (field === 'TRUE' || field === 'true') {
                            field = true;
                        } else if (field === 'FALSE' || field === 'false') {
                            field = false;
                        } else if (field === 'N/A') {
                            field = null;
                        }

                        entry[headings[f]] = field;
                    }

                    entries.push(entry);
                }
            }

            collection.iam.generateCredentialReport[AWSConfig.region].data = entries;
            callback();
        });
    });
};