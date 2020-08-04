var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var iam = new AWS.IAM(AWSConfig);

    var generateCredentialReport = function(genCb) {
        iam.generateCredentialReport(function(err, data) {
            if ((err && err.code && err.code == 'ReportInProgress') || (data && data.State)) return genCb();
            if (err || !data || !data.State) return genCb(err || 'Unable to generate credential report');
            genCb();
        });
    };

    var getCredentialReport = function(pingCb) {
        iam.getCredentialReport(function(err, data) {
            if (err || !data || !data.Content) return pingCb('Waiting for credential report');
            pingCb(null, data);
        });
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
                var csvContent = reportData.Content.toString();
                var csvRows = csvContent.split('\n');
            } catch(e) {
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