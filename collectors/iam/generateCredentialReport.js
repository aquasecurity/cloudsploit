var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
	var iam = new AWS.IAM(AWSConfig);

	iam.generateCredentialReport(function(err, data){
		if ((err && err.code && err.code == 'ReportInProgress') || (data && data.State)) {
			// Okay to query for credential report

			var pingCredentialReport = function(pingCb, pingResults) {
				iam.getCredentialReport(function(getErr, getData) {
					if (getErr || !getData || !getData.Content) {
						return pingCb('Waiting for credential report');
					}

					pingCb(null, getData);
				});
			};

			async.retry({times: 10, interval: 1000}, pingCredentialReport, function(reportErr, reportData){
				if (reportErr || !reportData || !reportData.Content) {
					collection.iam.generateCredentialReport[AWSConfig.region].err = reportErr || 'Unable to download credential report';
					return callback();
				}
				
				try {
					var csvContent = reportData.Content.toString();
					var csvRows = csvContent.split('\n');
					var firstRow = csvRows[0];
				} catch(e) {
					collection.iam.generateCredentialReport[AWSConfig.region].err = 'Error converting credential CSV to string: ' + e;
					return callback();
				}

				var headings = [];
				var entries = [];

				for (r in csvRows) {
					var csvRow = csvRows[r];
					var csvFields = csvRow.split(',');
					
					// Create the header row
					if (r == 0) {
						headings = csvRow.split(',');
						continue;
					} else {
						var entry = {};

						for (f in csvFields) {
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
		} else {
			collection.iam.generateCredentialReport[AWSConfig.region].err = err || 'Unable to download credential report';
			callback();
		}
	});
};