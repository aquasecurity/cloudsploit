var async = require('async');
var cache = require('./cache.js');

var ONE_DAY = 24*60*60*1000;

var CREDENTIAL_DOWNLOAD_STARTED = false;
var CREDENTIAL_REPORT_DATA;
var CREDENTIAL_REPORT_ERROR;

function daysBetween(date1, date2) {
	return Math.round(Math.abs((new Date(date1).getTime() - new Date(date2).getTime())/(ONE_DAY)));
}

function daysAgo(date1) {
	return daysBetween(date1, new Date());
}

function mostRecentDate(dates) {
	var mostRecentDate;

	for (d in dates) {
		if (!mostRecentDate || dates[d] > mostRecentDate) {
			mostRecentDate = dates[d];
		}
	}

	return mostRecentDate;
}

function waitForCredentialReport(iam, callback) {
	if (CREDENTIAL_REPORT_DATA) return callback(null, CREDENTIAL_REPORT_DATA);
	if (CREDENTIAL_REPORT_ERROR) return callback(CREDENTIAL_REPORT_ERROR);

	if (!CREDENTIAL_DOWNLOAD_STARTED) {
		CREDENTIAL_DOWNLOAD_STARTED = true;

		iam.generateCredentialReport(function(err, data){
			if ((err && err.code && err.code == 'ReportInProgress') || (data && data.State)) {
				// Okay to query for credential report
				waitForCredentialReport(iam, callback);
			} else {
				CREDENTIAL_REPORT_ERROR = 'Error downloading report';
				callback(CREDENTIAL_REPORT_ERROR);
			}
		});
	} else {
		var pingCredentialReport = function(pingCb, pingResults) {
			iam.getCredentialReport(function(getErr, getData) {
				if (getErr || !getData || !getData.Content) {
					return pingCb('Waiting for credential report');
				}

				pingCb(null, getData);
			});
		};

		async.retry({times: 10, interval: 1000}, pingCredentialReport, function(reportErr, reportData){
			if (reportErr || !reportData) {
				CREDENTIAL_REPORT_ERROR = 'Error downloading report';
				return callback(CREDENTIAL_REPORT_ERROR);
			}

			CREDENTIAL_REPORT_DATA = reportData;
			callback(null, CREDENTIAL_REPORT_DATA);
		});
	}
}

module.exports = {
	daysBetween: daysBetween,
	daysAgo: daysAgo,
	mostRecentDate: mostRecentDate,
	waitForCredentialReport: waitForCredentialReport
};