var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

function getPluginInfo() {
	return {
		title: 'Root Account Security',
		query: 'rootAccountSecurity',
		category: 'IAM',
		description: 'Ensures a multi-factor authentication device is enabled for the root account and that no access keys are present',
		tests: {
			rootMfaEnabled: {
				title: 'Root MFA Enabled',
				description: 'Ensures a multi-factor authentication device is enabled for the root account',
				more_info: 'The root account should have an MFA device setup to enable two-factor authentication.',
				link: 'http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html',
				recommended_action: 'Enable an MFA device for the root account and then use an IAM user for managing services',
				results: []
			},
			rootAccessKeys: {
				title: 'Root Access Keys',
				description: 'Ensures the root account is not using access keys',
				more_info: 'The root account should avoid using access keys. Since the root account has full permissions across the entire account, creating access keys for it only increases the chance that they are compromised. Instead, create IAM users with pre-defined roles.',
				link: 'http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html',
				recommended_action: 'Remove access keys for the root account and setup IAM users with limited permissions instead',
				results: []
			},
			rootAccountInUse: {
				title: 'Root Account In Use',
				description: 'Ensures the root account is not being actively used',
				more_info: 'The root account should not be used for day-to-day account management. IAM users, roles, and groups should be used instead.',
				link: 'http://docs.aws.amazon.com/general/latest/gr/root-vs-iam.html',
				recommended_action: 'Create IAM users with appropriate group-level permissions for account access. Create an MFA token for the root account, and store its password and token generation QR codes in a secure place.',
				results: []
			}
		}
	};
}

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {
		var iam = new AWS.IAM(AWSConfig);
		var pluginInfo = getPluginInfo();

		async.parallel([
			// Test the IAM MFA and access keys
			function(cb) {
				iam.getAccountSummary(function(err, data){
					if (err) {
						pluginInfo.tests.rootMfaEnabled.results.push({
							status: 3,
							message: 'Unable to query for MFA status',
							region: 'global'
						});
						pluginInfo.tests.rootAccessKeys.results.push({
							status: 3,
							message: 'Unable to query for access key status',
							region: 'global'
						});
						return cb();
					}

					// Perform checks for establishing if MFA token is enabled
					if (data && data.SummaryMap) {
						if (data.SummaryMap.AccountMFAEnabled) {
							pluginInfo.tests.rootMfaEnabled.results.push({
								status: 0,
								message: 'An MFA device was found for the root account',
								region: 'global'
							});
						} else {
							pluginInfo.tests.rootMfaEnabled.results.push({
								status: 2,
								message: 'An MFA device was not found for the root account',
								region: 'global'
							});
						}

						if (data.SummaryMap.AccountAccessKeysPresent > 0) {
							pluginInfo.tests.rootAccessKeys.results.push({
								status: 2,
								message: 'Access keys were found for the root account',
								region: 'global'
							});
						} else {
							pluginInfo.tests.rootAccessKeys.results.push({
								status: 0,
								message: 'No access keys were found for the root account',
								region: 'global'
							});
						}

						return cb();
					}

					pluginInfo.tests.rootMfaEnabled.results.push({
						status: 3,
						message: 'Unexpected data when querying MFA status',
						region: 'global'
					});

					pluginInfo.tests.rootAccessKeys.results.push({
						status: 3,
						message: 'Unexpected data when querying access key status',
						region: 'global'
					});

					return cb();
				});
			},
			// Test last-used time for the root account
			function(cb) {
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
							if (reportErr || !reportData) {
								pluginInfo.tests.rootAccountInUse.results.push({
									status: 3,
									message: 'Unable to query for root account usage',
									region: 'global'
								});

								return cb();
							}

							var csvContent = reportData.Content.toString();
							var csvRows = csvContent.split('\n');

							for (r in csvRows) {
								var csvRow = csvRows[r];
								var csvFields = csvRow.split(',');

								if (csvFields[0] === '<root_account>') {
									var rootCreated = new Date(csvFields[2]);
									var rootLastUsed = new Date(csvFields[4]);

									// If the account was accessed >7 days after being created and
									// <10 days ago, then assume the root account is being actively used
									if (helpers.functions.daysBetween(rootCreated, rootLastUsed) > 7 &&
										helpers.functions.daysAgo(rootLastUsed) < 10) {
										console.log('Used recently');
									}

								}
							}

						});
					} else {
						pluginInfo.tests.rootAccountInUse.results.push({
							status: 3,
							message: 'Unable to query for root account usage',
							region: 'global'
						});

						cb();
					}

					
				});
			}
		], function(){
			return callback(null, pluginInfo);
		});
	}
};