var AWS = require('aws-sdk');

function getPluginInfo() {
	return {
		title: 'Root MFA Enabled',
		query: 'rootMfaEnabled',
		category: 'IAM',
		aws_service: 'IAM',
		description: 'Ensures a multi-factor authentication device is enabled for the root account',
		more_info: 'The root account should have an MFA device setup to enable two-factor authentication',
		link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
		tests: {
			rootMfaEnabled: {
				title: 'Root MFA Enabled',
				description: 'Ensures a multi-factor authentication device is enabled for the root account',
				recommendedAction: 'Enable an MFA device for the root account and then use an IAM user for managing services',
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

	run: function(AWSConfig, callback) {
		var iam = new AWS.IAM(AWSConfig);
		var pluginInfo = getPluginInfo();

		iam.getAccountSummary(function(err, data){
			if (err) {
				pluginInfo.tests.rootMfaEnabled.results.push({
					status: 3,
					message: 'Unable to query for MFA status'
				});
				return callback(null, pluginInfo);
			}

			// Perform checks for establishing if MFA token is enabled
			if (data && data.SummaryMap) {
				if (data.SummaryMap.AccountMFAEnabled) {
					pluginInfo.tests.rootMfaEnabled.results.push({
						status: 0,
						message: 'An MFA device was found for the root account'
					});
				} else {
					pluginInfo.tests.rootMfaEnabled.results.push({
						status: 2,
						message: 'An MFA device was not found for the root account'
					});
				}
				return callback(null, pluginInfo);
			}

			pluginInfo.tests.rootMfaEnabled.results.push({
				status: 3,
				message: 'Unexpected data when querying MFA status'
			});

			return callback(null, pluginInfo);
		});
	}
};