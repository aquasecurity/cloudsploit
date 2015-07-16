var AWS = require('aws-sdk');

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

		iam.getAccountSummary(function(err, data){
			if (err) {
				pluginInfo.tests.rootMfaEnabled.results.push({
					status: 3,
					message: 'Unable to query for MFA status'
				});
				pluginInfo.tests.rootAccessKeys.results.push({
					status: 3,
					message: 'Unable to query for access key status'
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

				if (data.SummaryMap.AccountAccessKeysPresent > 0) {
					pluginInfo.tests.rootAccessKeys.results.push({
						status: 2,
						message: 'Access keys were found for the root account'
					});
				} else {
					pluginInfo.tests.rootAccessKeys.results.push({
						status: 0,
						message: 'No access keys were found for the root account'
					});
				}

				return callback(null, pluginInfo);
			}

			pluginInfo.tests.rootMfaEnabled.results.push({
				status: 3,
				message: 'Unexpected data when querying MFA status'
			});

			pluginInfo.tests.rootAccessKeys.results.push({
				status: 3,
				message: 'Unexpected data when querying access key status'
			});

			return callback(null, pluginInfo);
		});
	}
};