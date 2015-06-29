var pluginInfo = {
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

module.exports = {
	title: pluginInfo.title,
	query: pluginInfo.query,
	category: pluginInfo.category,
	description: pluginInfo.description,
	more_info: pluginInfo.more_info,
	link: pluginInfo.link,

	run: function(AWS, callback) {

		var iam = new AWS.IAM();

		iam.getAccountSummary(function(err, data){
			if (err) {
				callback(err);
				return;
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
				callback(null, pluginInfo);
			} else {
				callback('unexpected return data');
				return;
			}
		});
	}
};