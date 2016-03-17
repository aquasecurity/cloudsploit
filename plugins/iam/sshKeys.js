var async = require('async');
var AWS = require('aws-sdk');

function getPluginInfo() {
	return {
		title: 'SSH Keys',
		query: 'sshKeys',
		category: 'IAM',
		description: 'Ensures SSH keys are properly rotated and audited',
		tests: {
			sshKeysRotated: {
				title: 'SSH Keys Rotated',
				description: 'Ensures SSH keys are not older than 180 days in order to reduce accidental exposures',
				more_info: 'SSH keys should be rotated frequently to avoid having them accidentally exposed.',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_ssh-keys.html',
				recommended_action: 'To rotate an SSH key, first create a new public-private key pair, then upload the public key to AWS and delete the old key.',
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

		iam.listUsers({}, function(err, data){
			if (err) {
				var returnMsg = {
					status: 3,
					message: 'Unable to query for users',
					region: 'global'
				};
				pluginInfo.tests.sshKeysRotated.results.push(returnMsg);

				return callback(null, pluginInfo);
			}

			if (data && data.Users) {
				if (data.Users.length) {

					var allSSHKeys = [];

					var oneDay = 24*60*60*1000;
					var now = new Date();
					var oneEightyDaysAgo = new Date(now - (oneDay*180));
					var threeSixtyDaysAgo = new Date(now - (oneDay*360));

					async.eachLimit(data.Users, 20, function(user, cb){
						iam.listSSHPublicKeys({UserName: user.UserName}, function(sshKeysErr, sshKeysData) {
							if (sshKeysErr) {
								pluginInfo.tests.sshKeysRotated.results.push({
									status: 3,
									message: 'Unable to query SSH keys for user: ' + user.UserName,
									region: 'global',
									resource: user.Arn
								});
							} else {
								if (sshKeysData && sshKeysData.SSHPublicKeys && sshKeysData.SSHPublicKeys.length) {
									for (i in sshKeysData.SSHPublicKeys) {
										allSSHKeys.push(sshKeysData.SSHPublicKeys[i].SSHPublicKeyId);
										
										var keyDate = new Date(sshKeysData.SSHPublicKeys[i].UploadDate);
										var daysOld = Math.round(Math.abs((now.getTime() - keyDate.getTime())/(oneDay)));

										var message = 'SSH key: ' + sshKeysData.SSHPublicKeys[i].SSHPublicKeyId + ' for user: ' + sshKeysData.SSHPublicKeys[i].UserName + ' is ' + daysOld + ' days old';
										var status = 0;
										
										if (keyDate < threeSixtyDaysAgo) {
											status = 2;
										} else if (keyDate < oneEightyDaysAgo) {
											status = 1;
										}

										pluginInfo.tests.sshKeysRotated.results.push({
											status: status,
											message: message,
											region: 'global',
											resource: sshKeysData.SSHPublicKeys[i].SSHPublicKeyId
										});
									}
								}
							}
							cb();
						});
					}, function(){
						if (!allSSHKeys.length) {
							pluginInfo.tests.sshKeysRotated.results.push({
								status: 0,
								message: 'No SSH keys found',
								region: 'global'
							});
						}

						return callback(null, pluginInfo);
					});
				} else {
					var returnMsg = {
						status: 0,
						message: 'No user accounts with SSH keys found',
						region: 'global'
					};
					pluginInfo.tests.sshKeysRotated.results.push(returnMsg);

					callback(null, pluginInfo);
				}
			} else {
				var returnMsg = {
					status: 3,
					message: 'Unable to query SSH keys',
					region: 'global'
				};
				pluginInfo.tests.sshKeysRotated.results.push(returnMsg);

				return callback(null, pluginInfo);
			}
		});
	}
};