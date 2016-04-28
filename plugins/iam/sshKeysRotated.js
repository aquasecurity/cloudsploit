var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'SSH Keys Rotated',
	category: 'IAM',
	description: 'Ensures SSH keys are not older than 180 days in order to reduce accidental exposures',
	more_info: 'SSH keys should be rotated frequently to avoid having them accidentally exposed.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_ssh-keys.html',
	recommended_action: 'To rotate an SSH key, first create a new public-private key pair, then upload the public key to AWS and delete the old key.',

	run: function(AWSConfig, callback) {
		var results = [];

		var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

		// Update the region
		LocalAWSConfig.region = 'us-east-1';

		var iam = new AWS.IAM(LocalAWSConfig);

		helpers.cache(iam, 'listUsers', function(err, data) {
			if (err || !data || !data.Users) {
				results.push({
					status: 3,
					message: 'Unable to query for users',
					region: 'global'
				});

				return callback(null, results);
			}

			if (!data.Users.length) {
				results.push({
					status: 0,
					message: 'No user accounts with SSH keys found',
					region: 'global'
				});

				return callback(null, results);
			}

			var allSSHKeys = [];

			async.eachLimit(data.Users, 20, function(user, cb){
				iam.listSSHPublicKeys({UserName: user.UserName}, function(sshKeysErr, sshKeysData) {
					if (sshKeysErr) {
						results.push({
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
								var daysOld = helpers.functions.daysAgo(keyDate);

								var message = 'SSH key: ' + sshKeysData.SSHPublicKeys[i].SSHPublicKeyId + ' for user: ' + sshKeysData.SSHPublicKeys[i].UserName + ' is ' + daysOld + ' days old';
								var status = 0;
								
								if (daysOld >= 360) {
									status = 2;
								} else if (daysOld >= 180) {
									status = 1;
								}

								results.push({
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
					results.push({
						status: 0,
						message: 'No SSH keys found',
						region: 'global'
					});
				}

				callback(null, results);
			});
		});
	}
};