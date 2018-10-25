var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
	title: 'Encrypted AMI',
	category: 'EC2',
	description: 'Checks for encrypted root EBS volume for AMI',
	more_info: 'Instances that are not based on encrypted EBS root volumes pose a security threat due to potential data snooping.',
	link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-an-ami-ebs.html',
	recommended_action: 'Create an Amazon EC2 instance backed by encrypted EBS volume.',
	apis: ['EC2:describeImages'],
	compliance: {
        hipaa: 'HIPAA data should not be stored on EC2 AMIs. However, if data is ' +
        		'accidentally included within an AMI, encrypting that data will ' +
        		'allow it to remain compliant with the encryption at-rest ' +
        		'regulatory requirement.'
    },

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var regions = helpers.regions(settings.govcloud);

		async.each(regions.ec2, function(region, rcb){
			var describeImages = helpers.addSource(cache, source,
				['ec2', 'describeImages', region]);

			if (!describeImages) return rcb();

			if (describeImages.err || !describeImages.data) {
				helpers.addResult(results, 3,
					'Unable to query for AMIs: ' + helpers.addError(describeImages), region);
				return rcb();
			}

			if (!describeImages.data.length) {
				helpers.addResult(results, 0, 'No AMIs found', region);
				return rcb();
			}

			var unencryptedAmis = [];

			for (i in describeImages.data) {
				var image = describeImages.data[i];
				for (j in image.BlockDeviceMappings) {
					var volume = image.BlockDeviceMappings[j];
					if (volume.hasOwnProperty('Ebs')) {
						if (!volume.Ebs.Encrypted) {
							unencryptedAmis.push(image.ImageId);
							break;
						}
					}
				}
			}

			if (unencryptedAmis.length > 20) {
				helpers.addResult(results, 2, 'More than 20 AMI EBS volumes are unencrypted', region);
			} else if (unencryptedAmis.length) {
				for (u in unencryptedAmis) {
					helpers.addResult(results, 2, 'AMI EBS volume is unencrypted', region, unencryptedAmis[u]);
				}
			} else {
				helpers.addResult(results, 0, 'No AMIs with unencrypted volumes found', region);
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
