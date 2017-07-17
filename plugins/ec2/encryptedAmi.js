var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Encrypted AMI',
	category: 'EC2',
	description: 'Checks for encrypted root EBS volume for AMI',
	more_info: 'Instances that are not based on encrypted EBS root volumes pose a security threat due to potential data snooping.',
	link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-an-ami-ebs.html',
	recommended_action: 'Create an Amazon EC2 instance backed by encrypted EBS volume.',
	apis: ['EC2:describeImages'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.ec2, function(region, rcb){
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

			var found = false;

			for (i in describeImages.data) {
				var image = describeImages.data[i];
				for (j in image.BlockDeviceMappings) {
					var volume = image.BlockDeviceMappings[j];
					if (volume.hasOwnProperty('Ebs')) {
						if (!volume.Ebs.Encrypted) {
							found = true;
							helpers.addResult(results, 2, 'AMI EBS volume is unencrypted', region, image.ImageId);
							break;
						}
					}
				}
			}

			if (!found) {
				helpers.addResult(results, 0, 'No AMIs with unencrypted volumes found', region);
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
