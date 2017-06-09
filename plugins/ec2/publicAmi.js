var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Public AMI',
	category: 'EC2',
	description: 'Checks for publicly shared AMIs',
	more_info: 'Accidentally sharing AMIs allows any AWS user to launch an EC2 instance using the image as a base. This can potentially expose sensitive information stored on the host.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html',
	recommended_action: 'Convert the public AMI a private image.',
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

			// Now lookup flow logs and map to images
			for (i in describeImages.data) {
				var image = describeImages.data[i];

				if (image.Public) {
					found = true;

					helpers.addResult(results, 1, 'AMI is public', region,
						'arn:aws:ec2:' + region + '::image/' + image.ImageId);
				}
			}

			if (!found) {
				helpers.addResult(results, 0, 'No public AMIs found', region);
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
