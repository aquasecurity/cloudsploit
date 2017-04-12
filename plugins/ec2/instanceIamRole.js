var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
    title: 'EC2 Instance IAM Role',
	category: 'EC2',
	description: 'Detects EC2 instances that do not have IAM roles attached to them ',
	more_info: 'EC2 instances should have IAM roles assigned to them so that' +
	'their applications can make use of AWS temporary access credentials. ' +
	'Applications running on EC2 should not use long-lived access keys and secrets.',

	link: '"http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html',
	recommended_action: 'Create an IAM role for the EC2 instance with the' +
	'required, limited permissions. Attach the role to the EC2 instance using' +
	 'an IAM instance profile.',

	run: function(AWSConfig, cache, includeSource, callback) {
		var results = [];
		var source = {};

		async.eachLimit(helpers.regions.ec2, helpers.MAX_REGIONS_AT_A_TIME, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var ec2 = new AWS.EC2(LocalAWSConfig);

			// Now call APIs to determine actual usage
            helpers.cache(cache, ec2, 'describeInstances', function(err, data) {
                if (includeSource) source['describeInstances'][region] = {error: err, data: data};

                //console.log(data.Reservations.length)
                if (err || !data || !data.Reservations) {
                    results.push({
                        status: 3,
                        message: 'Unable to query for instances',
                        region: region
                    });

                    return rcb();
                }

                // loop through Instances for every reservation
                data.Reservations.forEach(function(Reservation){
                    Reservation.Instances.forEach(function(Instance){
                        //console.log(Instance)
                        if (!Instance.IamInstanceProfile){
                            results.push({
                                status: 2,
                                message:  + 'The instance is not using an IAM role attachment',
                                region: region,
                                resource: Instance.InstanceId
                            });
                        }else{
                            //
                            results.push({
                                status: 0,
                                message: 'The instance is using an IAM role attachment',
                                region: region,
                                resource: Instance.InstanceId
                            });
                        }
                    });
                });

                rcb();
            });


		}, function(){
			return callback(null, results, source);
		});
	}
};