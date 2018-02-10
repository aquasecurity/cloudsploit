var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Cross VPC Public Private Communication',
	category: 'EC2',
	description: 'Ensures communication between public and private VPC tiers is not enabled.',
	more_info: 'Communication between the public tier of one VPC and the private tier of other \
				VPCs should never be allowed. Instead, VPC peerings with proper NACLs and gateways\
				 should be used.',
	link: 'https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html',
	recommended_action: 'Remove the NACL rules allowing communication between the public and \
						private tiers of different VPCs.',
	apis: ['EC2:describeVpcs', 'EC2:describeSubnets', 'EC2:describeRouteTables'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.ec2, function(region, rcb){

			// fetch all route tables
			var describeRouteTables = helpers.addSource(cache, source,
				['ec2', 'describeRouteTables', region]);

			if (!describeRouteTables) return rcb();

			if (describeRouteTables.err || !describeRouteTables.data) {
				helpers.addResult(results, 3,
					'Unable to query for RouteTables: ' + helpers.addError(describeRouteTables), region);
				return rcb();
			}

			if (!describeRouteTables.data.length) {
				helpers.addResult(results, 0, 'No RouteTables found', region);
				return rcb();
			}

			// now make array for for cross checking with vpc
			// {vpcid: routable data}
			//{public: {}}
			var VpcRouteTables = {
				'public': [],
				'private': [],
			};

			// fetch all public and private routetables and its corresponding subnets
			for (Rt of describeRouteTables.data){
				isPublic = false;
				for (route of Rt.Routes){
					if (route.DestinationCidrBlock === '0.0.0.0/0'){
						isPublic = true;
					}
				}
				if (isPublic){
					for (Association of Rt.Associations){
						VpcRouteTables.public.push(Association.SubnetId)
					}
				}
				else{
					for (Association of Rt.Associations){
						VpcRouteTables.private.push(Association.SubnetId)
					}
				}
			}


			// for (Rt of describeRouteTables.data){
			// 	VpcId = Rt.VpcId;
			// 	if (!(VpcId in VpcRouteTables)){
			// 		console.log('new ' + VpcId)
			// 		VpcRouteTables[VpcId] = [];
			// 	}
			// 	VpcRouteTables[VpcId].push(Rt);
			// }

			// fetch all VPcs
			var describeVpcs = helpers.addSource(cache, source,
				['ec2', 'describeVpcs', region]);

			if (!describeVpcs) return rcb();

			if (describeVpcs.err || !describeVpcs.data) {
				helpers.addResult(results, 3,
					'Unable to query for VPCs: ' + helpers.addError(describeVpcs), region);
				return rcb();
			}

			if (!describeVpcs.data.length) {
				helpers.addResult(results, 0, 'No VPCs found', region);
				return rcb();
			}

			// loop through all Vpcs
			for(Vpc of describeVpcs.data){

				// fetch all subnet for corresponding vpc
				var describeSubnets = helpers.addSource(cache, source,
					['ec2', 'describeSubnets', region, Vpc.VpcId]);

				// loop through each subnet and check if it is private or public


				debugger;


			}



			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
