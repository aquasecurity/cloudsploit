// TODO: MOVE TO EC2
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'VPC Flow Logs Enabled',
	category: 'EC2',
	description: 'Ensures VPC flow logs are enabled for traffic logging',
	more_info: 'VPC flow logs record all traffic flowing in to and out of a VPC. These logs are critical for auditing and review after security incidents.',
	link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html',
	recommended_action: 'Enable VPC flow logs for each VPC',
	apis: ['EC2:describeVpcs', 'EC2:describeFlowLogs'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.flowlogs, function(region, rcb){
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

			var vpcMap = {};

			for (i in describeVpcs.data) {
				if (!describeVpcs.data[i].VpcId) continue;
				vpcMap[describeVpcs.data[i].VpcId] = [];
			}

			var describeFlowLogs = helpers.addSource(cache, source,
				['ec2', 'describeFlowLogs', region]);

			if (! describeFlowLogs || describeFlowLogs.err || !describeFlowLogs.data) {
				helpers.addResult(results, 3,
					'Unable to query for flow logs: ' + helpers.addError(describeFlowLogs), region);
				return rcb();
			}

			// Now lookup flow logs and map to VPCs
			for (f in describeFlowLogs.data) {
				if (describeFlowLogs.data[f].ResourceId &&
					vpcMap[describeFlowLogs.data[f].ResourceId]) {
					vpcMap[describeFlowLogs.data[f].ResourceId].push(describeFlowLogs.data[f]);
				}
			}

			// Loop through VPCs and add results
			for (v in vpcMap) {
				if (!vpcMap[v].length) {
					helpers.addResult(results, 1, 'VPC flow logs are not enabled', region, v);
				} else {
					var activeLogs = false;

					for (f in vpcMap[v]) {
						if (vpcMap[v][f].FlowLogStatus == 'ACTIVE') {
							activeLogs = true;
							break;
						}
					}

					if (activeLogs) {
						helpers.addResult(results, 0, 'VPC flow logs are enabled', region, v);
					} else {
						helpers.addResult(results, 1, 'VPC flow logs are enabled, but not active', region, v);
					}
				}
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
