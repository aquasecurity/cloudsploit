var async = require('async');
var helpers = require('../../helpers');

var filterPatterns = [
	{
		name: 'Unauthorized API Calls',
		pattern: '{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }'
	},
	{
		name: 'Sign In Without MFA',
		pattern: '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'
	},
	{
		name: 'Root Account Usage',
		pattern: '{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }'
	},
	{
		name: 'IAM Policy Changes',
		pattern: '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}'
	},
	{
		name: 'CloudTrail Configuration Changes',
		pattern: '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'
	},
	{
		name: 'Sign In Failures',
		pattern: '{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }'
	},
	{
		name: 'Disabled CMKs',
		pattern: '{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))} }'
	},
	{
		name: 'S3 Policy Changes',
		pattern: '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'
	},
	{
		name: 'ConfigService Changes',
		pattern: '{($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder))}'
	},
	{
		name: 'Security Group Changes',
		pattern: '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}'
	},
	{
		name: 'Network ACL Changes',
		pattern: '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
	},
	{
		name: 'Network Gateway Changes',
		pattern: '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
	},
	{
		name: 'Route Table Changes',
		pattern: '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'
	},
	{
		name: 'VPC Changes',
		pattern: '"{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'
	}
];

module.exports = {
	title: 'CloudWatch Monitoring Metrics',
	category: 'CloudWatchLogs',
	description: 'Ensures metric filters are setup for CloudWatch logs to detect security risks from CloudTrail.',
	more_info: 'Sending CloudTrail logs to CloudWatch is only useful if metrics are setup to detect risky activity from those logs. There are numerous metrics that should be used. For the exact filter patterns, please see this plugin on GitHub: https://github.com/cloudsploit/scans/blob/master/plugins/cloudwatchlogs/monitoringMetrics.js',
	recommended_action: 'Enable metric filters to detect malicious activity in CloudTrail logs sent to CloudWatch.',
	link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html',
	apis: ['CloudTrail:describeTrails', 'CloudWatchLogs:describeMetricFilters'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.cloudtrail, function(region, rcb){
			var describeTrails = helpers.addSource(cache, source,
				['cloudtrail', 'describeTrails', region]);

			if (!describeTrails || describeTrails.err ||
				!describeTrails.data || !describeTrails.data.length) {
				return rcb();
			}

			var trailsInRegion = [];

			for (t in describeTrails.data) {
				if (describeTrails.data[t].HomeRegion &&
					describeTrails.data[t].HomeRegion === region) {
					trailsInRegion.push(describeTrails.data[t]);
				}
			}

			if (!trailsInRegion.length) return rcb();

			var describeMetricFilters = helpers.addSource(cache, source,
				['cloudwatchlogs', 'describeMetricFilters', region]);

			if (!describeMetricFilters ||
				describeMetricFilters.err || !describeMetricFilters.data) {
				helpers.addResult(results, 3,
					'Unable to query for CloudWatchLogs metric filters: ' + helpers.addError(describeMetricFilters), region);

				return rcb();
			}

			if (!describeMetricFilters.data.length) {
				helpers.addResult(results, 2,
					'There are no CloudWatch metric filters in this region', region);

				return rcb();
			}

			// Organize filters by log group name
			var filters = {};

			for (f in describeMetricFilters.data) {
				var filter = describeMetricFilters.data[f];

				if (filter.logGroupName && filter.filterPattern) {
					if (!filters[filter.logGroupName]) filters[filter.logGroupName] = [];
					filters[filter.logGroupName].push(filter.filterPattern.replace(/\s+/g, '').toLowerCase());
				}
			}

			async.each(trailsInRegion, function(trail, tcb){
				if (!trail.CloudWatchLogsLogGroupArn) return tcb();

				// CloudTrail stores the CloudWatch Log Group as a full ARN
				// while CloudWatch Logs just stores the group name.
				// Need to filter the name out for comparison.
				var startPos = trail.CloudWatchLogsLogGroupArn.indexOf('log-group:') + 10;
				var endPos = trail.CloudWatchLogsLogGroupArn.lastIndexOf(':');
				var logGroupName = trail.CloudWatchLogsLogGroupArn.substring(startPos, endPos);

				if (!filters[logGroupName]) {
					helpers.addResult(results, 2,
						'There are no CloudWatch metric filters for this trail', region,
						trail.TrailARN);

					return tcb();
				}

				var missing = [];

				// If there is a filter setup, check for all strings.
				for (p in filterPatterns) {
					var pattern = filterPatterns[p];

					for (f in filters) {
						var filter = filters[f];

						if (filter.indexOf(pattern.pattern.replace(/\s+/g, '').toLowerCase()) > - 1) {
							pattern.found = true;
							break;
						}
					}

					if (!pattern.found) {
						missing.push(pattern.name);
					}
				}

				if (missing.length) {
					helpers.addResult(results, 2,
						'Trail logs are missing filters for: ' + missing.join(', '), region,
						trail.TrailARN);
				} else {
					helpers.addResult(results, 0,
						'Trail logs have filter patterns for all required metrics', region,
						trail.TrailARN);
				}

				tcb();
			}, function(){
				rcb();
			});
		}, function(){
			callback(null, results, source);
		});
	}
};
