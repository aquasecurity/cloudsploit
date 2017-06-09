var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Empty Groups',
	category: 'IAM',
	description: 'Ensures all groups have at least one member',
	more_info: 'While having empty groups does not present a direct security risk, it does broaden the management landscape which could potentially introduce risks in the future.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_WorkingWithGroupsAndUsers.html',
	recommended_action: 'Remove unused groups without users',
	apis: ['IAM:listGroups', 'IAM:getGroup'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		var region = 'us-east-1';

		var listGroups = helpers.addSource(cache, source,
				['iam', 'listGroups', region]);

		if (!listGroups) return callback(null, results, source);

		if (listGroups.err || !listGroups.data) {
			helpers.addResult(results, 3,
				'Unable to query for groups: ' + helpers.addError(listGroups));
			return callback(null, results, source);
		}

		if (!listGroups.data.length) {
			helpers.addResult(results, 0, 'No groups found');
			return callback(null, results, source);
		}
		
		async.each(listGroups.data, function(group, cb){
			if (!group.GroupName) return cb();

			var getGroup = helpers.addSource(cache, source,
				['iam', 'getGroup', region, group.GroupName]);

			if (!getGroup || getGroup.err || !getGroup.data || !getGroup.data.Users) {
				helpers.addResult(results, 3, 'Unable to query for group: ' + group.GroupName, 'global', group.Arn);
			} else if (!getGroup.data.Users.length) {
				helpers.addResult(results, 1, 'Group: ' + group.GroupName + ' does not contain any users', 'global', group.Arn);
				return cb();
			} else {
				helpers.addResult(results, 0, 'Group: ' + group.GroupName + ' contains ' + getGroup.data.Users.length + ' user(s)', 'global', group.Arn);
			}

			cb();
		}, function(){
			callback(null, results, source);
		});
	}
};