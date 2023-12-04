var async     = require('async');
var helpers  = require('../../../helpers/google');



module.exports = function(GoogleConfig, collection, settings, regions, call, service, dummy, callback) {
    let project;
    if (settings && settings.identifier && settings.identifier.cloud_account) {
        project = settings.identifier.cloud_account;
    } else {
        return callback();
    }

    async.eachOfLimit(call, 1, function(callObj, callKey, callCb) {
        if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
        if (!collection[service]) collection[service] = {};
        if (!collection[service][callKey]) collection[service][callKey] = {};
        if (!collection[service][callKey]['global']) collection[service][callKey]['global'] = {};
        if (!collection[service][callKey]['global']['data']) collection[service][callKey]['global']['data'] = [];

        let memberObj = {};

        let groups = {};

        if (collection['memberships'] &&
            collection['memberships']['list'] &&
            collection['memberships']['list']['global'] &&
            collection['memberships']['list']['global']['data'] &&
            collection['memberships']['list']['global']['data'].length) {
            collection['memberships']['list']['global']['data'].forEach(membership => {
                let user_email = membership.preferredMemberKey ? membership.preferredMemberKey.id: '';
                let group_name = membership.parent ? membership.parent.displayName : '';
                if (!groups[group_name]) groups[group_name] = [];

                groups[group_name].push({
                    email: user_email,
                    roles: membership.roles
                });
            });
        }
        if (collection['projects'] &&
            collection['projects']['getIamPolicy'] &&
            collection['projects']['getIamPolicy']['global'] &&
            collection['projects']['getIamPolicy']['global']['data'] &&
            collection['projects']['getIamPolicy']['global']['data'].length) {

            collection['projects']['getIamPolicy']['global']['data'].forEach(data => {
                if (data.bindings && data.bindings.length) {
                    data.bindings.forEach(binding => {
                        let role = binding.role;
                        let condition = binding.condition;
                        binding.members.forEach(member => {
                            let accountName = (member.includes(':')) ? member.split(':')[1] : member;
                            let memberType = member.startsWith('serviceAccount') ? 'serviceAccounts' : (member.startsWith('user') ? 'users' : (member.startsWith('group') ? 'groups' : 'domains'));
                            let resource = helpers.createResourceName(memberType, accountName, project);
                            if (!memberObj[resource]) memberObj[resource] = {
                                roles: [],
                                Id: resource,
                                email: accountName,
                                type: memberType
                            };

                            if (memberType === 'groups') {
                                let groupName = accountName.split('@')[0];
                                if (groups[groupName]) {
                                    memberObj[resource].users = groups[groupName];
                                } else {
                                    memberObj[resource].users = [];
                                }
                            }

                            let roleObj = {role: role};
                            if (condition) roleObj.condition = condition;
                            memberObj[resource].roles.push(roleObj);
                        });
                    });
                }
            });

            if (memberObj && Object.values(memberObj).length) collection[service][callKey]['global']['data'] = Object.values(memberObj);
            callCb();
        } else {
            collection[service][callKey]['global']['data'] = [];
            callCb();
        }

    }, function() {
        callback();
    });
};