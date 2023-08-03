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