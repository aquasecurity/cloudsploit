var expect = require('chai').expect;
const iamMasterManagerRoles = require('./iamMasterManagerRoles');

const roles = [
    {
        "Path": "/",
        "RoleName": "IAM-Manager-Role",
        "RoleId": "AROAYE32SRU5TQY4O5JBW",
        "Arn": "arn:aws:iam::111122223333:role/IAM-Manager-Role",
        "CreateDate": "2020-12-02T06:34:08.000Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22iam.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
        "Description": "Iam manager role.",
        "MaxSessionDuration": 3600,
        "Tags": []
    },
    {
        "Path": "/",
        "RoleName": "IAM-Master-Role",
        "RoleId": "AROAYE32SRU5R232MB5LZ",
        "Arn": "arn:aws:iam::111122223333:role/IAM-Master-Role",
        "CreateDate": "2020-11-30T07:58:42.000Z",
        "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Sid%22%3A%22%22%2C%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22iam.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
        "Description": "Iam Master role",
        "MaxSessionDuration": 3600,
        "Tags": []
    }
];

const listRolePolicies = [
    {
        "ResponseMetadata": { 
            "RequestId": '32c83dc4-bbdb-4b20-b9b7-b461a6942e04'
        },
        "PolicyNames": [ 'manager-role-policy' ],
        "IsTruncated": false
    },
    {
        "ResponseMetadata": {
            "RequestId": 'ecfb7061-b67c-47de-afe4-e5505bb17a97'
        },
        "PolicyNames": [ 'master-role-policy' ],
        "IsTruncated": false
    }
];

const getRolePolicy = [
    {
        "manager-role-policy": {
            "data": {
                "ResponseMetadata": [{}],
                "RoleName": 'IAM-Manager-Role',
                "PolicyName": 'manager-role-policy',
                "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetRole%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetUser%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListRoles%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListGroups%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AUpdateUser%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AUpdateGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetUserPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3APutUserPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAddUserToGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3APutGroupPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteUserPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADetachRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADetachUserPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetPolicyVersion%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListRolePolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAttachGroupPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteGroupPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADetachGroupPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListGroupPolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListGroupsForUser%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListPolicyVersions%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ARemoveUserFromGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListEntitiesForPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AUpdateAssumeRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListAttachedRolePolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListAttachedUserPolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListAttachedGroupPolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListPoliciesGrantingServiceAccess%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Deny%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ACreateRole%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ACreateUser%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteRole%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteUser%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ACreateGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ACreatePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeletePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3APutRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAddUserToGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAttachRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ACreatePolicyVersion%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeletePolicyVersion%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
            }
        }
    },
    {
        "master-role-policy": {
            "data": {
                "ResponseMetadata": [{}],
                "RoleName": 'IAM-Master-Role',
                "PolicyName": 'master-role-policy',
                "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetRole%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetUser%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListRoles%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ACreateRole%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ACreateUser%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteRole%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteUser%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListGroups%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ACreateGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ACreatePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeletePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3APutRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetUserPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAttachRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AGetPolicyVersion%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListRolePolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListGroupsForUser%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListGroupPolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListPolicyVersions%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ACreatePolicyVersion%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeletePolicyVersion%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListEntitiesForPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListAttachedRolePolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListAttachedUserPolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListAttachedGroupPolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListPoliciesGrantingServiceAccess%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Deny%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AUpdateUser%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AUpdateGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3APutUserPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAddUserToGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3APutGroupPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteUserPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADetachRolePolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADetachUserPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAttachGroupPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADeleteGroupPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ADetachGroupPolicy%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3ARemoveUserFromGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AUpdateAssumeRolePolicy%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
            }
        }
    }
];

const createPassCache = (roles, listRolePolicies, getRolePolicy) => {
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    data: roles,
                },
            },
            listRolePolicies: {
                'us-east-1': {
                    [roles[0].RoleName]: {
                        data: listRolePolicies[0]
                    },
                    [roles[1].RoleName]: {
                        data: listRolePolicies[1]
                    }
                }
            },
            getRolePolicy: {
                'us-east-1': {
                    [roles[0].RoleName]: getRolePolicy[0],
                    [roles[1].RoleName]: getRolePolicy[1]
                }
            }
        }
    };
};

const createCache = (roles, listRolePolicies, getRolePolicy) => {
    var roleName = (roles && roles.length) ? roles[0].RoleName : null;
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    data: roles,
                },
            },
            listRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        data: listRolePolicies
                    }
                }
            },
            getRolePolicy: {
                'us-east-1': {
                    [roleName]: getRolePolicy
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    err: {
                        message: 'error listing IAM roles'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        iam: {
            listRoles: {
                'us-east-1': null,
            },
        },
    };
};

describe('iamMasterManagerRoles', function () {
    describe('run', function () {
        it('should PASS if IAM Master and Manager Roles found', function (done) {
            const cache = createPassCache(roles, listRolePolicies, getRolePolicy);
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if IAM Master Role not found', function (done) {
            const cache = createCache([roles[0]], listRolePolicies[0], getRolePolicy[0]);
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if IAM Manager Role not found', function (done) {
            const cache = createCache([roles[1]], listRolePolicies[1], getRolePolicy[1]);
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if IAM Master and Manager Roles not found', function (done) {
            const cache = createCache([roles[1]], listRolePolicies[0], getRolePolicy[0]);
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no IAM roles found', function (done) {
            const cache = createCache([]);
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for IAM roles', function (done) {
            const cache = createErrorCache();
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list IAM roles response not found', function (done) {
            const cache = createNullCache();
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});