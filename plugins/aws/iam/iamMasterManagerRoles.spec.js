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
    },
    {
        "Path": "/",
        "RoleName": "aqua-cspm-security-remediator-rotator",
        "RoleId": "AROARPGOCGXSYQSXS37BT",
        "Arn": "arn:aws:iam::000000001111111:role/aqua-cspm-security-remediator-rotator",
        "CreateDate": "2022-09-21T09:56:11+00:00",
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
    },
    {
        "PolicyNames": [ "aqua-cspm-iam-remediator-access" ]
    }
];

const getRolePolicy = [
    {
        "manager-role-policy": {
            "data": {
                "ResponseMetadata": [{}],
                "RoleName": 'IAM-Manager-Role',
                "PolicyName": 'manager-role-policy',
                "PolicyDocument": [ { Sid: 'VisualEditor0',
                    Effect: 'Allow',
                    Action:
                        [   'iam:GetRole',
                            'iam:GetUser',
                            'iam:GetPolicy',
                            'iam:ListRoles',
                            'iam:ListUsers',
                            'iam:ListGroups',
                            'iam:UpdateUser',
                            'iam:UpdateGroup',
                            'iam:ListPolicies',
                            'iam:GetRolePolicy',
                            'iam:GetUserPolicy',
                            'iam:PutUserPolicy',
                            'iam:AddUserToGroup',
                            'iam:PutGroupPolicy',
                            'iam:DeleteUserPolicy',
                            'iam:DetachRolePolicy',
                            'iam:DetachUserPolicy',
                            'iam:GetPolicyVersion',
                            'iam:ListRolePolicies',
                            'iam:AttachGroupPolicy',
                            'iam:DeleteGroupPolicy',
                            'iam:DetachGroupPolicy',
                            'iam:ListGroupPolicies',
                            'iam:ListGroupsForUser',
                            'iam:ListPolicyVersions',
                            'iam:RemoveUserFromGroup',
                            'iam:ListEntitiesForPolicy',
                            'iam:UpdateAssumeRolePolicy',
                            'iam:ListAttachedRolePolicies',
                            'iam:ListAttachedUserPolicies',
                            'iam:ListAttachedGroupPolicies',
                            'iam:ListPoliciesGrantingServiceAccess' ],
                    Resource: [ '*' ] },
                    { Sid: 'VisualEditor1',
                        Effect: 'Deny',
                        Action:
                            [   'iam:CreateRole',
                                'iam:CreateUser',
                                'iam:DeleteRole',
                                'iam:DeleteUser',
                                'iam:CreateGroup',
                                'iam:DeleteGroup',
                                'iam:CreatePolicy',
                                'iam:DeletePolicy',
                                'iam:PutRolePolicy',
                                'iam:AddUserToGroup',
                                'iam:AttachRolePolicy',
                                'iam:DeleteRolePolicy',
                                'iam:CreatePolicyVersion',
                                'iam:DeletePolicyVersion' ],
                        Resource: [ '*' ] } ]
            }
        }
    },
    {
        "master-role-policy": {
            "data": {
                "ResponseMetadata": [{}],
                "RoleName": 'IAM-Master-Role',
                "PolicyName": 'master-role-policy',
                "PolicyDocument": [ { Sid: 'VisualEditor0',
                    Effect: 'Allow',
                    Action:
                        [   'iam:GetRole',
                            'iam:GetUser',
                            'iam:GetPolicy',
                            'iam:ListRoles',
                            'iam:ListUsers',
                            'iam:CreateRole',
                            'iam:CreateUser',
                            'iam:DeleteRole',
                            'iam:DeleteUser',
                            'iam:ListGroups',
                            'iam:CreateGroup',
                            'iam:DeleteGroup',
                            'iam:CreatePolicy',
                            'iam:DeletePolicy',
                            'iam:ListPolicies',
                            'iam:GetRolePolicy',
                            'iam:PutRolePolicy',
                            'iam:GetUserPolicy',
                            'iam:AttachRolePolicy',
                            'iam:DeleteRolePolicy',
                            'iam:GetPolicyVersion',
                            'iam:ListRolePolicies',
                            'iam:ListGroupsForUser',
                            'iam:ListGroupPolicies',
                            'iam:ListPolicyVersions',
                            'iam:CreatePolicyVersion',
                            'iam:DeletePolicyVersion',
                            'iam:ListEntitiesForPolicy',
                            'iam:ListAttachedRolePolicies',
                            'iam:ListAttachedUserPolicies',
                            'iam:ListAttachedGroupPolicies',
                            'iam:ListPoliciesGrantingServiceAccess' ],
                    Resource: [ '*' ] },
                    { Sid: 'VisualEditor1',
                        Effect: 'Deny',
                        Action:
                            [   'iam:UpdateUser',
                                'iam:UpdateGroup',
                                'iam:PutUserPolicy',
                                'iam:AddUserToGroup',
                                'iam:PutGroupPolicy',
                                'iam:DeleteUserPolicy',
                                'iam:DetachRolePolicy',
                                'iam:DetachUserPolicy',
                                'iam:AttachGroupPolicy',
                                'iam:DeleteGroupPolicy',
                                'iam:DetachGroupPolicy',
                                'iam:RemoveUserFromGroup',
                                'iam:UpdateAssumeRolePolicy' ],
                        Resource: [ '*' ] } ]
            }
        }
    },
    {
        "aqua-cspm-iam-remediator-access": {
            "data": {
                "ResponseMetadata": [{}],
                "RoleName": 'aqua-cspm-security-remediator',
                "PolicyName": 'aqua-cspm-iam-remediator-access',
            }
        }
    }
];

const getRole = [
    {
        'Role':{
            "Path": "/",
            "RoleName": "IAM-Manager-Role",
            "RoleId": "AROAYE32SRU5R232MB5LZ",
            "Arn": "arn:aws:iam::111122223333:role/IAM-Manager-Role",
            "Tags": [
                {
                    "Key": "app_name",
                    "Value": "Aqua CSPM"
                }
            ]
        }
    },
    {
        'Role':{
            "Path": "/",
            "RoleName": "IAM-Master-Role",
            "RoleId": "AROAYE32SRU5R232MB5LZ",
            "Arn": "arn:aws:iam::111122223333:role/IAM-Master-Role",
            "Tags": [
                {
                    "Key": "app_name",
                    "Value": "Aqua CSPM"
                }
            ]
        }  
    },
    {
        'Role':{
            "Path": "/",
            "RoleName": "aqua-cspm-security-remediator",
            "RoleId": "AROAYE32SRU5R232MB5LZ",
            "Arn": "arn:aws:iam::111122223333:role/aqua-cspm-security-remediator",
            "Tags": [
                {
                    "Key": "app_name",
                    "Value": "Aqua CSPM"
                }
            ]
        }  
    }
]

const createPassCache = (roles, listRolePolicies, getRolePolicy, getRole) => {
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
            },
            getRole: {
                'us-east-1': {
                    [roles[0].RoleName]: {
                        data: getRole[0]
                    },
                    [roles[1].RoleName]: {
                        data: getRole[1]
                    }
                }
            }
        }
    };
};

const createCache = (roles, listRolePolicies, getRolePolicy, getRole) => {
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
            },
            getRole: {
                'us-east-1': {
                    [roleName]:{   
                        data: getRole,
                        err: null    
                    }              
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
            const cache = createPassCache(roles, listRolePolicies, getRolePolicy, getRole);
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('IAM Master and Manager Roles found');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if IAM Master Role not found', function (done) {
            const cache = createCache([roles[0]], listRolePolicies[0], getRolePolicy[0], getRole[0]);
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('IAM Master Role not found');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if IAM Manager Role not found', function (done) {
            const cache = createCache([roles[1]], listRolePolicies[1], getRolePolicy[1], getRole[1]);
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('IAM Manager Role not found');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if IAM Master and Manager Roles not found', function (done) {
            const cache = createCache([roles[2]], listRolePolicies[2], getRolePolicy[2], getRole[2]);
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('IAM Master and Manager Roles not found');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no IAM roles found', function (done) {
            const cache = createCache([]);
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results[0].message).to.include('No IAM roles found');
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for IAM roles', function (done) {
            const cache = createErrorCache();
            iamMasterManagerRoles.run(cache, {}, (err, results) => {
                expect(results[0].message).to.include('Unable to query for IAM roles');
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

        it('should PASS if role with specific regex is ignored', function (done) {
            const cache =  createPassCache(roles, listRolePolicies, getRolePolicy, getRole)
            iamMasterManagerRoles.run(cache, {iam_role_policies_ignore_tag:'app_name:Aqua CSPM'}, (err, results) => {
                expect(results.length).to.equal(1);
                done();
            });
        })
    });
});