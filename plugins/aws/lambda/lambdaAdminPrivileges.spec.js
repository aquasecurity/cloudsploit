const expect = require('chai').expect;
var lambdaAdminPrivileges = require('./lambdaAdminPrivileges');

const listFunctions = [
    {
        "FunctionName": "test-lambda",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::000011112222:role/lambda-role"
    },
    {
        "FunctionName": "testing-1",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:testing-1",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::000011112222:role/service-role/testing-123"
    }
];

const listRoles = [
    {
        "Path": "/",
        "RoleName": "lambda-role",
        "RoleId": "AROAYE32SRU55L7TD7HQ7",
        "Arn": "arn:aws:iam::000011112222:role/lambda-role",
        "CreateDate": "2020-12-22T08:47:57Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "Description": "Allows Lambda functions to call AWS services on your behalf.",
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "testing-123",
        "RoleId": "AROAYE32SRU5UELB2F76P",
        "Arn": "arn:aws:iam::000011112222:role/testing-123",
        "CreateDate": "2020-12-25T09:09:48Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "Description": "Allows Lambda functions to call AWS services on your behalf.",
        "MaxSessionDuration": 3600
    }
];

const listRolePolicies = [
    {
       "PolicyNames": [
           "EFS-Full"
       ]
    }
];

const listAttachedRolePolicies = [
    {
        "ResponseMetadata": {
            "RequestId": 'f7d427cc-970b-47af-9b7d-3e06121f83da'
        },
        "AttachedPolicies": [
            {
                "PolicyName": 'AdministratorAccess',
                "PolicyArn": 'arn:aws:iam::aws:policy/AdministratorAccess'
            }
        ],
        "IsTruncated": false
    },
    {
        "ResponseMetadata": {
            "RequestId": 'b06a66ed-53af-4737-b0d3-7ef9031d2c2e'
        },
        "AttachedPolicies": [
            {
                "PolicyName": 'Allow_Admin_Role_Policy',
                "PolicyArn": 'arn:aws:iam::000011112222:policy/Allow_Admin_Role_Policy'
            }
        ],
        "IsTruncated": false
    }
];

const getRolePolicy = [
    {
        "RoleName": 'lambda-role-2',
        "PolicyName": 'EFS-Full',
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22elasticfilesystem%3A%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
    }
];

const getPolicy = [
    {
        "Policy": {
            "PolicyName": 'Allow_Manager_Role_Policy',
            "PolicyId": 'ANPAYE32SRU57UHNCIGCT',
            "Arn": 'arn:aws:iam::000011112222:policy/Allow_Manager_Role_Policy',
            "Path": '/',
            "DefaultVersionId": 'v5',
            "AttachmentCount": 2,
            "PermissionsBoundaryUsageCount": 0,
            "IsAttachable": true
        }
    }
];

const getPolicyVersion = [
    {
        "PolicyVersion": {
            "Document": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListPoliciesGrantingServiceAccess%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListRoles%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AListGroups%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor2%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Deny%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22iam%3ACreateGroup%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3Aiam%3A%3A000011112222%3Agroup%2F%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D',
            "VersionId": 'v5',
        }
    }
];


const createCache = (listFunctions, listRoles, listAttachedRolePolicies, listRolePolicies, getRolePolicy, getPolicy, getPolicyVersion) => {
    var roleName = (listRoles && listRoles.length) ? listRoles[0].RoleName : null;
    var policyArn = (listAttachedRolePolicies && listAttachedRolePolicies.AttachedPolicies) ? listAttachedRolePolicies.AttachedPolicies.PolicyArn : null;
    var policyName = (listRolePolicies) ? listRolePolicies.PolicyNames[0] : null;
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    data: listFunctions
                }
            }
        },
        iam: {
            listRoles: {
                'us-east-1': {
                    data: listRoles
                }
            },
            listAttachedRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        data: listAttachedRolePolicies
                    }
                }
            },
            listRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        data: listRolePolicies
                    }
                }
            },
            getPolicy: {
                'us-east-1': {
                    [policyArn]: {
                        data: getPolicy
                    }
                }
            },
            getRolePolicy: {
                'us-east-1': {
                    [policyName]: {
                        data: getRolePolicy
                    }
                }
            },
            getPolicyVersion: {
                'us-east-1': {
                    [policyArn]: {
                        data: getPolicyVersion
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: {
                        message: 'error listing Lambda functions'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': null
            }
        }
    };
};

describe('lambdaAdminPrivileges', function () {
    describe('run', function () {

        it('should PASS if fcuntion does not have amdin priveleges', function (done) {
            const cache = createCache([listFunctions[0]], [listRoles[0]], listAttachedRolePolicies[1], listRolePolicies[0], getRolePolicy[0]);
            lambdaAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if function had admin priveleges', function (done) {
            const cache = createCache([listFunctions[1]], [listRoles[1]], listAttachedRolePolicies[0], listRolePolicies[0], {}, getPolicy[0], getPolicyVersion[0]);
            lambdaAdminPrivileges.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Lambda functons found', function (done) {
            const cache = createCache([]);
            lambdaAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list Lambda functions', function (done) {
            const cache = createErrorCache();
            lambdaAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list attached role policies', function (done) {
            const cache = createCache([listFunctions[1]], [listRoles[1]], null);
            lambdaAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list role policies', function (done) {
            const cache = createCache([listFunctions[1]], [listRoles[1]], listAttachedRolePolicies[0], null);
            lambdaAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list Lambda functions response not found', function (done) {
            const cache = createNullCache();
            lambdaAdminPrivileges.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});