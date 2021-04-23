const expect = require('chai').expect;
var iamRolePolicies = require('./iamRolePolicies');


const listRoles = [
    {
        "Path": "/",
        "RoleName": "test-role-1",
        "RoleId": "AROAYE32SRU5VIMXXL3BH",
        "Arn": "arn:aws:iam::000011112222:role/test-role-1",
        "CreateDate": "2020-11-21T23:56:33Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::000011112222:root"
                    },
                    "Action": "sts:AssumeRoleWithSAML",
                    "Condition": {}
                }
            ]
        },
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "test-role-2",
        "RoleId": "AROAYE32SRU5VIMXXL3BH",
        "Arn": "arn:aws:iam::000011112222:role/test-role-2",
        "CreateDate": "2020-11-21T23:56:33Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::000011112222:root"
                    },
                    "Action": "sts:AssumeRoleWithSAML",
                    "Condition": {}
                }
            ]
        },
        "MaxSessionDuration": 3600
    }
];

const listRolePolicies = [
    {
       "PolicyNames": [
           "S3-Full"
       ]
    },
    {
        "PolicyNames": [
            "All-Action-Resources"
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
                "PolicyName": 'EC2-Full',
                "PolicyArn": 'arn:aws:iam::000011112222:policy/EC2-Full'
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
                "PolicyName": 'EC2-Wildcard',
                "PolicyArn": 'arn:aws:iam::000011112222:policy/EC2-Wildcard'
            }
        ],
        "IsTruncated": false
    }
];

const getRolePolicy = [
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'S3-Full',
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22s3%3A%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'S3-WildCard',
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22s3%3Ag%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'S3-Limited',
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22s3%3AGetObject%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D' 
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'All-Action-Resources',
        "PolicyDocument":'%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
    },
    {
        "RoleName": 'test-role-2',
        "PolicyName": 'All-Actions',
        "PolicyDocument": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3As3%3A%3A%3A%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D'
    }
];

const getPolicy = [
    {
        "Policy": {
            "PolicyName": 'EC2-Wildcard',
            "PolicyId": 'ANPAYE32SRU57UHNCIGCT',
            "Arn": 'arn:aws:iam::000011112222:policy/EC2-Wildcard',
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
            "Document": '%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor1%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22s3%3Ag%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D',
            "VersionId": 'v5',
        }
    }
];


const createCache = (listRoles, listAttachedRolePolicies, listRolePolicies, getRolePolicy, getPolicy, getPolicyVersion, listRolesErr, listRolePoliciesErr, listAttachedRolePoliciesErr) => {
    var roleName = (listRoles && listRoles.length) ? listRoles[0].RoleName : null;
    var policyArn = (listAttachedRolePolicies && listAttachedRolePolicies.AttachedPolicies) ? listAttachedRolePolicies.AttachedPolicies[0].PolicyArn : null;
    var policyName = (listRolePolicies && listRolePolicies.PolicyNames) ? listRolePolicies.PolicyNames[0] : null;
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    err: listRolesErr,
                    data: listRoles
                }
            },
            listAttachedRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        err: listAttachedRolePoliciesErr,
                        data: listAttachedRolePolicies
                    }
                }
            },
            listRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        err: listRolePoliciesErr,
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
                    [roleName]: {
                        [policyName]: {
                            data: getRolePolicy
                        }
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

const createNullCache = () => {
    return {
        lambda: {
            listRoles: {
                'us-east-1': null
            }
        }
    };
};

describe('iamRolePolicies', function () {
    describe('run', function () {

        it('should PASS if role does not have overly-permissive policy', function (done) {
            const cache = createCache([listRoles[0]], listAttachedRolePolicies[2], listRolePolicies[0], getRolePolicy[2]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if role policy allows wildcard actions', function (done) {
            const cache = createCache([listRoles[0]], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role policy allows wildcard actions but ignore managed iam policies is set to true', function (done) {
            const cache = createCache([listRoles[0]], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            iamRolePolicies.run(cache, { ignore_customer_managed_iam_policies : 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if role policy allows all actions on selected resources', function (done) {
            const cache = createCache([listRoles[0]], {}, listRolePolicies[1], getRolePolicy[4]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if role policy allows all actions on all resources', function (done) {
            const cache = createCache([listRoles[1]], {}, listRolePolicies[1], getRolePolicy[3]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if role policy allows wildcard actions but ignore service specific roles setting is enabled', function (done) {
            const cache = createCache([listRoles[0]], listAttachedRolePolicies[2], null, null, getPolicy[0], getPolicyVersion[0]);
            iamRolePolicies.run(cache, { ignore_service_specific_wildcards: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if on IAM roles found', function (done) {
            const cache = createCache([]);
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list', function (done) {
            const cache = createCache(null, null, null, null, null, null, { message: 'Unable to list IAM roles'});
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list attached role policies', function (done) {
            const cache = createCache([listRoles[1]], {}, null, null, null, null, null, null, { message: 'Unable to list attached role policies'});
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list role policies', function (done) {
            const cache = createCache([listRoles[1]], listAttachedRolePolicies[0], {}, null, null, null, null, { message: 'Unable to query role policies'});
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list roles response not found', function (done) {
            const cache = createNullCache();
            iamRolePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});