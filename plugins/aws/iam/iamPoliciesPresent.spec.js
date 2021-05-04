const expect = require('chai').expect;
var iamPoliciesPresent = require('./iamPoliciesPresent');


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
    }
];

const listRolePolicies = [
    {
       "PolicyNames": [
           "S3-Full"
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
    }
];

const createCache = (listRoles, listAttachedRolePolicies, listRolePolicies, listRolesErr, listAttachedRolePoliciesErr, listRolePoliciesErr) => {
    var roleName = (listRoles && listRoles.length) ? listRoles[0].RoleName : null;
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

describe('iamPoliciesPresent', function () {
    describe('run', function () {

        it('should PASS if IAM role has all required policies attached', function (done) {
            const cache = createCache([listRoles[0]], listAttachedRolePolicies[0], listRolePolicies[0]);
            iamPoliciesPresent.run(cache, { iam_required_policy_names: 'S3-Full,AdministratorAccess' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if IAM role does not have required policies attached', function (done) {
            const cache = createCache([listRoles[0]], {}, listRolePolicies[0]);
            iamPoliciesPresent.run(cache, { iam_required_policy_names: 'AdministratorAccess' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if on IAM roles found', function (done) {
            const cache = createCache([]);
            iamPoliciesPresent.run(cache, { iam_required_policy_names: 'S3-Full' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list IAM roles', function (done) {
            const cache = createCache(null, null, null, { message: 'Unable to list IAM roles'});
            iamPoliciesPresent.run(cache, { iam_required_policy_names: 'S3-Full' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list attached role policies', function (done) {
            const cache = createCache([listRoles[0]], {}, null, { message: 'Unable to list attached role policies'});
            iamPoliciesPresent.run(cache, { iam_required_policy_names: 'S3-Full' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list role policies', function (done) {
            const cache = createCache([listRoles[0]], listAttachedRolePolicies[0], {}, null, null, { message: 'Unable to query role policies'});
            iamPoliciesPresent.run(cache, { iam_required_policy_names: 'S3-Full' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list roles response not found', function (done) {
            const cache = createNullCache();
            iamPoliciesPresent.run(cache, { iam_required_policy_names: 'S3-Full' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});