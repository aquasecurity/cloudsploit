const expect = require('chai').expect;
var iamSupportPolicy = require('./iamSupportPolicy');

const supportPolicyArn = 'arn:aws:iam::aws:policy/AWSSupportAccess';

const listRoles = [
    {
        RoleName: 'support-role',
        Arn: 'arn:aws:iam::111111111111:role/support-role'
    },
    {
        RoleName: 'other-role',
        Arn: 'arn:aws:iam::111111111111:role/other-role'
    }
];

const createCache = (roles, attachedMap, listRolesErr) => {
    var attachedRolePolicies = { 'us-east-1': {} };

    if (roles && attachedMap) {
        for (var role of roles) {
            attachedRolePolicies['us-east-1'][role.RoleName] = {
                data: attachedMap[role.RoleName] || { AttachedPolicies: [] }
            };
        }
    }

    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    err: listRolesErr,
                    data: roles
                }
            },
            listAttachedRolePolicies: attachedRolePolicies
        }
    };
};

describe('iamSupportPolicy', function () {
    describe('run', function () {
        it('should PASS if AWSSupportAccess is attached to an IAM role', function (done) {
            const cache = createCache([listRoles[0]], {
                'support-role': {
                    AttachedPolicies: [{
                        PolicyName: 'AWSSupportAccess',
                        PolicyArn: supportPolicyArn
                    }]
                }
            });
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('attached to an IAM role');
                expect(results[0].resource).to.equal(listRoles[0].Arn);
                done();
            });
        });

        it('should FAIL if no IAM roles exist', function (done) {
            const cache = createCache([]);
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if no IAM role has AWSSupportAccess attached', function (done) {
            const cache = createCache(listRoles, {
                'support-role': { AttachedPolicies: [] },
                'other-role': { AttachedPolicies: [] }
            });
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to list IAM roles', function (done) {
            const cache = createCache(null, null, { message: 'Unable to list IAM roles' });
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list attached role policies', function (done) {
            const cache = {
                iam: {
                    listRoles: {
                        'us-east-1': {
                            data: [listRoles[0]]
                        }
                    },
                    listAttachedRolePolicies: {
                        'us-east-1': {
                            'support-role': {
                                err: { message: 'Unable to list attached role policies' }
                            }
                        }
                    }
                }
            };
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
