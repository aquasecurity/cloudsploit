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

const listAttachedRolePolicies = {
    'support-role': {
        AttachedPolicies: [
            {
                PolicyName: 'AWSSupportAccess',
                PolicyArn: supportPolicyArn
            }
        ]
    },
    'other-role': {
        AttachedPolicies: [
            {
                PolicyName: 'ReadOnlyAccess',
                PolicyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess'
            }
        ]
    }
};

const createCache = (roles, attachedPoliciesByRole) => {
    var cache = {
        iam: {
            listRoles: {
                'us-east-1': {
                    data: roles
                }
            },
            listAttachedRolePolicies: {
                'us-east-1': {}
            }
        }
    };

    if (roles && roles.length) {
        roles.forEach(function(role) {
            if (!role.RoleName) return;
            cache.iam.listAttachedRolePolicies['us-east-1'][role.RoleName] = {
                data: attachedPoliciesByRole && attachedPoliciesByRole[role.RoleName] ?
                    attachedPoliciesByRole[role.RoleName] : { AttachedPolicies: [] }
            };
        });
    }

    return cache;
};

const createErrorCache = () => {
    return {
        iam: {
            listRoles: {
                'us-east-1': {
                    err: {
                        message: 'error listing roles'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        iam: {
            listRoles: {
                'us-east-1': null
            }
        }
    };
};

describe('iamSupportPolicy', function () {
    describe('run', function () {
        it('should PASS if AWSSupportAccess is attached to a role', function (done) {
            const cache = createCache([listRoles[0]], listAttachedRolePolicies);
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no roles found', function (done) {
            const cache = createCache([]);
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if no role has AWSSupportAccess attached', function (done) {
            const cache = createCache([listRoles[1]], listAttachedRolePolicies);
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to query for IAM roles', function (done) {
            const cache = createErrorCache();
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list roles response not found', function (done) {
            const cache = createNullCache();
            iamSupportPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
