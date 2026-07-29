var expect = require('chai').expect;
const cloudShellFullAccess = require('./cloudShellFullAccess');

const cloudShellPolicyArn = 'arn:aws:iam::aws:policy/AWSCloudShellFullAccess';
const otherPolicyArn = 'arn:aws:iam::aws:policy/ReadOnlyAccess';

const listUsers = [
    {
        'Path': '/',
        'UserName': 'dev-user',
        'UserId': 'AIDAYE32SRU57PAYVNPEI',
        'Arn': 'arn:aws:iam::111111111111:user/dev-user',
        'CreateDate': '2020-09-12T16:58:32Z'
    }
];

const listGroups = [
    {
        'Path': '/',
        'GroupName': 'dev-group',
        'GroupId': 'AGPAYE32SRU5WTVWZJGNX',
        'Arn': 'arn:aws:iam::111111111111:group/dev-group',
        'CreateDate': '2020-08-30T14:24:48.000Z'
    }
];

const listRoles = [
    {
        'Path': '/',
        'RoleName': 'dev-role',
        'RoleId': 'AROAYE32SRU5VIMXXL3BH',
        'Arn': 'arn:aws:iam::111111111111:role/dev-role',
        'CreateDate': '2020-11-21T23:56:33Z'
    }
];

const listAttachedUserPolicies = [
    {
        'AttachedPolicies': [
            {
                'PolicyName': 'ReadOnlyAccess',
                'PolicyArn': otherPolicyArn
            }
        ]
    },
    {
        'AttachedPolicies': [
            {
                'PolicyName': 'AWSCloudShellFullAccess',
                'PolicyArn': cloudShellPolicyArn
            }
        ]
    },
    {
        'AttachedPolicies': []
    }
];

const listAttachedGroupPolicies = [
    {
        'AttachedPolicies': []
    },
    {
        'AttachedPolicies': [
            {
                'PolicyName': 'AWSCloudShellFullAccess',
                'PolicyArn': cloudShellPolicyArn
            }
        ]
    }
];

const listAttachedRolePolicies = [
    {
        'AttachedPolicies': []
    },
    {
        'AttachedPolicies': [
            {
                'PolicyName': 'AWSCloudShellFullAccess',
                'PolicyArn': cloudShellPolicyArn
            }
        ]
    }
];

const createCache = (users, attachedUserPolicies, groups, attachedGroupPolicies, roles, attachedRolePolicies) => {
    var username = (users && users.length) ? users[0].UserName : null;
    var groupName = (groups && groups.length) ? groups[0].GroupName : null;
    var roleName = (roles && roles.length) ? roles[0].RoleName : null;

    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    data: users
                },
            },
            listAttachedUserPolicies: {
                'us-east-1': {
                    [username]: {
                        data: attachedUserPolicies
                    },
                },
            },
            listGroups: {
                'us-east-1': {
                    data: groups,
                },
            },
            listAttachedGroupPolicies: {
                'us-east-1': {
                    [groupName]: {
                        data: attachedGroupPolicies
                    },
                },
            },
            listRoles: {
                'us-east-1': {
                    data: roles,
                },
            },
            listAttachedRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        data: attachedRolePolicies
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    err: {
                        message: 'error listing IAM users'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        iam: {
            listUsers: {
                'us-east-1': null
            }
        }
    };
};

describe('cloudShellFullAccess', function () {
    describe('run', function () {
        it('should PASS if AWSCloudShellFullAccess is not attached to any entity', function (done) {
            const cache = createCache(
                [listUsers[0]], listAttachedUserPolicies[0],
                [listGroups[0]], listAttachedGroupPolicies[0],
                [listRoles[0]], listAttachedRolePolicies[0]
            );
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no entities exist', function (done) {
            const cache = createCache([], null, [], null, [], null);
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if AWSCloudShellFullAccess is attached to a user', function (done) {
            const cache = createCache(
                [listUsers[0]], listAttachedUserPolicies[1],
                [], null, [], null
            );
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('user: dev-user');
                done();
            });
        });

        it('should FAIL if AWSCloudShellFullAccess is attached to a group', function (done) {
            const cache = createCache(
                [], null,
                [listGroups[0]], listAttachedGroupPolicies[1],
                [], null
            );
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('group: dev-group');
                done();
            });
        });

        it('should FAIL if AWSCloudShellFullAccess is attached to a role', function (done) {
            const cache = createCache(
                [], null, [], null,
                [listRoles[0]], listAttachedRolePolicies[1]
            );
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('role: dev-role');
                done();
            });
        });

        it('should FAIL if AWSCloudShellFullAccess is attached to multiple entities', function (done) {
            const cache = createCache(
                [listUsers[0]], listAttachedUserPolicies[1],
                [listGroups[0]], listAttachedGroupPolicies[1],
                [listRoles[0]], listAttachedRolePolicies[1]
            );
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(3);
                results.forEach(r => expect(r.status).to.equal(2));
                done();
            });
        });

        it('should UNKNOWN if unable to query for IAM users', function (done) {
            const cache = createErrorCache();
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for IAM users', function (done) {
            const cache = createNullCache();
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
