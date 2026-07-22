const expect = require('chai').expect;
var cloudShellFullAccess = require('./cloudShellFullAccess');

const cloudShellPolicyArn = 'arn:aws:iam::aws:policy/AWSCloudShellFullAccess';
const otherPolicyArn = 'arn:aws:iam::aws:policy/ReadOnlyAccess';

const createCache = (users, userPoliciesMap, groups, groupPoliciesMap, roles, rolePoliciesMap) => {
    var cache = {
        iam: {
            listUsers: { 'us-east-1': { data: users || [] } },
            listAttachedUserPolicies: { 'us-east-1': {} },
            listGroups: { 'us-east-1': { data: groups || [] } },
            listAttachedGroupPolicies: { 'us-east-1': {} },
            listRoles: { 'us-east-1': { data: roles || [] } },
            listAttachedRolePolicies: { 'us-east-1': {} }
        }
    };

    (users || []).forEach(u => {
        cache.iam.listAttachedUserPolicies['us-east-1'][u.UserName] = {
            data: { AttachedPolicies: (userPoliciesMap && userPoliciesMap[u.UserName]) || [] }
        };
    });
    (groups || []).forEach(g => {
        cache.iam.listAttachedGroupPolicies['us-east-1'][g.GroupName] = {
            data: { AttachedPolicies: (groupPoliciesMap && groupPoliciesMap[g.GroupName]) || [] }
        };
    });
    (roles || []).forEach(r => {
        cache.iam.listAttachedRolePolicies['us-east-1'][r.RoleName] = {
            data: { AttachedPolicies: (rolePoliciesMap && rolePoliciesMap[r.RoleName]) || [] }
        };
    });

    return cache;
};

const user1 = { UserName: 'dev-user', Arn: 'arn:aws:iam::111111111111:user/dev-user' };
const group1 = { GroupName: 'dev-group', Arn: 'arn:aws:iam::111111111111:group/dev-group' };
const role1 = { RoleName: 'dev-role', Arn: 'arn:aws:iam::111111111111:role/dev-role' };

describe('cloudShellFullAccess', function () {
    describe('run', function () {
        it('should PASS if AWSCloudShellFullAccess is not attached to any entity', function (done) {
            const cache = createCache(
                [user1], { 'dev-user': [{ PolicyArn: otherPolicyArn }] },
                [group1], { 'dev-group': [] },
                [role1], { 'dev-role': [] }
            );
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no entities exist', function (done) {
            const cache = createCache([], {}, [], {}, [], {});
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if AWSCloudShellFullAccess is attached to a user', function (done) {
            const cache = createCache(
                [user1], { 'dev-user': [{ PolicyArn: cloudShellPolicyArn }] },
                [], {}, [], {}
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
                [], {},
                [group1], { 'dev-group': [{ PolicyArn: cloudShellPolicyArn }] },
                [], {}
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
                [], {}, [], {},
                [role1], { 'dev-role': [{ PolicyArn: cloudShellPolicyArn }] }
            );
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('role: dev-role');
                done();
            });
        });

        it('should return multiple FAILs if attached to multiple entities', function (done) {
            const cache = createCache(
                [user1], { 'dev-user': [{ PolicyArn: cloudShellPolicyArn }] },
                [group1], { 'dev-group': [{ PolicyArn: cloudShellPolicyArn }] },
                [role1], { 'dev-role': [{ PolicyArn: cloudShellPolicyArn }] }
            );
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(3);
                results.forEach(r => expect(r.status).to.equal(2));
                done();
            });
        });

        it('should UNKNOWN if unable to list IAM users', function (done) {
            const cache = {
                iam: {
                    listUsers: { 'us-east-1': { err: { message: 'error' } } }
                }
            };
            cloudShellFullAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
