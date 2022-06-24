var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./emptyGroups');

const userGroups = [
    {
        "userId": 'ocid1.user.oc1..11111111111111222222222222222333333333333',
        "groupId": 'ocid1.group.oc1..aaaaaaaa5y47111111222222333333',
        "id": 'ocid1.groupmembership.oc1..111111111222222222223333333333333'
    },
    {
        "userId": 'ocid1.user.oc1..1111111111111111112222222222222222333333333333',
        "groupId": 'ocid1.group.oc1..aaaaaaaa5y47111111222222333333',
        "id": 'ocid1.groupmembership.oc1..1111111111111222222222222222233333333333333'
    },
    {
        "userId": 'ocid1.user.oc1..111111111111111122222222222222222333333333333333',
        "groupId": 'ocid1.group.oc1..aaaaaaaa5y47111111222222333333',
        "id": 'ocid1.groupmembership.oc1..1111111111111112222222222222222222333333333333'
    }
];

const groups = [
    {
        "id": 'ocid1.group.oc1..aaaaaaaa5y47111111222222333333',
        "name": 'Administrators'
    },
    {
        "id": 'ocid1.group.oc1..111111111111111222222222222223333333333333333',
        "name": 'securityAudit'
    }
]

const createCache = (groups, userGroups, groupsErr, userGroupsErr) => {
    return {
        group: {
            list: {
                'us-ashburn-1': {
                    data: groups,
                    err: groupsErr
                }
            }
        },
        userGroupMembership: {
            list: {
                'us-ashburn-1': {
                    data: userGroups,
                    err: userGroupsErr
                }
            }
        }
    }
};

describe('emptyGroups', function () {
    describe('run', function () {
        it('should give unknown result if unable to query user groups', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query user groups')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [{}],
                [{}],
                {err: 'error'}
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no groups found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No groups found')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [],
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give warn result if group does not contain any users', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(1)
                expect(results[0].message).to.include('does not contain any users')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [groups[1]],
                userGroups
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if group contains user(s)', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('contains 3 user(s)')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [groups[0]],
                userGroups
            );

            plugin.run(cache, {}, callback);
        });
    });
});