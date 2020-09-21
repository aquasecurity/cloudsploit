var expect = require('chai').expect;
var groupInlinePolicies = require('./groupInlinePolicies');

const groups = [
    {
        "Path": "/",
        "GroupName": "akhtar-gr-15",
        "GroupId": "AGPAYE32SRU5WTVWZJGNX",
        "Arn": "arn:aws:iam::123456654321:group/akhtar-gr-15",
        "CreateDate": "2020-08-30T14:24:48.000Z"
      },
      {
        "Path": "/",
        "GroupName": "akhtar-gr3-15",
        "GroupId": "AGPAYE32SRU56LRFN4U55",
        "Arn": "arn:aws:iam::123456654321:group/akhtar-gr3-15",
        "CreateDate": "2020-08-30T15:06:01.000Z"
      }
];

const groupPolicies = [
    {
        ResponseMetadata: { RequestId: 'ac47dbfc-6333-4840-8500-2ffb616f03d4' },
        PolicyNames: [],
        IsTruncated: false
    },
    {
        ResponseMetadata: { RequestId: '485a4202-06ef-4e8b-9661-ed4d1dd286d3' },
        PolicyNames: [
          'policygen-akhtar-gr-15-202008301932',
          'policygen-akhtar-gr-15-202008302019'
        ],
        IsTruncated: false
    }
];

const createCache = (groups, groupPolicies) => {
    if (groups && groups.length) var groupName = groups[0].GroupName;
    return {
        iam: {
            listGroups: {
                'us-east-1': {
                    data: groups,
                },
            },
            listGroupPolicies: {
                'us-east-1': {
                    [groupName]: {
                        data: groupPolicies
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listGroups: {
                'us-east-1': {
                    err: {
                        message: 'error listing IAM groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        iam: {
            listGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('groupInlinePolicies', function () {
    describe('run', function () {
        it('should FAIL if IAM group contains inline policies', function (done) {
            const cache = createCache([groups[0]], groupPolicies[1]);
            groupInlinePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if IAM group does not contain inline policies', function (done) {
            const cache = createCache([groups[1]], groupPolicies[0]);
            groupInlinePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no IAM groups found', function (done) {
            const cache = createCache([]);
            groupInlinePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for IAM groups', function (done) {
            const cache = createErrorCache();
            groupInlinePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for IAM groups', function (done) {
            const cache = createNullCache();
            groupInlinePolicies.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
